package com.salyvn.serverdoctor

import com.github.ajalt.clikt.core.parse
import com.github.ajalt.clikt.core.subcommands
import com.salyvn.serverdoctor.cli.DiagnoseIncidentCommand
import com.salyvn.serverdoctor.core.Severity
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.IncidentTimelineCorrelator
import com.salyvn.serverdoctor.log.LogTriage
import com.salyvn.serverdoctor.mcp.ToolCatalog
import com.salyvn.serverdoctor.plugins.PluginIndex
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class ServerDoctorV100Test {

    @Test
    fun `detects Project Loom virtual thread carrier pinning from tracePinnedThreads and JFR events`() {
        val traceText = """
            [15:12:01.420] [VirtualThread-42/WARN]: Thread[#94,ForkJoinPool-1-worker-2,5,CarrierThreads]
                java.base/java.lang.VirtualThread${'$'}VThreadContinuation.onPinned(VirtualThread.java:185)
                com.mysql.cj.jdbc.ConnectionImpl.execSQL(ConnectionImpl.java:2024) <== monitors:1
                com.example.vaultsync.SqlPlayerDao.loadProfile(SqlPlayerDao.java:91)
            jdk.VirtualThreadPinned {
              startTime = 15:12:02.100
              duration = 84.5 ms
              carrierThread = "ForkJoinPool-1-worker-5"
              pinnedReason = "Native frame on stack"
              stackTrace = [
                org.sqlite.core.NativeDB._exec_utf8(Native Method)
                com.example.crates.SqliteCrateStore.openCrate(SqliteCrateStore.java:64)
              ]
            }
        """.trimIndent()

        val report = IncidentTimelineCorrelator.analyzeLoomPinning(traceText)
        assertEquals(2, report.totalPinnedEvents)
        assertEquals(2, report.distinctCarriersPinned)
        assertEquals(84.5, report.maxDurationMs, 0.01)
        assertEquals(2, report.incidents.size)

        val syncPin = report.incidents.first {
            it.mechanism == IncidentTimelineCorrelator.PinningMechanism.SYNCHRONIZED_MONITOR
        }
        assertEquals("com.mysql.cj.jdbc.ConnectionImpl.execSQL", syncPin.monitorFrame)
        assertEquals("JDBC query / socket I/O", syncPin.blockingOperation)
        assertEquals("com.example.vaultsync.SqlPlayerDao", syncPin.blamedPlugin)

        val nativePin = report.incidents.first {
            it.mechanism == IncidentTimelineCorrelator.PinningMechanism.NATIVE_OR_FOREIGN_UPCALL
        }
        assertEquals("com.example.crates.SqliteCrateStore", nativePin.blamedPlugin)
    }

    @Test
    fun `detects HikariCP pool exhaustion and SQLite WAL lock starvation with tick-thread escalation`() {
        val dbLog = """
            [15:12:02.050] [Region Scheduler Thread #1/ERROR]: SQLTransientConnectionException: VaultSync-Pool - Connection is not available, request timed out after 3000ms.
            	at com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)
            	at com.example.vaultsync.SqlPlayerDao.saveSync(SqlPlayerDao.java:118)
            [15:12:02.060] [VaultSync-Pool housekeeper/WARN]: VaultSync-Pool - PoolStats (total=10, active=10, idle=0, waiting=7)
            [15:14:10.000] [Folia Async Scheduler Thread #2/WARN]: [SQLITE_BUSY] The database file is locked (wal_checkpoint stalled at 14200 frames)
            	at com.example.quests.SqliteQuestRepo.flush(SqliteQuestRepo.java:77)
        """.trimIndent()

        val report = IncidentTimelineCorrelator.analyzeDbStarvation(dbLog)
        assertEquals(2, report.incidents.size)
        assertEquals(1, report.tickThreadStalls)

        val hikari = report.incidents.first {
            it.kind == IncidentTimelineCorrelator.DbStarvationKind.HIKARICP_POOL_EXHAUSTION
        }
        assertTrue(hikari.onTickThread)
        assertEquals(10, hikari.activeConnections)
        assertEquals(10, hikari.totalConnections)
        assertEquals(7, hikari.waitingThreads)
        assertEquals(3000.0, hikari.timeoutMs!!, 0.1)
        assertEquals("com.example.vaultsync.SqlPlayerDao", hikari.blamedPlugin)

        val sqlite = report.incidents.first {
            it.kind == IncidentTimelineCorrelator.DbStarvationKind.SQLITE_WAL_OR_BUSY_LOCK
        }
        assertFalse(sqlite.onTickThread)
        assertEquals(14200, sqlite.walFrames)
        assertEquals("com.example.quests.SqliteQuestRepo", sqlite.blamedPlugin)
    }

    @Test
    fun `analyzes Linux cgroup CPU CFS throttling, PSI stalls, THP compaction, and swap pressure`() {
        val hostCapture = """
            nr_periods 2000
            nr_throttled 540
            throttled_usec 28400000
            cpu pressure: some avg10=28.40 avg60=19.10 avg300=8.00 total=91200400
            /sys/kernel/mm/transparent_hugepage/enabled: [always] madvise never
            VmSwap: 1572864 kB
        """.trimIndent()

        val incidents = IncidentTimelineCorrelator.analyzeHostPressure(hostCapture)
        assertEquals(4, incidents.size)
        val cgroup = incidents.first { it.kind == IncidentTimelineCorrelator.HostPressureKind.CGROUP_CPU_THROTTLING }
        assertTrue(cgroup.critical)
        assertEquals(0.27, cgroup.throttleRatio!!, 0.001)
        val swap = incidents.first { it.kind == IncidentTimelineCorrelator.HostPressureKind.SWAP_OR_CGROUP_OOM }
        assertEquals(1536L, swap.swapMegabytes)
        assertTrue(swap.critical)
    }

    @Test
    fun `correlates multi-stage causal cascade across log, CLI diagnose-incident, and MCP tool`(@TempDir tempDir: Path) {
        val serverLog = tempDir.resolve("outage-v100.log")
        val hostCapture = tempDir.resolve("host-cgroup.txt")

        Files.writeString(
            hostCapture,
            """
            [15:12:01.100] cgroup cpu.stat nr_periods 2000 nr_throttled 500 throttled_usec 19500000
            """.trimIndent(),
        )
        Files.writeString(
            serverLog,
            """
            [15:10:00.000] [ServerMain/INFO]: Starting minecraft server version 26.3
            [15:12:01.420] [VirtualThread-42/WARN]: Thread[#94,ForkJoinPool-1-worker-2,5,CarrierThreads]
                com.mysql.cj.jdbc.ConnectionImpl.execSQL(ConnectionImpl.java:2024) <== monitors:1
                com.example.vaultsync.SqlPlayerDao.loadProfile(SqlPlayerDao.java:91)
            [15:12:02.050] [Region Scheduler Thread #1/ERROR]: SQLTransientConnectionException: VaultSync-Pool - Connection is not available, request timed out after 3000ms.
            	at com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)
            	at com.example.vaultsync.SqlPlayerDao.saveSync(SqlPlayerDao.java:118)
            [15:12:03.200] [Folia Region Watchdog/ERROR]: --- DO NOT REPORT THIS TO FOLIA - THIS IS NOT A BUG OR A CRASH ---
            [15:12:03.200] [Folia Region Watchdog/ERROR]: Tick region (8, -4) has not responded for 15.1 seconds!
            """.trimIndent(),
        )

        val diag = IncidentTimelineCorrelator.diagnose(
            primarySource = LogSource.of(serverLog),
            jfrSource = LogSource.of(hostCapture),
        )
        val diagIds = diag.findings.map { it.ruleId }.toSet()
        assertEquals(setOf("L042", "L043", "L044", "L045"), diagIds)
        val cascadeFinding = diag.findings.single { it.ruleId == "L045" }
        assertEquals(Severity.CRITICAL, cascadeFinding.severity)
        assertTrue(cascadeFinding.detail.contains("delta-t=2100 ms"), cascadeFinding.detail)
        assertTrue(cascadeFinding.detail.contains("[L044]") && cascadeFinding.detail.contains("[L001]"), cascadeFinding.detail)

        // LogTriage over the single server log should also surface L042, L043, and L045
        val triaged = LogTriage(PluginIndex.EMPTY).analyse(LogSource.of(serverLog))
        val triageIds = triaged.findings.map { it.ruleId }.toSet()
        assertTrue(triageIds.containsAll(setOf("L042", "L043", "L045")), "Expected L042, L043, L045 in $triageIds")

        // CLI diagnose-incident SARIF output
        val sarifOut = tempDir.resolve("incident.sarif")
        val cli = ServerDoctorCommand().subcommands(DiagnoseIncidentCommand())
        cli.parse(
            listOf(
                "diagnose-incident",
                serverLog.toString(),
                "--jfr",
                hostCapture.toString(),
                "--format",
                "sarif",
                "-o",
                sarifOut.toString(),
                "--fail-on",
                "never",
            ),
        )
        val sarifText = Files.readString(sarifOut)
        assertTrue(sarifText.contains("\"L042\""))
        assertTrue(sarifText.contains("\"L045\""))

        // MCP correlate_incident_timeline tool
        val mcpTool = ToolCatalog.tools().firstOrNull { it.name == "correlate_incident_timeline" }
        assertNotNull(mcpTool)
        val mcpRes = mcpTool!!.call(
            buildJsonObject {
                put("path", serverLog.toAbsolutePath().toString())
                put("jfr_path", hostCapture.toAbsolutePath().toString())
            },
        )
        assertFalse(mcpRes.isError)
        val parsed = Json.parseToJsonElement(mcpRes.text).jsonObject
        val findings = parsed["audits"]!!.jsonArray.single().jsonObject["findings"]!!.jsonArray
        assertEquals(4, findings.size)
    }
}
