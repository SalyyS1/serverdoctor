package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.core.Severity
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.LogParser
import com.salyvn.serverdoctor.log.LogTriage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class LogTriageTest {

    private val report by lazy {
        LogTriage().analyse(LogSource.of(TestFixtures.path("/logs/broken-paper-server.log")))
    }

    private fun ids() = report.findings.map { it.ruleId }.toSet()

    @Test
    fun `finds the signatures the fixture contains`() {
        val expected = setOf(
            "L001", // watchdog
            "L002", // async catcher
            "L003", // event handler threw
            "L004", // plugin load failed
            "L005", // ambiguous plugin name
            "L006", // class file version
            "L009", // legacy plugin, no api-version
            "L010", // deprecated api nag
            "L012", // eula
            "L013", // out of memory
        )
        assertTrue(ids().containsAll(expected), "missing ${expected - ids()} in ${ids()}")
    }

    @Test
    fun `does not claim vanilla's overload warning on a paper log`() {
        assertFalse("L014" in ids(), "L014 should only fire when the line is actually present")
    }

    @Test
    fun `groups repeated occurrences instead of listing each one`() {
        val eventThrow = report.findings.first { it.ruleId == "L003" }
        assertTrue(eventThrow.location.contains("x2"), "expected a count in ${eventThrow.location}")
    }

    @Test
    fun `keeps the watchdog dump separate from later stack traces`() {
        val watchdog = report.findings.first { it.ruleId == "L001" }
        assertTrue(
            watchdog.evidence.any { it.contains("MySqlStore") },
            "watchdog evidence should carry the dump: ${watchdog.evidence}",
        )
        assertTrue(
            watchdog.evidence.none { it.contains("RegionReader") },
            "an unrelated later trace leaked into the dump: ${watchdog.evidence}",
        )
    }

    @Test
    fun `reports an error no rule explains rather than staying silent`() {
        val leftover = report.findings.firstOrNull { it.ruleId == "L016" }
        assertNotNull(leftover, "the corrupt-region exception has no signature and must still surface")
        assertTrue(leftover!!.detail.contains("IllegalStateException"))
    }

    @Test
    fun `reads the server facts out of the header lines`() {
        assertEquals("26.2", report.facts["minecraft"])
        assertTrue(report.facts["server"]!!.startsWith("Paper version"))
        assertEquals("paper", report.facts["line format"])
    }

    @Test
    fun `worst severity is a blocker because start-up failed`() {
        assertEquals(Severity.BLOCKER, report.worst)
    }

    @Test
    fun `parses the three header shapes and strips transport noise`() {
        val parser = LogParser()
        val cases = mapOf(
            "[22:31:04] [Server thread/INFO]: hello" to Triple("Server thread", "INFO", "hello"),
            "[22:31:04 WARN]: hello" to Triple(null, "WARN", "hello"),
            "[2026-08-24 22:31:04] [main/ERROR]: hello" to Triple("main", "ERROR", "hello"),
        )
        for ((line, expected) in cases) {
            val events = collect(parser, line)
            assertEquals(1, events.size, "one event for: $line")
            val event = events.single()
            assertEquals(expected.first, event.thread)
            assertEquals(expected.second, event.level)
            assertEquals(expected.third, event.message)
        }
    }

    @Test
    fun `takes the plugin name out of a bracketed logger prefix`() {
        val event = collect(LogParser(), "[22:31:04] [Server thread/INFO]: [WorldTools] loaded").single()
        assertEquals("WorldTools", event.loggerPlugin)
        assertEquals("loaded", event.message)
    }

    @Test
    fun `does not mistake bracketed prose for a plugin prefix`() {
        val event = collect(LogParser(), "[22:31:04] [Server thread/INFO]: [this is not a plugin!] x").single()
        assertNull(event.loggerPlugin)
    }

    @Test
    fun `parses unified jvm gc log lines as individual events`() {
        val log = """
            [142.810s][info][gc] GC(14) Pause Young (Normal) (G1 Evacuation Pause) 4812M->2104M(8192M) 185.421ms
            [512.119s][warning][gc,alloc] Regionizer-Tick-2: Retried waiting for GCLocker too often allocating 256 words
        """.trimIndent()
        val events = collect(LogParser(), log)
        assertEquals(2, events.size)
        assertEquals("jvm:gc", events[0].thread)
        assertEquals("INFO", events[0].level)
        assertEquals("jvm:gc,alloc", events[1].thread)
        assertEquals("WARN", events[1].level)
    }

    @Test
    fun `detects folia tickthread violations and synchronous teleports without double firing L002`() {
        val foliaLog = """
            [12:01:00] [Region Scheduler Thread #3/ERROR]: Thread Region Scheduler Thread #3 failed main thread check: Cannot move entity off-main
            java.lang.IllegalStateException: Cannot read world asynchronously
            	at ca.spottedleaf.moonrise.common.util.TickThread.ensureTickThread(TickThread.java:58)
            	at net.minecraft.server.level.ServerLevel.getBlockState(ServerLevel.java:412)
            	at com.example.skywars.ArenaManager.resetCage(ArenaManager.java:91)
            [12:01:05] [Region Scheduler Thread #1/ERROR]: Could not pass event PlayerMoveEvent to SkyWars v2.1.0
            java.lang.UnsupportedOperationException: Must use teleportAsync while in region threading
            	at org.bukkit.craftbukkit.entity.CraftEntity.teleport(CraftEntity.java:214)
            	at com.example.skywars.BorderGuard.pushBack(BorderGuard.java:44)
            [12:01:09] [Region Scheduler Thread #2/ERROR]: Unhandled scheduler error
            java.lang.UnsupportedOperationException: CraftScheduler is not supported in Folia region threading
            	at org.bukkit.craftbukkit.scheduler.CraftScheduler.handleCraftSchedulerUnsupported(CraftScheduler.java:512)
            	at com.example.skywars.ArenaTimer.start(ArenaTimer.java:29)
        """.trimIndent()
        val triaged = triageText(foliaLog)
        val ids = triaged.findings.map { it.ruleId }.toSet()
        assertTrue("L017" in ids, "expected Folia TickThread violation L017 in $ids")
        assertFalse("L002" in ids, "Folia TickThread check should report as L017 rather than generic L002: $ids")
        val hits = triaged.findings.filter { it.ruleId == "L017" }
        assertEquals(3, hits.size, "expected 3 distinct Folia violations: $hits")
        assertTrue(hits.any { it.detail.contains("com.example.skywars") })
    }

    @Test
    fun `detects folia regional watchdog stall and collects stalled region stack frames`() {
        val stallLog = """
            [14:22:10] [Folia Region Watchdog/ERROR]: --- DO NOT REPORT THIS TO FOLIA - THIS IS NOT A BUG OR A CRASH ---
            [14:22:10] [Folia Region Watchdog/ERROR]: Tick region (12, -4) has not responded for 15.2 seconds!
            [14:22:10] [Folia Region Watchdog/ERROR]: 	at java.base/java.net.SocketInputStream.read(SocketInputStream.java:151)
            [14:22:10] [Folia Region Watchdog/ERROR]: 	at com.example.crates.WebhookClient.post(WebhookClient.java:77)
        """.trimIndent()
        val triaged = triageText(stallLog)
        val ids = triaged.findings.map { it.ruleId }.toSet()
        assertTrue("L018" in ids, "expected Folia region stall L018 in $ids")
        assertFalse("L001" in ids, "Folia region stall should not also fire Paper L001")
        val stall = triaged.findings.first { it.ruleId == "L018" }
        assertTrue(stall.evidence.any { it.contains("WebhookClient") }, "expected region dump frame in ${stall.evidence}")
    }

    @Test
    fun `distinguishes healthy sub-tick gc pauses from long pauses and heap thrashing`() {
        val healthyGc = """
            [10.100s][info][gc] GC(1) Pause Young (Normal) (G1 Evacuation Pause) 2048M->512M(8192M) 18.420ms
            [12.400s][info][gc] GC(2) Pause Mark Start 0.042ms
        """.trimIndent()
        assertTrue(triageText(healthyGc).findings.isEmpty(), "sub-50ms pauses with low live occupancy must stay quiet")

        val unhealthyGc = """
            [142.810s][info][gc] GC(14) Pause Young (Normal) (G1 Evacuation Pause) 6812M->2104M(8192M) 185.421ms
            [318.004s][info][gc] GC(29) Pause Full (G1 Compaction Pause) 7980M->7420M(8192M) 1420.612ms
            [604.220s][info][gc] GC(44) Allocation Stall (Region Scheduler Thread #2) 312.480ms
        """.trimIndent()
        val triaged = triageText(unhealthyGc)
        val ids = triaged.findings.map { it.ruleId }.toSet()
        assertTrue("L019" in ids, "expected long GC pause L019 in $ids")
        assertTrue("L020" in ids, "expected GC heap pressure / stall L020 in $ids")
    }

    @Test
    fun `detects paper synchronous chunk loads and chunk system io bottlenecks`() {
        val chunkLog = """
            [18:10:01] [Server thread/WARN]: Catching synchronous chunk load at world (-42, 19)
            java.lang.Throwable: Synchronous chunk load
            	at io.papermc.paper.chunk.system.scheduling.SyncLoadFinder.logSyncLoad(SyncLoadFinder.java:88)
            	at com.example.rtp.RandomTeleport.pickSafeSpot(RandomTeleport.java:114)
            [18:11:12] [RegionFile I/O Thread #0/ERROR]: Failed to save chunk (-42, 19) in world 'world'
            java.io.IOException: No space left on device
            	at ca.spottedleaf.moonrise.patches.chunk_system.io.MoonriseRegionFileIO.writeData(MoonriseRegionFileIO.java:310)
            [18:11:20] [RegionFile I/O Thread #0/WARN]: Saving oversized chunk (8, -3) (1482310 bytes) to external .mcc file
        """.trimIndent()
        val triaged = triageText(chunkLog)
        val ids = triaged.findings.map { it.ruleId }.toSet()
        assertTrue("L021" in ids, "expected sync chunk load L021 in $ids")
        assertTrue("L022" in ids, "expected chunk I/O bottleneck L022 in $ids")
        val syncFinding = triaged.findings.first { it.ruleId == "L021" }
        assertTrue(syncFinding.detail.contains("com.example.rtp"), syncFinding.detail)
    }

    @Test
    fun `detects spark slow tick duration spikes and exported flamegraphs`() {
        val sparkLog = """
            [19:15:30] [Server thread/WARN]: [spark] Slow tick detected: 482ms (threshold: 100ms)
            [19:15:32] [Server thread/INFO]: [spark] Flame graph exported to https://spark.lucko.me/abcXYZ123
        """.trimIndent()
        val triaged = triageText(sparkLog)
        val ids = triaged.findings.map { it.ruleId }.toSet()
        assertTrue("L023" in ids, "expected spark hotspot L023 in $ids")
        val finding = triaged.findings.first { it.ruleId == "L023" }
        assertTrue(finding.detail.contains("spark.lucko.me") || finding.detail.contains("482ms"), finding.detail)
    }

    @Test
    fun `detects netty packet sizing overflows and direct memory exhaustion`() {
        val nettyLog = """
            [20:01:15] [Netty Epoll Server IO #1/ERROR]: io.netty.handler.codec.EncoderException: Packet too large: 2491823 bytes
            	at io.netty.handler.codec.MessageToByteEncoder.write(MessageToByteEncoder.java:107)
            	at com.example.customprotocol.PacketInterceptor.encode(PacketInterceptor.java:45)
            [20:02:10] [Netty Epoll Server IO #2/ERROR]: io.netty.util.internal.OutOfDirectMemoryError: failed to allocate 16777216 byte(s) of direct memory
        """.trimIndent()
        val triaged = triageText(nettyLog)
        val ids = triaged.findings.map { it.ruleId }.toSet()
        assertTrue("L024" in ids, "expected netty packet contention L024 in $ids")
        val encoderFinding = triaged.findings.first { it.ruleId == "L024" && it.detail.contains("Packet") }
        assertTrue(encoderFinding.detail.contains("com.example.customprotocol") || encoderFinding.detail.contains("Packet payload"), encoderFinding.detail)
    }

    private fun triageText(text: String): com.salyvn.serverdoctor.core.ScanReport {
        val file = kotlin.io.path.createTempFile(suffix = ".log")
        file.toFile().writeText(text + "\n")
        return try {
            LogTriage().analyse(LogSource.of(file))
        } finally {
            file.toFile().delete()
        }
    }

    private fun collect(parser: LogParser, text: String): List<com.salyvn.serverdoctor.log.LogEvent> {
        val file = kotlin.io.path.createTempFile(suffix = ".log")
        file.toFile().writeText(text + "\n")
        val events = mutableListOf<com.salyvn.serverdoctor.log.LogEvent>()
        parser.parse(LogSource.of(file)) { events += it }
        file.toFile().delete()
        return events
    }
}
