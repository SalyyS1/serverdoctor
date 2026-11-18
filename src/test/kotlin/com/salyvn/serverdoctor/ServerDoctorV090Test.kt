package com.salyvn.serverdoctor

import com.github.ajalt.clikt.core.parse
import com.github.ajalt.clikt.core.subcommands
import com.salyvn.serverdoctor.cli.ContentionCommand
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.LogTriage
import com.salyvn.serverdoctor.log.NativeLeakTicketAndContentionAnalyzer
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

class ServerDoctorV090Test {

    @Test
    fun `detects Netty ResourceLeakDetector ByteBuf last-touch leak and native pool pressure`() {
        val logText = """
            [14:01:12] [Netty Epoll Server IO #1/ERROR]: LEAK: ByteBuf.release() was not called before it's garbage-collected. See https://netty.io/wiki/reference-counted-objects.html for more information.
            Recent access records:
            #1:
                Hint: 'packet_interceptor'
                at com.example.packetguard.CustomPayloadDecoder.channelRead(CustomPayloadDecoder.java:74)
                at io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:444)
            Created at:
                at io.netty.buffer.PooledByteBufAllocator.newDirectBuffer(PooledByteBufAllocator.java:402)
            [14:01:20] [Server thread/WARN]: DirectBufferPool: used=768 MiB, max=1024 MiB
        """.trimIndent()

        val report = NativeLeakTicketAndContentionAnalyzer.analyzeDirectByteBufLeaks(logText)
        assertEquals(1, report.leakRecordCount)
        assertEquals(2, report.incidents.size)

        val touchIncident = report.incidents.first {
            it.kind == NativeLeakTicketAndContentionAnalyzer.ByteBufLeakKind.UNRELEASED_LAST_TOUCH
        }
        assertEquals("packet_interceptor", touchIncident.handlerHint)
        assertEquals("com.example.packetguard.CustomPayloadDecoder", touchIncident.blamedPlugin)
        assertEquals("com.example.packetguard.CustomPayloadDecoder.channelRead", touchIncident.primaryFrame)

        val poolIncident = report.incidents.first {
            it.kind == NativeLeakTicketAndContentionAnalyzer.ByteBufLeakKind.OFF_HEAP_DIRECT_POOL_PRESSURE
        }
        assertEquals(768L * 1024L * 1024L, poolIncident.committedBytes)
    }

    @Test
    fun `computes exact deduplicated 2D Chebyshev propagation footprint for Moonrise chunk tickets`() {
        // Two overlapping level-31 tickets at (0, 0) and (1, 0):
        // Each level-31 ticket has radius r = 33 - 31 = 2 (5x5 = 25 chunks).
        // Shifting x by +1 overlaps 4x5 = 20 chunks, so exact union = 25 + 25 - 20 = 30 chunks!
        val overlappingText = """
            world=world chunk (0, 0) level=31 type=plugin_ticket owner=DungeonArenas
            world=world chunk (1, 0) level=31 type=plugin_ticket owner=DungeonArenas
        """.trimIndent()

        val smallReport = NativeLeakTicketAndContentionAnalyzer.analyzeChunkTicketLeaks(overlappingText)
        assertEquals(2, smallReport.totalTickets)
        assertEquals(30, smallReport.totalEffectivePinnedChunks)

        // Generate 36 non-player tickets across spaced coordinates to cross leak thresholds
        val spacedLines = (0 until 36).joinToString("\n") { idx ->
            "world=world_dungeons chunk (${idx * 10}, 0) level=31 type=plugin_ticket owner=DungeonArenas"
        }
        val leakReport = NativeLeakTicketAndContentionAnalyzer.analyzeChunkTicketLeaks(spacedLines)
        assertEquals(36, leakReport.totalTickets)
        assertEquals(36 * 25, leakReport.totalEffectivePinnedChunks)
        assertEquals(1, leakReport.flaggedLeaks.size)
        assertEquals("DungeonArenas", leakReport.flaggedLeaks.single().owner)
    }

    @Test
    fun `analyzes JFR JavaMonitorEnter lock inversion and async-profiler collapsed lock stacks`() {
        val profile = """
            jdk.JavaMonitorEnter {
              startTime = 14:03:10.112
              duration = 142.5 ms
              monitorClass = com.example.guilds.GuildCacheLock
              previousOwner = "Craft Scheduler Thread - 4"
              eventThread = "Server thread"
              stackTrace = [
                com.example.guilds.GuildManager.getGuild(GuildManager.java:118)
                net.minecraft.server.MinecraftServer.tickServer(MinecraftServer.java:912)
              ]
            }
            jdk.ThreadPark {
              startTime = 14:03:11.000
              duration = 45.0 ms
              parkedClass = java.util.concurrent.locks.AbstractQueuedSynchronizer
              eventThread = "Server thread"
              stackTrace = [
                net.minecraft.server.MinecraftServer.waitUntilNextTick(MinecraftServer.java:960)
              ]
            }
            Region Scheduler Thread #2;io.papermc.paper.threadedregions.TickRegions.tick;com.example.claims.ClaimIndex.lookup;java.util.concurrent.locks.ReentrantLock_[i] 85000000
        """.trimIndent()

        val contention = NativeLeakTicketAndContentionAnalyzer.analyzeLockContention(profile)
        // Benign waitUntilNextTick is filtered out; 2 real contention hotspots remain
        assertEquals(2, contention.flaggedHotspots.size)
        assertEquals(1, contention.lockInversionCount)

        val jfrHotspot = contention.flaggedHotspots.first { it.monitorClass.contains("GuildCacheLock") }
        assertTrue(jfrHotspot.lockInversion)
        assertEquals("Server thread", jfrHotspot.waiterThread)
        assertEquals("Craft Scheduler Thread - 4", jfrHotspot.ownerThread)
        assertEquals(142.5, jfrHotspot.totalBlockedMs, 0.01)
        assertEquals("com.example.guilds.GuildManager", jfrHotspot.blamedPlugin)

        val asyncProfHotspot = contention.flaggedHotspots.first { it.waiterThread == "Region Scheduler Thread #2" }
        assertEquals(85.0, asyncProfHotspot.totalBlockedMs, 0.01)
        assertEquals("com.example.claims.ClaimIndex", asyncProfHotspot.blamedPlugin)
    }

    @Test
    fun `diagnose, LogTriage, CLI contention command, and MCP tool surface L039 through L041`(@TempDir tempDir: Path) {
        val logFile = tempDir.resolve("combined-v090.log")
        Files.writeString(
            logFile,
            """
            [14:00:01] [ServerMain/INFO]: Starting minecraft server version 26.3
            [14:01:12] [Netty Epoll Server IO #1/ERROR]: LEAK: ByteBuf.release() was not called before it's garbage-collected.
            Recent access records:
            #1:
                Hint: 'packet_guard'
                at com.example.packetguard.PacketHook.channelRead(PacketHook.java:51)
            [14:02:00] [Server thread/WARN]: PluginChunkTickets(world=world): ArenaKeeper=48, SpawnGuard=2
            jdk.JavaMonitorEnter {
              duration = 96.0 ms
              monitorClass = com.example.economy.LedgerLock
              previousOwner = "Folia Async Scheduler Thread #1"
              eventThread = "Region Scheduler Thread #0"
              stackTrace = [
                com.example.economy.LedgerService.debit(LedgerService.java:63)
              ]
            }
            """.trimIndent(),
        )

        val diagReport = NativeLeakTicketAndContentionAnalyzer.diagnose(LogSource.of(logFile))
        val diagRules = diagReport.findings.map { it.ruleId }.toSet()
        assertTrue(diagRules.containsAll(setOf("L039", "L040", "L041")), "Expected L039..L041 in $diagRules")

        val triageReport = LogTriage(PluginIndex.EMPTY).analyse(LogSource.of(logFile))
        val triageRules = triageReport.findings.map { it.ruleId }.toSet()
        assertTrue(triageRules.containsAll(setOf("L039", "L040", "L041")), "Expected L039..L041 in LogTriage: $triageRules")

        val sarifOut = tempDir.resolve("contention.sarif")
        val cli = ServerDoctorCommand().subcommands(ContentionCommand())
        cli.parse(listOf("contention", logFile.toString(), "--format", "sarif", "-o", sarifOut.toString(), "--fail-on", "never"))
        val sarifJson = Files.readString(sarifOut)
        assertTrue(sarifJson.contains("\"L039\""))
        assertTrue(sarifJson.contains("\"L040\""))
        assertTrue(sarifJson.contains("\"L041\""))

        val mcpTool = ToolCatalog.tools().firstOrNull { it.name == "analyze_memory_and_contention" }
        assertNotNull(mcpTool)
        val result = mcpTool!!.call(
            buildJsonObject {
                put("path", logFile.toAbsolutePath().toString())
            },
        )
        assertFalse(result.isError)
        val parsed = Json.parseToJsonElement(result.text).jsonObject
        val findings = parsed["audits"]!!.jsonArray.single().jsonObject["findings"]!!.jsonArray
        assertEquals(3, findings.size)
    }
}
