package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.JvmGcAndHeapAnalyzer
import com.salyvn.serverdoctor.log.LogRules
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

class ServerDoctorV080Test {

    @Test
    fun `analyze heap histogram detects plugin retention and leaks`() {
        val histogram = """
             num     #instances         #bytes  class name (module)
            -------------------------------------------------------
               1:        145281       34867440  [B (java.base@21.0.3)
               2:        125000       18500000  com.massivecraft.factions.entity.Board
               3:         85000        9200000  net.coreprotect.consumer.Process
               4:            28         150000  org.bukkit.plugin.java.PluginClassLoader
            Total        500000       75000000
        """.trimIndent()

        val report = JvmGcAndHeapAnalyzer.analyzeHeapHistogram(histogram)
        assertEquals(500000L, report.totalInstances)
        assertEquals(75000000L, report.totalBytes)
        assertEquals(4, report.entries.size)

        // Board has 125,000 instances and ~24.6% of heap -> flagged leak
        val board = report.flaggedLeaks.find { it.className.contains("Board") }
        assertNotNull(board)
        assertEquals("Factions", board?.blamedPlugin)
        assertTrue((board?.percentageOfHeap ?: 0.0) > 0.20)

        // PluginClassLoader has 28 instances (>15 reload leak threshold) -> flagged leak
        val classLoader = report.flaggedLeaks.find { it.className.contains("PluginClassLoader") }
        assertNotNull(classLoader)
    }

    @Test
    fun `analyze gc log detects G1GC to-space exhaustion and humongous allocations`() {
        val gcLog = """
            [0.120s][info][gc,start    ] GC(10) Pause Young (Normal) (G1 Evacuation Pause)
            [0.125s][info][gc          ] GC(10) To-space exhausted
            [0.180s][info][gc          ] GC(10) Pause Young (Normal) (G1 Evacuation Pause) 58.45ms
            [0.210s][info][gc,humongous] GC(11) Humongous allocation: 33554448 bytes (requested by Server thread)
            [0.250s][info][gc          ] GC(12) Pause Young (Normal) (G1 Evacuation Pause) 24.10ms
        """.trimIndent()

        val summary = JvmGcAndHeapAnalyzer.analyzeGcLog(gcLog)
        assertEquals("G1GC", summary.collector)
        assertEquals(2, summary.totalPauses)
        assertTrue(summary.maxPauseMs >= 58.45)
        assertEquals(1, summary.toSpaceExhaustionCount)
        assertEquals(1, summary.humongousAllocationCount)
    }

    @Test
    fun `analyze gc log detects Generational ZGC allocation stalls`() {
        val gcLog = """
            [1.450s][info][gc,alloc    ] Allocation Stall (Server thread) 84.120ms
            [1.520s][info][gc,alloc    ] Allocation Stall (Worker-3) 45.200ms
            [1.600s][info][gc          ] GC(20) Garbage Collection (Allocation Rate) 4500M->2100M(8192M) 5.120ms
        """.trimIndent()

        val summary = JvmGcAndHeapAnalyzer.analyzeGcLog(gcLog)
        assertEquals("Generational ZGC", summary.collector)
        assertEquals(2, summary.allocationStallCount)
        assertEquals(2, summary.totalPauses)
        val stallEvents = summary.events.filter { it.allocationStall }
        assertEquals(2, stallEvents.size)
        assertTrue(stallEvents.any { it.stalledThread == "Server thread" })
        assertTrue(stallEvents.any { it.stalledThread == "Worker-3" })
    }

    @Test
    fun `analyze gc log detects Metaspace expansion pauses`() {
        val gcLog = """
            [2.100s][info][gc,metaspace] GC(25) Pause Young (Normal) (Metadata GC Threshold) 95.412ms
            [2.110s][info][gc,metaspace] Metaspace: 124M->122M(145M)
            [2.115s][info][gc,metaspace] CompressedClassSpace: 16M->15M(24M)
        """.trimIndent()

        val summary = JvmGcAndHeapAnalyzer.analyzeGcLog(gcLog)
        assertEquals(1, summary.metaspacePauseCount)
        assertEquals(1, summary.totalPauses)
        assertTrue(summary.maxPauseMs >= 95.0)
    }

    @Test
    fun `diagnose produces comprehensive ScanReport with rules L035 through L038`(@TempDir tempDir: Path) {
        val logFile = tempDir.resolve("gc.log")
        val content = """
            [0.100s][info][gc,start    ] GC(1) Pause Young (Normal) (G1 Evacuation Pause)
            [0.110s][info][gc          ] GC(1) To-space exhausted
            [0.170s][info][gc          ] GC(1) Pause Young (Normal) (G1 Evacuation Pause) 62.50ms
            [0.200s][info][gc,humongous] GC(2) Humongous allocation: 33554448 bytes
            [0.300s][info][gc,alloc    ] Allocation Stall (Server thread) 95.20ms
            [0.400s][info][gc,metaspace] GC(3) Pause Young (Normal) (Metadata GC Threshold) 88.00ms
             num     #instances         #bytes  class name
            ----------------------------------------------
               1:        150000       25000000  com.example.leakyplugin.CacheEntry
               2:         10000        5000000  java.lang.String
            Total        200000       35000000
        """.trimIndent()
        Files.writeString(logFile, content)

        val report = JvmGcAndHeapAnalyzer.diagnose(LogSource.of(logFile))
        val ruleIds = report.findings.map { it.ruleId }.toSet()

        assertTrue(ruleIds.contains("L035"), "Expected L035 in $ruleIds")
        assertTrue(ruleIds.contains("L036"), "Expected L036 in $ruleIds")
        assertTrue(ruleIds.contains("L037"), "Expected L037 in $ruleIds")
        assertTrue(ruleIds.contains("L038"), "Expected L038 in $ruleIds")

        assertEquals("G1GC", report.facts["gc.collector"])
        assertNotNull(report.facts["gc.max_pause_ms"])
        assertNotNull(report.facts["heap.total_live_bytes"])
    }

    @Test
    fun `log triage pipeline recognizes L035 through L038`(@TempDir tempDir: Path) {
        val logFile = tempDir.resolve("server.log")
        val content = """
            [12:00:00 INFO]: [Server] Starting server...
            [12:00:01 INFO]: [gc] GC(10) To-space exhausted
            [12:00:02 INFO]: [gc] Allocation Stall (Server thread) 88.40ms
            [12:00:03 INFO]: [gc] GC(11) Pause Young (Normal) (Metadata GC Threshold) 74.20ms
            [12:00:04 INFO]: class name: com.example.plugin.Leaker instances: 120000 bytes: 40000000
               1:        120000       40000000  com.example.plugin.Leaker
            Total        150000       50000000
        """.trimIndent()
        Files.writeString(logFile, content)

        val report = LogTriage(PluginIndex.EMPTY).analyse(LogSource.of(logFile))
        val ruleIds = report.findings.map { it.ruleId }.toSet()

        assertTrue(ruleIds.contains("L035") || ruleIds.contains("L036") || ruleIds.contains("L037") || ruleIds.contains("L038"),
            "Expected one or more GC/heap rules in $ruleIds")
    }

    @Test
    fun `mcp tool analyze_gc_log returns valid JSON report`(@TempDir tempDir: Path) {
        val gcLog = tempDir.resolve("gc-test.log")
        Files.writeString(gcLog, """
            [0.100s][info][gc          ] GC(1) To-space exhausted
            [0.120s][info][gc,alloc    ] Allocation Stall (Server thread) 65.00ms
        """.trimIndent())

        val tool = ToolCatalog.tools().firstOrNull { it.name == "analyze_gc_log" }
        assertNotNull(tool)

        val result = tool!!.call(buildJsonObject {
            put("path", gcLog.toAbsolutePath().toString())
        })

        assertFalse(result.isError)
        val json = Json.parseToJsonElement(result.text).jsonObject
        assertEquals("serverdoctor", json["tool"]?.toString()?.replace("\"", ""))
        val audits = json["audits"]?.jsonArray
        assertNotNull(audits)
        assertTrue(audits!!.isNotEmpty())
        val findings = audits[0].jsonObject["findings"]?.jsonArray
        assertNotNull(findings)
    }
}
