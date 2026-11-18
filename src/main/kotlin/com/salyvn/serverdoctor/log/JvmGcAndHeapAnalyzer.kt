package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.util.Locale

/**
 * Diagnostic analyzer for unified JVM garbage collection logs (-Xlog:gc*) and
 * heap histograms (jmap -histo, jcmd GC.class_histogram, and Spark heap summaries).
 *
 * Specializes in identifying:
 * - Plugin memory retention and classloader leaks (L035)
 * - G1GC to-space exhaustion and humongous allocation fragmentation (L036)
 * - Generational ZGC mutator allocation stalls and worker preemption (L037)
 * - Metaspace threshold expansion pauses and class unloading thrash (L038)
 */
object JvmGcAndHeapAnalyzer {

    data class HeapHistogramEntry(
        val rank: Int,
        val instances: Long,
        val bytes: Long,
        val className: String,
        val blamedPlugin: String? = null,
        val percentageOfHeap: Double = 0.0,
    )

    data class HeapHistogramReport(
        val totalInstances: Long,
        val totalBytes: Long,
        val entries: List<HeapHistogramEntry>,
        val flaggedLeaks: List<HeapHistogramEntry>,
    )

    data class GcPauseEvent(
        val cycleNumber: Long?,
        val phase: String,
        val collector: String,
        val pauseDurationMs: Double,
        val rawLine: String,
        val humongousAllocation: Boolean = false,
        val toSpaceExhausted: Boolean = false,
        val allocationStall: Boolean = false,
        val metaspaceTriggered: Boolean = false,
        val stalledThread: String? = null,
    )

    data class GcAnalysisSummary(
        val collector: String,
        val totalPauses: Int,
        val totalPauseMs: Double,
        val maxPauseMs: Double,
        val p95PauseMs: Double,
        val toSpaceExhaustionCount: Int,
        val allocationStallCount: Int,
        val humongousAllocationCount: Int,
        val metaspacePauseCount: Int,
        val events: List<GcPauseEvent>,
    )

    private val HISTO_LINE_RE = Regex(
        """^\s*(\d+):\s+(\d+)\s+(\d+)\s+([a-zA-Z0-9_$.\[]+)(?:\s+\(.*\))?""",
    )
    private val HISTO_TOTAL_RE = Regex(
        """Total\s+(\d+)\s+(\d+)""",
        RegexOption.IGNORE_CASE,
    )

    private val GC_PAUSE_RE = Regex(
        """(?:GC\((\d+)\)\s+)?Pause\s+([A-Za-z0-9 ()_-]+?)\s+(?:.*?(\d+(?:[.,]\d+)?)ms)""",
    )
    private val GC_CYCLE_RE = Regex("""GC\((\d+)\)""")
    private val PAUSE_MS_RE = Regex("""(\d+(?:[.,]\d+)?)\s*ms\b""")
    private val ZGC_STALL_RE = Regex("""Allocation Stall\s+\(([^)]+)\)\s+(\d+(?:[.,]\d+)?)ms""", RegexOption.IGNORE_CASE)
    private val HUMONGOUS_RE = Regex("""Humongous allocation:?\s*(\d+)\s*(?:bytes|B)""", RegexOption.IGNORE_CASE)

    fun formatBytes(bytes: Long): String = when {
        bytes >= 1024L * 1024L * 1024L -> String.format(Locale.ROOT, "%.2f GB", bytes.toDouble() / (1024.0 * 1024.0 * 1024.0))
        bytes >= 1024L * 1024L -> String.format(Locale.ROOT, "%.2f MB", bytes.toDouble() / (1024.0 * 1024.0))
        bytes >= 1024L -> String.format(Locale.ROOT, "%.2f KB", bytes.toDouble() / 1024.0)
        else -> "$bytes B"
    }

    /**
     * Parses output from `jmap -histo`, `jcmd GC.class_histogram`, or text heap summaries.
     */
    fun analyzeHeapHistogram(text: String, plugins: PluginIndex = PluginIndex.EMPTY): HeapHistogramReport {
        val lines = text.lines()
        val rawEntries = mutableListOf<HeapHistogramEntry>()
        var parsedTotalInstances = 0L
        var parsedTotalBytes = 0L

        for (line in lines) {
            val totalMatch = HISTO_TOTAL_RE.find(line)
            if (totalMatch != null) {
                parsedTotalInstances = totalMatch.groupValues[1].toLongOrNull() ?: parsedTotalInstances
                parsedTotalBytes = totalMatch.groupValues[2].toLongOrNull() ?: parsedTotalBytes
                continue
            }

            val match = HISTO_LINE_RE.find(line) ?: continue
            val rank = match.groupValues[1].toIntOrNull() ?: continue
            val instances = match.groupValues[2].toLongOrNull() ?: continue
            val bytes = match.groupValues[3].toLongOrNull() ?: continue
            val className = match.groupValues[4]

            val plugin = plugins.owningPlugin(className)?.descriptor?.name
                ?: inferPluginNameFromClass(className)

            rawEntries += HeapHistogramEntry(
                rank = rank,
                instances = instances,
                bytes = bytes,
                className = className,
                blamedPlugin = plugin,
            )
        }

        val totalBytes = if (parsedTotalBytes > 0L) parsedTotalBytes else rawEntries.sumOf { it.bytes }
        val totalInstances = if (parsedTotalInstances > 0L) parsedTotalInstances else rawEntries.sumOf { it.instances }

        val entries = rawEntries.map { entry ->
            val ratio = if (totalBytes > 0L) entry.bytes.toDouble() / totalBytes.toDouble() else 0.0
            entry.copy(percentageOfHeap = ratio)
        }

        val flagged = mutableListOf<HeapHistogramEntry>()
        for (entry in entries) {
            val isServer = ServerPackages.isServerOwned(entry.className)
            val isPrimitiveArray = entry.className.startsWith("[") && entry.className.length <= 3
            val isStandardJre = isServer || isPrimitiveArray ||
                entry.className.startsWith("java.lang.") ||
                entry.className.startsWith("java.util.") ||
                entry.className.startsWith("jdk.")

            val isPluginAssociated = entry.blamedPlugin != null || !isStandardJre ||
                entry.className.contains("PluginClassLoader", ignoreCase = true)

            // Flag if plugin-associated and dominates heap:
            // 1. Over 15% of live heap
            // 2. Over 100,000 instances
            // 3. Over 20,000 instances and >= 8% of heap
            // 4. Multiple PluginClassLoader instances (> 15) indicating reload leakage
            val isLeakCandidate = when {
                entry.className.contains("PluginClassLoader", ignoreCase = true) && entry.instances > 15 -> true
                isPluginAssociated && entry.percentageOfHeap >= 0.15 -> true
                isPluginAssociated && entry.instances >= 100_000 -> true
                isPluginAssociated && entry.instances >= 20_000 && entry.percentageOfHeap >= 0.08 -> true
                else -> false
            }

            if (isLeakCandidate) {
                flagged += entry
            }
        }

        return HeapHistogramReport(
            totalInstances = totalInstances,
            totalBytes = totalBytes,
            entries = entries,
            flaggedLeaks = flagged,
        )
    }

    private fun inferPluginNameFromClass(className: String): String? {
        if (ServerPackages.isServerOwned(className)) return null
        if (className.startsWith("[") || className.startsWith("java.") || className.startsWith("javax.")) return null
        val parts = className.split('.')
        return when {
            parts.size >= 3 && (parts[0] == "com" || parts[0] == "net" || parts[0] == "org" || parts[0] == "io" || parts[0] == "me") -> {
                parts[2].replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.ROOT) else it.toString() }
            }
            parts.size >= 2 -> parts[1]
            else -> null
        }
    }

    /**
     * Parses unified JVM garbage collection logs (-Xlog:gc*).
     */
    fun analyzeGcLog(text: String): GcAnalysisSummary {
        val lines = text.lines()
        val events = mutableListOf<GcPauseEvent>()

        var detectedCollector = "Unknown"
        var toSpaceCount = 0
        var allocStallCount = 0
        var humongousCount = 0
        var metaspaceCount = 0

        for (line in lines) {
            val lower = line.lowercase()
            if (detectedCollector == "Unknown") {
                when {
                    lower.contains("g1") -> detectedCollector = "G1GC"
                    lower.contains("zgc") || lower.contains("zgeneration") || lower.contains("allocation stall") -> detectedCollector = "Generational ZGC"
                    lower.contains("parallel") -> detectedCollector = "Parallel"
                    lower.contains("shenandoah") -> detectedCollector = "Shenandoah"
                    lower.contains("serial") -> detectedCollector = "Serial"
                }
            }

            val isToSpace = lower.contains("to-space exhausted") || lower.contains("evacuation failure")
            if (isToSpace) toSpaceCount++

            val isHumongous = lower.contains("humongous allocation")
            if (isHumongous) humongousCount++

            val isMeta = lower.contains("metadata gc threshold") || lower.contains("metaspace:") || lower.contains("compressedclassspace")
            if (isMeta && lower.contains("pause")) metaspaceCount++

            val zgcStallMatch = ZGC_STALL_RE.find(line)
            val isZgcStall = zgcStallMatch != null
            if (isZgcStall) allocStallCount++

            val cycleNum = GC_CYCLE_RE.find(line)?.groupValues?.get(1)?.toLongOrNull()

            val pauseMatch = GC_PAUSE_RE.find(line)
            if (pauseMatch != null) {
                val phase = pauseMatch.groupValues[2].trim()
                val durationMs = pauseMatch.groupValues[3].replace(',', '.').toDoubleOrNull() ?: 0.0

                events += GcPauseEvent(
                    cycleNumber = cycleNum,
                    phase = phase,
                    collector = detectedCollector,
                    pauseDurationMs = durationMs,
                    rawLine = line.trim(),
                    humongousAllocation = isHumongous,
                    toSpaceExhausted = isToSpace,
                    allocationStall = isZgcStall,
                    metaspaceTriggered = isMeta,
                    stalledThread = zgcStallMatch?.groupValues?.get(1),
                )
            } else if (isZgcStall) {
                val stalledThread = zgcStallMatch.groupValues[1]
                val durationMs = zgcStallMatch.groupValues[2].replace(',', '.').toDoubleOrNull() ?: 0.0
                events += GcPauseEvent(
                    cycleNumber = cycleNum,
                    phase = "Allocation Stall",
                    collector = "Generational ZGC",
                    pauseDurationMs = durationMs,
                    rawLine = line.trim(),
                    allocationStall = true,
                    stalledThread = stalledThread,
                )
            }
        }

        val durations = events.map { it.pauseDurationMs }.sorted()
        val totalPauses = events.size
        val totalMs = durations.sum()
        val maxMs = durations.lastOrNull() ?: 0.0
        val p95Ms = if (durations.isNotEmpty()) {
            val idx = (durations.size * 0.95).toInt().coerceAtMost(durations.size - 1)
            durations[idx]
        } else 0.0

        return GcAnalysisSummary(
            collector = if (detectedCollector == "Unknown") "HotSpot Unified GC" else detectedCollector,
            totalPauses = totalPauses,
            totalPauseMs = totalMs,
            maxPauseMs = maxMs,
            p95PauseMs = p95Ms,
            toSpaceExhaustionCount = toSpaceCount,
            allocationStallCount = allocStallCount,
            humongousAllocationCount = humongousCount,
            metaspacePauseCount = metaspaceCount,
            events = events,
        )
    }

    /**
     * Complete diagnostic run over GC log and optional heap histogram source.
     */
    fun diagnose(
        source: LogSource,
        plugins: PluginIndex = PluginIndex.EMPTY,
        histoSource: LogSource? = null,
    ): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()

        val fullLines = mutableListOf<String>()
        source.forEachLine { fullLines += it.text }
        val fullText = fullLines.joinToString("\n")

        val histoLines = mutableListOf<String>()
        if (histoSource != null) {
            histoSource.forEachLine { histoLines += it.text }
        }
        val histoText = if (histoLines.isNotEmpty()) histoLines.joinToString("\n") else fullText
        val locationName = source.path.fileName.toString()

        val histoReport = analyzeHeapHistogram(histoText, plugins)
        if (histoReport.totalBytes > 0L) {
            facts["heap.total_live_bytes"] = formatBytes(histoReport.totalBytes)
            facts["heap.total_instances"] = histoReport.totalInstances.toString()
            histoReport.entries.firstOrNull()?.let { top ->
                facts["heap.top_retained_class"] = "${top.className} (${formatBytes(top.bytes)}, ${String.format(Locale.ROOT, "%.1f", top.percentageOfHeap * 100)}%)"
            }
        }

        for (leak in histoReport.flaggedLeaks) {
            val pluginText = if (leak.blamedPlugin != null) " attributable to plugin '${leak.blamedPlugin}'" else ""
            sink.add(
                rule = LogRules.JVM_HEAP_HISTO_PLUGIN_RETENTION,
                location = "class ${leak.className}",
                detail = "JVM heap histogram shows dominant memory retention: class '${leak.className}' retains ${formatBytes(leak.bytes)} (${String.format(Locale.ROOT, "%.1f", leak.percentageOfHeap * 100)}% of live heap across ${leak.instances} instances)$pluginText.",
                evidence = listOf(
                    "#instances: ${leak.instances}, #bytes: ${leak.bytes} (${formatBytes(leak.bytes)})",
                    "live heap share: ${String.format(Locale.ROOT, "%.1f", leak.percentageOfHeap * 100)}%",
                ),
            )
        }

        val gcSummary = analyzeGcLog(fullText)
        facts["gc.collector"] = gcSummary.collector
        facts["gc.total_pauses"] = gcSummary.totalPauses.toString()
        facts["gc.total_pause_ms"] = String.format(Locale.ROOT, "%.2f ms", gcSummary.totalPauseMs)
        facts["gc.max_pause_ms"] = String.format(Locale.ROOT, "%.2f ms", gcSummary.maxPauseMs)
        facts["gc.p95_pause_ms"] = String.format(Locale.ROOT, "%.2f ms", gcSummary.p95PauseMs)

        if (gcSummary.toSpaceExhaustionCount > 0 || gcSummary.humongousAllocationCount > 0) {
            sink.add(
                rule = LogRules.G1GC_CONCURRENT_MARK_OR_TO_SPACE_EXHAUSTION,
                location = locationName,
                detail = "G1GC log records ${gcSummary.toSpaceExhaustionCount} to-space exhaustion event(s) and ${gcSummary.humongousAllocationCount} humongous allocation event(s) causing memory fragmentation and evacuation failure.",
                evidence = gcSummary.events.filter { it.toSpaceExhausted || it.humongousAllocation }.take(5).map { it.rawLine },
            )
        }

        if (gcSummary.allocationStallCount > 0) {
            val stalledThreads = gcSummary.events.filter { it.allocationStall }.mapNotNull { it.stalledThread }.distinct()
            val threadList = if (stalledThreads.isNotEmpty()) " (threads: ${stalledThreads.joinToString(", ")})" else ""
            sink.add(
                rule = LogRules.GENERATIONAL_ZGC_ALLOCATION_STALL_OR_RATE_SPIKE,
                location = locationName,
                detail = "Generational ZGC log records ${gcSummary.allocationStallCount} mutator thread allocation stall(s)$threadList freezing server tick processing while waiting for free heap pages.",
                evidence = gcSummary.events.filter { it.allocationStall }.take(5).map { it.rawLine },
            )
        }

        if (gcSummary.metaspacePauseCount > 0) {
            sink.add(
                rule = LogRules.GC_PAUSE_JITTER_AND_METASPACE_EXPANSION,
                location = locationName,
                detail = "Unified GC log records ${gcSummary.metaspacePauseCount} pause(s) triggered by Metadata GC Threshold / Metaspace expansion.",
                evidence = gcSummary.events.filter { it.metaspaceTriggered }.take(5).map { it.rawLine },
            )
        }

        return ScanReport(
            tool = "serverdoctor",
            toolVersion = BuildInfo.version,
            subject = locationName,
            subjectKind = "jvm-gc-heap-log",
            findings = sink.findings(),
            facts = facts,
        )
    }
}
