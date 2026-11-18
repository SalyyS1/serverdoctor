package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.util.Locale
import kotlin.math.max

/**
 * Offline diagnostic analyzer for native off-heap memory leaks, Paper 26.3 Moonrise chunk ticket
 * leaks, and JDK Flight Recorder / async-profiler wall-clock lock contention profiles:
 * - L039: Netty ResourceLeakDetector ByteBuf touch/allocation leaks and VM.native_memory off-heap growth
 * - L040: Paper 26.3 / Moonrise persistent plugin chunk tickets and force-loaded chunk propagation footprints
 * - L041: JFR (jdk.JavaMonitorEnter / jdk.ThreadPark) and async-profiler lock contention convoys and inversions
 */
object NativeLeakTicketAndContentionAnalyzer {

    enum class ByteBufLeakKind {
        UNRELEASED_LAST_TOUCH,
        UNRELEASED_ALLOCATION,
        OFF_HEAP_DIRECT_POOL_PRESSURE,
    }

    data class DirectMemoryLeakIncident(
        val line: Int,
        val kind: ByteBufLeakKind,
        val blamedPlugin: String?,
        val handlerHint: String?,
        val primaryFrame: String?,
        val touchRecordCount: Int,
        val committedBytes: Long?,
        val maxBytes: Long?,
        val evidence: List<String>,
    )

    data class DirectMemoryReport(
        val leakRecordCount: Int,
        val committedDirectBytes: Long,
        val maxDirectBytes: Long,
        val incidents: List<DirectMemoryLeakIncident>,
    )

    data class ChunkTicketLeakGroup(
        val line: Int,
        val owner: String,
        val ticketType: String,
        val world: String,
        val ticketCount: Int,
        val minTicketLevel: Int,
        val effectivePinnedChunks: Int,
        val blamedPlugin: String?,
        val evidence: List<String>,
    )

    data class ChunkTicketReport(
        val totalTickets: Int,
        val totalEffectivePinnedChunks: Int,
        val groups: List<ChunkTicketLeakGroup>,
        val flaggedLeaks: List<ChunkTicketLeakGroup>,
    )

    data class LockContentionHotspot(
        val line: Int,
        val waiterThread: String,
        val ownerThread: String?,
        val monitorClass: String,
        val eventCount: Int,
        val totalBlockedMs: Double,
        val maxWaitMs: Double,
        val lostTicks: Double,
        val lockInversion: Boolean,
        val blamedPlugin: String?,
        val evidence: List<String>,
    )

    data class LockContentionReport(
        val totalEvents: Int,
        val totalBlockedMs: Double,
        val maxSingleWaitMs: Double,
        val lockInversionCount: Int,
        val hotspots: List<LockContentionHotspot>,
        val flaggedHotspots: List<LockContentionHotspot>,
    )

    data class LineHit(
        val discriminator: String,
        val line: Int,
        val detail: String,
        val evidence: List<String>,
    )

    private data class ChunkCoord(val world: String, val x: Int, val z: Int)

    private val NETTY_LEAK_BANNER_RE = Regex(
        """LEAK:\s*ByteBuf\.release\(\)\s+was not called before it's garbage-collected""",
        RegexOption.IGNORE_CASE,
    )
    private val NETTY_HINT_RE = Regex("""Hint:\s*['"]?([^'"\r\n]+)['"]?""")
    private val NETTY_TOUCH_INDEX_RE = Regex("""^\s*#(\d+):\s*(.*)$""")
    private val NMT_SECTION_RE = Regex(
        """-\s*(Internal|Other)\s*\(reserved=(\d+)\s*([KMG]B)?,\s*committed=(\d+)\s*([KMG]B)?\)""",
        RegexOption.IGNORE_CASE,
    )
    private val DIRECT_POOL_RE = Regex(
        """(?:Direct(?:BufferPool|Memory)|direct\s+buffer\s+pool|netty\.directMemory)[:\s]+used[=\s]+(\d+(?:\.\d+)?)\s*([KMGT]?i?B)(?:[,/\s]+(?:max|capacity)[=\s]+(\d+(?:\.\d+)?)\s*([KMGT]?i?B))?""",
        RegexOption.IGNORE_CASE,
    )

    private val COORD_TICKET_RE = Regex(
        """(?:world[=:\s]+['"]?([A-Za-z0-9_.:/-]+)['"]?\s+)?(?:chunk\s*)?[\[(]\s*(-?\d+)\s*,\s*(-?\d+)\s*[\])][^\r\n]*?\blevel[=:\s]+(\d+)[^\r\n]*?\btype[=:\s]+([A-Za-z0-9_:-]+)(?:[^\r\n]*?\b(?:owner|identifier|source|plugin)[=:\s]+['"]?([A-Za-z0-9_.-]+)['"]?)?""",
        RegexOption.IGNORE_CASE,
    )
    private val PLUGIN_TICKET_KV_RE = Regex(
        """(?:PluginChunkTickets|plugin[_-]tickets?|ChunkTickets)\s*(?:\(\s*world[=:\s]*['"]?([A-Za-z0-9_.:/-]+)['"]?\s*\))?\s*:\s*(.+)""",
        RegexOption.IGNORE_CASE,
    )
    private val PLUGIN_TICKET_PAIR_RE = Regex("""([A-Za-z0-9_.-]+)\s*[=:]\s*(\d+)""")
    private val PLUGIN_HOLDS_TICKETS_RE = Regex(
        """Plugin\s+['"]?([A-Za-z0-9_.-]+)['"]?\s+(?:holds|retained|leaked)\s+(\d+)\s+(?:persistent\s+)?(?:plugin\s+)?chunk\s+tickets?(?:\s+in\s+world\s+['"]?([A-Za-z0-9_.:/-]+)['"]?)?(?:[^\r\n]*?\blevel\s+(\d+))?""",
        RegexOption.IGNORE_CASE,
    )
    private val FORCELOAD_SUMMARY_RE = Regex(
        """(?:force[- ]?loaded\s+chunks|non-player\s+ticking\s+chunks|retained\s+plugin_ticket\s+chunks)\s*(?:in\s+['"]?([A-Za-z0-9_.:/-]+)['"]?)?\s*[=:]\s*(\d+)""",
        RegexOption.IGNORE_CASE,
    )

    private val JFR_EVENT_START_RE = Regex("""^\s*(jdk\.JavaMonitorEnter|jdk\.ThreadPark)\s*\{\s*$""")
    private val JFR_DURATION_RE = Regex("""^\s*duration\s*=\s*(\d+(?:[.,]\d+)?)\s*(ns|us|µs|ms|s)\b""")
    private val JFR_MONITOR_CLASS_RE = Regex("""^\s*(?:monitorClass|parkedClass)\s*=\s*([^\s(]+)""")
    private val JFR_THREAD_RE = Regex("""^\s*(eventThread|previousOwner)\s*=\s*"([^"]+)"""")
    private val JFR_FRAME_RE = Regex("""^\s*([A-Za-z0-9_$.]+)\.([A-Za-z0-9_$<>]+)\([^)]*\)""")

    private val COLLAPSED_LOCK_RE = Regex("""^([^;\r\n]+(?:;[^;\r\n]+){2,})\s+(\d+)\s*$""")
    private val SUMMARY_CONTENTION_RE = Regex(
        """Thread\s+"([^"]+)"\s+(?:blocked|parked|stalled)\s+on\s+(?:monitor|lock)\s+([A-Za-z0-9_$.]+)(?:\s+owned\s+by\s+"([^"]+)")?\s+for\s+(\d+(?:[.,]\d+)?)\s*(ms|s|us|ns)""",
        RegexOption.IGNORE_CASE,
    )

    const val DIRECT_MEMORY_WARN_BYTES: Long = 512L * 1024L * 1024L
    const val PLUGIN_TICKET_THRESHOLD: Int = 32
    const val PINNED_CHUNKS_THRESHOLD: Int = 128
    const val SINGLE_TICK_LOCK_WAIT_MS: Double = 25.0
    const val CUMULATIVE_TICK_LOCK_WAIT_MS: Double = 50.0
    const val CUMULATIVE_WORKER_LOCK_WAIT_MS: Double = 200.0

    fun analyzeDirectByteBufLeaks(
        text: String,
        plugins: PluginIndex = PluginIndex.EMPTY,
    ): DirectMemoryReport {
        val rawLines = text.lines()
        val incidents = mutableListOf<DirectMemoryLeakIncident>()
        var totalRecords = 0
        var maxCommittedBytes = 0L
        var maxCapBytes = 0L

        var i = 0
        while (i < rawLines.size) {
            val line = stripLogHeader(rawLines[i])
            val lineNo = i + 1

            if (NETTY_LEAK_BANNER_RE.containsMatchIn(line)) {
                totalRecords++
                val touchFrames = mutableListOf<StackFrame>()
                val allocFrames = mutableListOf<StackFrame>()
                val rawEvidence = mutableListOf(rawLines[i].trim())
                var firstHint: String? = null
                var touchCount = 0
                var inCreationSection = false

                var j = i + 1
                while (j < rawLines.size && j - i < 120) {
                    val subRaw = rawLines[j]
                    val sub = stripLogHeader(subRaw)
                    if (NETTY_LEAK_BANNER_RE.containsMatchIn(sub)) break
                    if (subRaw.trimStart().startsWith("[") && !subRaw.contains("ResourceLeakDetector") && !sub.trimStart().startsWith("#") && !sub.trimStart().startsWith("at ")) {
                        break
                    }
                    if (sub.contains("Created at:", ignoreCase = true)) {
                        inCreationSection = true
                        if (rawEvidence.size < 8) rawEvidence += sub.trim()
                        j++
                        continue
                    }
                    NETTY_TOUCH_INDEX_RE.find(sub)?.let { m ->
                        touchCount = max(touchCount, m.groupValues[1].toIntOrNull() ?: 0)
                        inCreationSection = false
                        val hintMatch = NETTY_HINT_RE.find(sub)
                        if (hintMatch != null && firstHint == null) {
                            firstHint = hintMatch.groupValues[1].trim()
                        }
                        if (rawEvidence.size < 8) rawEvidence += sub.trim()
                    } ?: run {
                        NETTY_HINT_RE.find(sub)?.let { hm ->
                            if (firstHint == null) firstHint = hm.groupValues[1].trim()
                        }
                    }

                    val trimmedFrame = sub.trim()
                    val parsedFrame = StackFrame.parse(if (trimmedFrame.startsWith("at ")) trimmedFrame else "at $trimmedFrame")
                    if (parsedFrame != null && (trimmedFrame.startsWith("at ") || trimmedFrame.contains(".java:") || trimmedFrame.contains(".kt:"))) {
                        if (inCreationSection) {
                            allocFrames += parsedFrame
                        } else {
                            touchFrames += parsedFrame
                        }
                        if (rawEvidence.size < 8 && !ServerPackages.isServerOwned(parsedFrame.className)) {
                            rawEvidence += trimmedFrame
                        }
                    }
                    j++
                }

                val touchBlameFrame = touchFrames.firstOrNull { !ServerPackages.isServerOwned(it.className) }
                val allocBlameFrame = allocFrames.firstOrNull { !ServerPackages.isServerOwned(it.className) }
                val chosenFrame = touchBlameFrame ?: allocBlameFrame ?: touchFrames.firstOrNull() ?: allocFrames.firstOrNull()
                val leakKind = if (touchBlameFrame != null || touchCount > 0) {
                    ByteBufLeakKind.UNRELEASED_LAST_TOUCH
                } else {
                    ByteBufLeakKind.UNRELEASED_ALLOCATION
                }
                val pluginName = resolvePluginBlame(chosenFrame?.className, firstHint, plugins)

                incidents += DirectMemoryLeakIncident(
                    line = lineNo,
                    kind = leakKind,
                    blamedPlugin = pluginName,
                    handlerHint = firstHint,
                    primaryFrame = chosenFrame?.let { "${it.className}.${it.method}" },
                    touchRecordCount = touchCount,
                    committedBytes = null,
                    maxBytes = null,
                    evidence = rawEvidence.take(6),
                )
                i = j
                continue
            }

            NMT_SECTION_RE.find(line)?.let { m ->
                val committed = parseSizeUnit(m.groupValues[4].toDoubleOrNull() ?: 0.0, m.groupValues[5].ifEmpty { "KB" })
                val reserved = parseSizeUnit(m.groupValues[2].toDoubleOrNull() ?: 0.0, m.groupValues[3].ifEmpty { "KB" })
                if (committed > maxCommittedBytes) maxCommittedBytes = committed
                if (reserved > maxCapBytes) maxCapBytes = reserved
                if (committed >= DIRECT_MEMORY_WARN_BYTES) {
                    incidents += DirectMemoryLeakIncident(
                        line = lineNo,
                        kind = ByteBufLeakKind.OFF_HEAP_DIRECT_POOL_PRESSURE,
                        blamedPlugin = null,
                        handlerHint = m.groupValues[1],
                        primaryFrame = null,
                        touchRecordCount = 0,
                        committedBytes = committed,
                        maxBytes = reserved,
                        evidence = listOf(rawLines[i].trim()),
                    )
                }
            }

            DIRECT_POOL_RE.find(line)?.let { m ->
                val used = parseSizeUnit(m.groupValues[1].toDoubleOrNull() ?: 0.0, m.groupValues[2])
                val cap = if (m.groupValues[3].isNotBlank()) {
                    parseSizeUnit(m.groupValues[3].toDoubleOrNull() ?: 0.0, m.groupValues[4])
                } else {
                    0L
                }
                if (used > maxCommittedBytes) maxCommittedBytes = used
                if (cap > maxCapBytes) maxCapBytes = cap
                val highRatio = cap > 0L && used.toDouble() / cap.toDouble() >= 0.80
                if (used >= DIRECT_MEMORY_WARN_BYTES || highRatio) {
                    incidents += DirectMemoryLeakIncident(
                        line = lineNo,
                        kind = ByteBufLeakKind.OFF_HEAP_DIRECT_POOL_PRESSURE,
                        blamedPlugin = null,
                        handlerHint = "DirectBufferPool",
                        primaryFrame = null,
                        touchRecordCount = 0,
                        committedBytes = used,
                        maxBytes = cap.takeIf { it > 0L },
                        evidence = listOf(rawLines[i].trim()),
                    )
                }
            }

            i++
        }

        return DirectMemoryReport(
            leakRecordCount = totalRecords,
            committedDirectBytes = maxCommittedBytes,
            maxDirectBytes = maxCapBytes,
            incidents = incidents,
        )
    }

    /**
     * Analyzes Paper 26.3 / Moonrise chunk ticket dumps and plugin ticket summaries, computing
     * exact deduplicated 2D Chebyshev propagation footprints when chunk coordinates are present.
     */
    fun analyzeChunkTicketLeaks(
        text: String,
        plugins: PluginIndex = PluginIndex.EMPTY,
    ): ChunkTicketReport {
        data class MutableGroup(
            var firstLine: Int,
            val owner: String,
            val ticketType: String,
            val world: String,
            var count: Int = 0,
            var minLevel: Int = 31,
            val pinnedCoords: MutableSet<ChunkCoord> = linkedSetOf(),
            val evidence: MutableList<String> = mutableListOf(),
        )

        val groups = linkedMapOf<String, MutableGroup>()
        val globalPinnedCoords = linkedSetOf<ChunkCoord>()
        var extraSummaryPinnedChunks = 0

        text.lines().forEachIndexed { idx, raw ->
            val lineNo = idx + 1
            val clean = stripLogHeader(raw).trim()
            if (clean.isEmpty()) return@forEachIndexed

            COORD_TICKET_RE.find(clean)?.let { m ->
                val world = m.groupValues[1].ifBlank { "world" }
                val cx = m.groupValues[2].toIntOrNull() ?: return@let
                val cz = m.groupValues[3].toIntOrNull() ?: return@let
                val level = m.groupValues[4].toIntOrNull() ?: 31
                val rawType = m.groupValues[5].lowercase(Locale.ROOT)
                if (rawType == "player" || rawType == "spawn" || rawType == "dragon") return@let
                val owner = m.groupValues[6].ifBlank { rawType }
                val key = "$world::$rawType::$owner"
                val group = groups.getOrPut(key) {
                    MutableGroup(lineNo, owner, rawType, world, minLevel = level)
                }
                group.count++
                if (level < group.minLevel) group.minLevel = level
                if (group.evidence.size < 5) group.evidence += raw.trim()

                val radius = (33 - level).coerceIn(0, 6)
                for (dx in -radius..radius) {
                    for (dz in -radius..radius) {
                        val coord = ChunkCoord(world, cx + dx, cz + dz)
                        group.pinnedCoords += coord
                        globalPinnedCoords += coord
                    }
                }
                return@forEachIndexed
            }

            PLUGIN_HOLDS_TICKETS_RE.find(clean)?.let { m ->
                val owner = m.groupValues[1]
                val count = m.groupValues[2].toIntOrNull() ?: 0
                val world = m.groupValues[3].ifBlank { "world" }
                val level = m.groupValues[4].toIntOrNull() ?: 31
                if (count > 0) {
                    val key = "$world::plugin_ticket::$owner"
                    val group = groups.getOrPut(key) {
                        MutableGroup(lineNo, owner, "plugin_ticket", world, minLevel = level)
                    }
                    group.count += count
                    if (level < group.minLevel) group.minLevel = level
                    if (group.evidence.size < 5) group.evidence += raw.trim()
                }
                return@forEachIndexed
            }

            PLUGIN_TICKET_KV_RE.find(clean)?.let { m ->
                val world = m.groupValues[1].ifBlank { "world" }
                val pairs = PLUGIN_TICKET_PAIR_RE.findAll(m.groupValues[2]).toList()
                for (pair in pairs) {
                    val owner = pair.groupValues[1]
                    val count = pair.groupValues[2].toIntOrNull() ?: 0
                    if (count <= 0) continue
                    val key = "$world::plugin_ticket::$owner"
                    val group = groups.getOrPut(key) {
                        MutableGroup(lineNo, owner, "plugin_ticket", world, minLevel = 31)
                    }
                    group.count += count
                    if (group.evidence.size < 5) group.evidence += raw.trim()
                }
                return@forEachIndexed
            }

            FORCELOAD_SUMMARY_RE.find(clean)?.let { m ->
                val world = m.groupValues[1].ifBlank { "world" }
                val count = m.groupValues[2].toIntOrNull() ?: 0
                if (count > 0) {
                    val key = "$world::forced::forceload"
                    val group = groups.getOrPut(key) {
                        MutableGroup(lineNo, "forceload", "forced", world, minLevel = 31)
                    }
                    group.count += count
                    if (group.evidence.size < 5) group.evidence += raw.trim()
                }
            }
        }

        val builtGroups = groups.values.map { g ->
            val radius = (33 - g.minLevel).coerceIn(0, 6)
            val perTicketSpan = (2 * radius + 1) * (2 * radius + 1)
            val estimatedPinned = if (g.pinnedCoords.isNotEmpty()) {
                g.pinnedCoords.size
            } else if (g.ticketType == "forced" && g.owner == "forceload") {
                g.count
            } else {
                // Conservative 40% non-overlapping factor when exact coordinates are omitted in summary lines
                max(g.count, (g.count * perTicketSpan * 4) / 10)
            }
            if (g.pinnedCoords.isEmpty()) extraSummaryPinnedChunks += estimatedPinned
            val resolvedPlugin = resolvePluginBlame(null, g.owner, plugins)
                ?: g.owner.takeIf { it != "forceload" && it != "plugin_ticket" && it != "portal" && it != "ender_pearl" && it != "unknown" }

            ChunkTicketLeakGroup(
                line = g.firstLine,
                owner = g.owner,
                ticketType = g.ticketType,
                world = g.world,
                ticketCount = g.count,
                minTicketLevel = g.minLevel,
                effectivePinnedChunks = estimatedPinned,
                blamedPlugin = resolvedPlugin,
                evidence = g.evidence,
            )
        }.sortedByDescending { it.effectivePinnedChunks }

        val flagged = builtGroups.filter {
            it.ticketCount >= PLUGIN_TICKET_THRESHOLD || it.effectivePinnedChunks >= PINNED_CHUNKS_THRESHOLD
        }

        return ChunkTicketReport(
            totalTickets = builtGroups.sumOf { it.ticketCount },
            totalEffectivePinnedChunks = globalPinnedCoords.size + extraSummaryPinnedChunks,
            groups = builtGroups,
            flaggedLeaks = flagged,
        )
    }

    /**
     * Parses JFR `jdk.JavaMonitorEnter` / `jdk.ThreadPark` print blocks, `async-profiler -e lock`
     * collapsed profiles, and structured lock-contention lines into aggregated contention hotspots.
     */
    fun analyzeLockContention(
        text: String,
        plugins: PluginIndex = PluginIndex.EMPTY,
    ): LockContentionReport {
        data class MutableContention(
            val firstLine: Int,
            val waiterThread: String,
            var ownerThread: String?,
            val monitorClass: String,
            var count: Int = 0,
            var totalMs: Double = 0.0,
            var maxMs: Double = 0.0,
            var blamedPlugin: String? = null,
            val evidence: MutableList<String> = mutableListOf(),
        )

        val buckets = linkedMapOf<String, MutableContention>()
        val lines = text.lines()

        fun recordEvent(
            line: Int,
            waiter: String,
            owner: String?,
            monitor: String,
            durationMs: Double,
            blame: String?,
            sampleEvidence: List<String>,
        ) {
            if (durationMs <= 0.0) return
            if (isBenignIdlePark(monitor, sampleEvidence)) return
            val key = "$waiter::$monitor::${owner ?: ""}"
            val bucket = buckets.getOrPut(key) {
                MutableContention(line, waiter, owner, monitor)
            }
            bucket.count++
            bucket.totalMs += durationMs
            if (durationMs > bucket.maxMs) bucket.maxMs = durationMs
            if (bucket.ownerThread == null && owner != null) bucket.ownerThread = owner
            if (bucket.blamedPlugin == null && blame != null) bucket.blamedPlugin = blame
            for (ev in sampleEvidence) {
                if (bucket.evidence.size < 6 && ev !in bucket.evidence) bucket.evidence += ev
            }
        }

        var i = 0
        while (i < lines.size) {
            val raw = lines[i]
            val clean = stripLogHeader(raw)
            val lineNo = i + 1

            val jfrStart = JFR_EVENT_START_RE.find(clean)
            if (jfrStart != null) {
                var durationMs = 0.0
                var monitorClass = jfrStart.groupValues[1]
                var waiter = "unknown"
                var owner: String? = null
                val frames = mutableListOf<StackFrame>()
                val rawFrames = mutableListOf<String>()
                var depth = 1
                var j = i + 1
                while (j < lines.size && depth > 0 && j - i < 160) {
                    val bodyLine = stripLogHeader(lines[j])
                    depth += bodyLine.count { it == '{' }
                    depth -= bodyLine.count { it == '}' }
                    JFR_DURATION_RE.find(bodyLine)?.let { dm ->
                        durationMs = toMillis(dm.groupValues[1].replace(',', '.').toDoubleOrNull() ?: 0.0, dm.groupValues[2])
                    }
                    JFR_MONITOR_CLASS_RE.find(bodyLine)?.let { mm ->
                        monitorClass = mm.groupValues[1].replace('/', '.')
                    }
                    JFR_THREAD_RE.find(bodyLine)?.let { tm ->
                        if (tm.groupValues[1] == "eventThread") waiter = tm.groupValues[2]
                        else if (tm.groupValues[1] == "previousOwner") owner = tm.groupValues[2]
                    }
                    JFR_FRAME_RE.find(bodyLine)?.let { fm ->
                        val cls = fm.groupValues[1].substringBefore("\$\$Lambda")
                        val mth = fm.groupValues[2]
                        val sf = StackFrame.parse("at $cls.$mth(SourceFile:1)")
                        if (sf != null) {
                            frames += sf
                            if (rawFrames.size < 4) rawFrames += "${cls}.${mth}()"
                        }
                    }
                    j++
                }

                val foreign = ServerPackages.firstForeignFrame(frames)
                val blame = resolvePluginBlame(foreign?.className ?: monitorClass, null, plugins)
                    ?: foreign?.className
                    ?: monitorClass.takeIf { !ServerPackages.isServerOwned(it) }

                val evList = buildList {
                    add("${jfrStart.groupValues[1]} on $monitorClass (${String.format(Locale.ROOT, "%.2f", durationMs)} ms, thread=\"$waiter\"${owner?.let { ", owner=\"$it\"" } ?: ""})")
                    addAll(rawFrames)
                }
                recordEvent(lineNo, waiter, owner, monitorClass, durationMs, blame, evList)
                i = j
                continue
            }

            SUMMARY_CONTENTION_RE.find(clean)?.let { sm ->
                val waiter = sm.groupValues[1]
                val monitor = sm.groupValues[2]
                val owner = sm.groupValues[3].takeIf { it.isNotBlank() }
                val durMs = toMillis(sm.groupValues[4].replace(',', '.').toDoubleOrNull() ?: 0.0, sm.groupValues[5])
                val blame = resolvePluginBlame(monitor, null, plugins)
                    ?: monitor.takeIf { !ServerPackages.isServerOwned(it) }
                recordEvent(lineNo, waiter, owner, monitor, durMs, blame, listOf(raw.trim()))
                i++
                continue
            }

            COLLAPSED_LOCK_RE.find(clean)?.let { cm ->
                val stack = cm.groupValues[1]
                val rawWeight = cm.groupValues[2].toLongOrNull() ?: 0L
                val parts = stack.split(';')
                val leaf = parts.last()
                val looksLikeLockProfile = leaf.endsWith("_[i]") || leaf.endsWith("_[j]") ||
                    stack.contains("MonitorEnter", ignoreCase = true) ||
                    stack.contains("ReentrantLock", ignoreCase = true) ||
                    stack.contains("Unsafe.park", ignoreCase = true) ||
                    stack.contains("LockSupport.park", ignoreCase = true)
                if (rawWeight > 0L && looksLikeLockProfile) {
                    val waiter = parts.first().trim()
                    val monitor = leaf.removeSuffix("_[i]").removeSuffix("_[j]").replace('/', '.')
                    // async-profiler -e lock records total lock wait nanoseconds (weights >= 1e5) or sample counts
                    val durMs = if (rawWeight >= 100_000L) rawWeight.toDouble() / 1_000_000.0 else rawWeight.toDouble() * 10.0
                    var foreignClass: String? = null
                    for (idxPart in parts.size - 1 downTo 1) {
                        val candidate = parts[idxPart]
                            .removeSuffix("_[i]")
                            .removeSuffix("_[j]")
                            .replace('/', '.')
                            .substringBefore("\$\$Lambda")
                        val lastDot = candidate.lastIndexOf('.')
                        val cls = if (lastDot > 0 && candidate[lastDot + 1].isLowerCase()) candidate.substring(0, lastDot) else candidate
                        if (cls.contains('.') && !ServerPackages.isServerOwned(cls)) {
                            foreignClass = cls
                            break
                        }
                    }
                    val blame = resolvePluginBlame(foreignClass ?: monitor, null, plugins) ?: foreignClass
                    recordEvent(lineNo, waiter, null, monitor, durMs, blame, listOf(raw.trim()))
                }
            }

            i++
        }

        val hotspots = buckets.values.map { b ->
            val inversion = isTickThread(b.waiterThread) && b.ownerThread != null && isAsyncOrIoThread(b.ownerThread!!)
            LockContentionHotspot(
                line = b.firstLine,
                waiterThread = b.waiterThread,
                ownerThread = b.ownerThread,
                monitorClass = b.monitorClass,
                eventCount = b.count,
                totalBlockedMs = b.totalMs,
                maxWaitMs = b.maxMs,
                lostTicks = b.totalMs / 50.0,
                lockInversion = inversion,
                blamedPlugin = b.blamedPlugin,
                evidence = b.evidence,
            )
        }.sortedByDescending { it.totalBlockedMs }

        val flagged = hotspots.filter { h ->
            if (isTickThread(h.waiterThread)) {
                h.maxWaitMs >= SINGLE_TICK_LOCK_WAIT_MS || h.totalBlockedMs >= CUMULATIVE_TICK_LOCK_WAIT_MS || h.lockInversion
            } else {
                h.totalBlockedMs >= CUMULATIVE_WORKER_LOCK_WAIT_MS
            }
        }

        return LockContentionReport(
            totalEvents = hotspots.sumOf { it.eventCount },
            totalBlockedMs = hotspots.sumOf { it.totalBlockedMs },
            maxSingleWaitMs = hotspots.maxOfOrNull { it.maxWaitMs } ?: 0.0,
            lockInversionCount = hotspots.count { it.lockInversion },
            hotspots = hotspots,
            flaggedHotspots = flagged,
        )
    }

    fun diagnose(
        source: LogSource,
        plugins: PluginIndex = PluginIndex.EMPTY,
    ): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()
        val lines = mutableListOf<String>()
        source.forEachLine { lines += it.text }
        val fullText = lines.joinToString("\n")
        val locationName = source.path.fileName.toString()

        val directReport = analyzeDirectByteBufLeaks(fullText, plugins)
        facts["direct_memory.leak_records"] = directReport.leakRecordCount.toString()
        if (directReport.committedDirectBytes > 0L) {
            facts["direct_memory.committed_bytes"] = JvmGcAndHeapAnalyzer.formatBytes(directReport.committedDirectBytes)
        }
        if (directReport.maxDirectBytes > 0L) {
            facts["direct_memory.max_bytes"] = JvmGcAndHeapAnalyzer.formatBytes(directReport.maxDirectBytes)
        }

        for (inc in directReport.incidents) {
            val detail = formatDirectLeakDetail(inc)
            sink.add(
                rule = LogRules.NETTY_DIRECT_BYTEBUF_LEAK,
                location = "$locationName:${inc.line}",
                detail = detail,
                evidence = inc.evidence,
            )
        }

        val ticketReport = analyzeChunkTicketLeaks(fullText, plugins)
        facts["chunk_tickets.total_tickets"] = ticketReport.totalTickets.toString()
        facts["chunk_tickets.pinned_chunks"] = ticketReport.totalEffectivePinnedChunks.toString()

        for (leak in ticketReport.flaggedLeaks) {
            sink.add(
                rule = LogRules.PAPER_CHUNK_TICKET_LEAK,
                location = "$locationName:${leak.line}",
                detail = formatTicketLeakDetail(leak),
                evidence = leak.evidence,
            )
        }

        val contentionReport = analyzeLockContention(fullText, plugins)
        facts["contention.total_events"] = contentionReport.totalEvents.toString()
        facts["contention.total_blocked_ms"] = String.format(Locale.ROOT, "%.2f ms", contentionReport.totalBlockedMs)
        facts["contention.lost_ticks"] = String.format(Locale.ROOT, "%.1f", contentionReport.totalBlockedMs / 50.0)
        facts["contention.lock_inversions"] = contentionReport.lockInversionCount.toString()

        for (hotspot in contentionReport.flaggedHotspots) {
            sink.add(
                rule = LogRules.JFR_ASYNC_PROFILER_LOCK_CONTENTION,
                location = "$locationName:${hotspot.line}",
                detail = formatContentionDetail(hotspot),
                evidence = hotspot.evidence,
            )
        }

        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = locationName,
            subjectKind = "memory-and-contention",
            findings = sink.findings(),
            facts = facts,
        )
    }

    internal fun formatDirectLeakDetail(inc: DirectMemoryLeakIncident): String = when (inc.kind) {
        ByteBufLeakKind.OFF_HEAP_DIRECT_POOL_PRESSURE -> {
            val usedText = inc.committedBytes?.let { JvmGcAndHeapAnalyzer.formatBytes(it) } ?: "high usage"
            val capText = inc.maxBytes?.let { " of ${JvmGcAndHeapAnalyzer.formatBytes(it)} cap" } ?: ""
            "Native off-heap memory pool (${inc.handlerHint ?: "DirectBufferPool"}) committed $usedText$capText outside -Xmx."
        }
        ByteBufLeakKind.UNRELEASED_LAST_TOUCH -> buildString {
            append("Netty ResourceLeakDetector caught unreleased direct ByteBuf after ${max(1, inc.touchRecordCount)} touch record(s)")
            inc.handlerHint?.let { append(" (handler hint: '$it')") }
            inc.primaryFrame?.let { append(" in $it") }
            inc.blamedPlugin?.let { append(", attributed to $it") }
            append('.')
        }
        ByteBufLeakKind.UNRELEASED_ALLOCATION -> buildString {
            append("Netty ResourceLeakDetector caught unforwarded direct ByteBuf allocation")
            inc.primaryFrame?.let { append(" created at $it") }
            inc.blamedPlugin?.let { append(", attributed to $it") }
            append('.')
        }
    }

    internal fun formatTicketLeakDetail(leak: ChunkTicketLeakGroup): String = buildString {
        append("World '${leak.world}' retains ${leak.ticketCount} '${leak.ticketType}' chunk ticket(s) ")
        append("(min level ${leak.minTicketLevel}, pinning ~${leak.effectivePinnedChunks} chunk(s)) ")
        append("for owner '${leak.owner}'")
        if (leak.blamedPlugin != null && leak.blamedPlugin != leak.owner) {
            append(" (plugin ${leak.blamedPlugin})")
        }
        append('.')
    }

    internal fun formatContentionDetail(h: LockContentionHotspot): String = buildString {
        if (h.lockInversion) {
            append("Tick-to-async lock inversion: ")
        }
        append("Thread \"${h.waiterThread}\" blocked for ${String.format(Locale.ROOT, "%.2f", h.totalBlockedMs)} ms ")
        append("(${String.format(Locale.ROOT, "%.1f", h.lostTicks)} tick budgets across ${h.eventCount} event(s), max ${String.format(Locale.ROOT, "%.2f", h.maxWaitMs)} ms) ")
        append("on ${h.monitorClass}")
        h.ownerThread?.let { append(" held by \"$it\"") }
        h.blamedPlugin?.let { append(" (attributed to $it)") }
        append('.')
    }

    private fun isTickThread(name: String): Boolean {
        val lower = name.lowercase(Locale.ROOT)
        return lower.contains("server thread") ||
            lower.contains("primary thread") ||
            lower.contains("tickregionthread") ||
            lower.contains("region scheduler thread") ||
            lower.contains("global region scheduler")
    }

    private fun isAsyncOrIoThread(name: String): Boolean {
        val lower = name.lowercase(Locale.ROOT)
        return lower.contains("async") ||
            lower.contains("craft scheduler") ||
            lower.contains("netty") ||
            lower.contains("forkjoinpool") ||
            lower.contains("worker") ||
            lower.contains("hikari") ||
            lower.contains("pool-")
    }

    private fun isBenignIdlePark(monitorClass: String, evidence: List<String>): Boolean {
        val joined = evidence.joinToString(" ")
        return joined.contains("MinecraftServer.waitUntilNextTick") ||
            joined.contains("ConcurrentLinkedQueue") ||
            (monitorClass.contains("ForkJoinPool") && !joined.contains("CompletableFuture.join"))
    }

    private fun resolvePluginBlame(className: String?, hintOrOwner: String?, plugins: PluginIndex): String? {
        if (className != null) {
            plugins.owningPlugin(className)?.let { return it.descriptor?.name ?: it.fileName }
        }
        if (hintOrOwner != null) {
            plugins.byLoggerLabel(hintOrOwner)?.let { return it.descriptor?.name ?: it.fileName }
            plugins.jars.firstOrNull {
                it.descriptor?.name?.equals(hintOrOwner, ignoreCase = true) == true
            }?.let { return it.descriptor?.name ?: it.fileName }
        }
        if (className != null && !ServerPackages.isServerOwned(className)) {
            return className
        }
        return null
    }

    private fun stripLogHeader(raw: String): String =
        raw.replace(Regex("""^\[[^\]]+\]\s*(?:\[[^\]]+\]:\s*)?"""), "")

    private fun parseSizeUnit(value: Double, rawUnit: String): Long {
        val u = rawUnit.trim().uppercase(Locale.ROOT)
        val mult = when {
            u.startsWith("T") -> 1024.0 * 1024.0 * 1024.0 * 1024.0
            u.startsWith("G") -> 1024.0 * 1024.0 * 1024.0
            u.startsWith("M") -> 1024.0 * 1024.0
            u.startsWith("K") -> 1024.0
            else -> 1.0
        }
        return (value * mult).toLong()
    }

    private fun toMillis(value: Double, unit: String): Double = when (unit.lowercase(Locale.ROOT)) {
        "s" -> value * 1000.0
        "ms" -> value
        "us", "µs" -> value / 1000.0
        "ns" -> value / 1_000_000.0
        else -> value
    }
}
