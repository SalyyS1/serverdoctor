package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.core.Severity
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.util.Locale
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

/**
 * Offline diagnostic analyzer and cross-signal root-cause timeline correlator for ServerDoctor v1.0.0:
 * - L042: Project Loom virtual thread carrier pinning (-Djdk.tracePinnedThreads and JFR jdk.VirtualThreadPinned)
 * - L043: HikariCP connection pool exhaustion and SQLite WAL lock / checkpoint starvation
 * - L044: Host Linux cgroup CPU CFS throttling, PSI pressure stalls, THP [always], and swap pressure
 * - L045: Temporal sliding-window (delta-t <= 5000 ms) causal DAG linking upstream root causes to
 *         downstream tick lag, Netty keepalive drops, and Paper/Folia watchdog stalls
 */
object IncidentTimelineCorrelator {

    enum class PinningMechanism {
        SYNCHRONIZED_MONITOR,
        NATIVE_OR_FOREIGN_UPCALL,
    }

    data class LoomPinningIncident(
        val line: Int,
        val carrierThread: String,
        val mechanism: PinningMechanism,
        val monitorFrame: String?,
        val blockingOperation: String,
        val durationMs: Double?,
        val monitorCount: Int,
        val eventCount: Int,
        val distinctCarriersPinned: Int,
        val blamedPlugin: String?,
        val evidence: List<String>,
    )

    data class LoomPinningReport(
        val totalPinnedEvents: Int,
        val distinctCarriersPinned: Int,
        val maxDurationMs: Double,
        val incidents: List<LoomPinningIncident>,
    )

    enum class DbStarvationKind {
        HIKARICP_POOL_EXHAUSTION,
        SQLITE_WAL_OR_BUSY_LOCK,
    }

    data class DbStarvationIncident(
        val line: Int,
        val kind: DbStarvationKind,
        val poolOrDbName: String,
        val activeConnections: Int?,
        val totalConnections: Int?,
        val waitingThreads: Int?,
        val timeoutMs: Double?,
        val walFrames: Int?,
        val onTickThread: Boolean,
        val eventCount: Int,
        val blamedPlugin: String?,
        val evidence: List<String>,
    )

    data class DbStarvationReport(
        val incidents: List<DbStarvationIncident>,
        val tickThreadStalls: Int,
    )

    enum class HostPressureKind {
        CGROUP_CPU_THROTTLING,
        LINUX_PSI_STALL,
        THP_COMPACTION_HAZARD,
        SWAP_OR_CGROUP_OOM,
    }

    data class HostPressureIncident(
        val line: Int,
        val kind: HostPressureKind,
        val metricSummary: String,
        val throttleRatio: Double?,
        val swapMegabytes: Long?,
        val oomKills: Long?,
        val critical: Boolean,
        val evidence: List<String>,
    )

    enum class SignalStage(val rank: Int, val label: String) {
        HOST_PRESSURE(1, "Host cgroup/OS stall"),
        GC_PAUSE(2, "JVM GC pause/stall"),
        PERSISTENCE_OR_LOOM(3, "DB pool or Loom carrier starvation"),
        LOCK_CONTENTION(4, "Tick/async monitor lock contention"),
        TICK_OR_NETTY_SYMPTOM(5, "Slow tick or Netty keepalive drop"),
        WATCHDOG_OR_REGION_CRASH(6, "Watchdog or Folia region stall"),
    }

    enum class ClockDomain {
        WALL_OF_DAY_MS,
        UPTIME_MS,
    }

    data class TimelineSignal(
        val sourceName: String,
        val line: Int,
        val clockDomain: ClockDomain,
        val timestampMs: Long,
        val stage: SignalStage,
        val ruleHint: String,
        val summary: String,
        val blamedPlugin: String?,
        val rawLine: String,
    )

    data class CausalCascade(
        val rootSignal: TimelineSignal,
        val intermediateSignals: List<TimelineSignal>,
        val symptomSignal: TimelineSignal,
        val leadTimeMs: Long,
        val confidence: Double,
        val blamedPlugin: String?,
        val chainSummary: String,
        val evidence: List<String>,
    )

    private data class ParsedLoomFrame(
        val raw: String,
        val className: String,
        val method: String,
        val monitors: Int,
        val nativeMethod: Boolean,
    )

    private const val CAUSAL_WINDOW_MS = 5_000L

    private val TRACE_PINNED_HEADER_RE = Regex(
        """Thread\[#?\d*,\s*([^,\]]*ForkJoinPool[^,\]]*|[^,\]]*Carrier[^,\]]*|VirtualThread[^,\]]*)""",
        RegexOption.IGNORE_CASE,
    )
    private val LOOM_FRAME_RE = Regex(
        """^\s*(?:at\s+)?(?:[\w.$@-]+/+)*([\w$.]+)\.([\w$<>]+)\(([^)]*)\)(?:\s*<==\s*monitors:(\d+))?""",
    )
    private val JFR_PINNED_OPEN_RE = Regex("""^\s*jdk\.VirtualThreadPinned\s*\{\s*$""")
    private val JFR_DURATION_RE = Regex("""duration\s*=\s*(\d+(?:\.\d+)?)\s*(ns|us|µs|ms|s)\b""", RegexOption.IGNORE_CASE)
    private val JFR_CARRIER_RE = Regex("""(?:carrierThread|eventThread)\s*=\s*"([^"]+)"""")
    private val JFR_PINNED_REASON_RE = Regex("""(?:pinnedReason|blockingOperation)\s*=\s*"?([^"\r\n]+)"?""")

    private val HIKARI_STATS_RE = Regex(
        """([A-Za-z0-9_.-]*Pool[A-Za-z0-9_.-]*|HikariPool-\d+)\s*-\s*(?:PoolStats|Timeout failure[^\r\n]*stats)\s*\(total=(\d+),\s*active=(\d+),\s*idle=(\d+),\s*waiting=(\d+)\)""",
        RegexOption.IGNORE_CASE,
    )
    private val HIKARI_TIMEOUT_RE = Regex(
        """(?:SQLTransientConnectionException:\s*)?([A-Za-z0-9_.-]+)\s*-\s*Connection is not available,\s*request timed out after\s*(\d+(?:\.\d+)?)ms""",
        RegexOption.IGNORE_CASE,
    )
    private val SQLITE_BUSY_RE = Regex(
        """(?:\[SQLITE_BUSY(?:_SNAPSHOT|_RECOVERY)?\]|SQLiteException:.*database is locked|database file is locked)""",
        RegexOption.IGNORE_CASE,
    )
    private val SQLITE_WAL_BACKLOG_RE = Regex(
        """(?:wal_checkpoint|db-wal|WAL\s+frames?)[^\r\n]*?\b(\d{4,})\s*(?:frames?|pages?)""",
        RegexOption.IGNORE_CASE,
    )

    private val NR_PERIODS_RE = Regex("""\bnr_periods[\s:=]+(\d+)""")
    private val NR_THROTTLED_RE = Regex("""\bnr_throttled[\s:=]+(\d+)""")
    private val THROTTLED_USEC_RE = Regex("""\bthrottled_(?:usec|time)[\s:=]+(\d+)""")
    private val PSI_STALL_RE = Regex(
        """(?:cpu|memory|io)?\s*(?:pressure[:/\s]+)?\b(some|full)\s+avg10=(\d+(?:\.\d+)?)\s+avg60=(\d+(?:\.\d+)?)""",
        RegexOption.IGNORE_CASE,
    )
    private val THP_ALWAYS_RE = Regex("""\[always\]\s+madvise\s+never|khugepaged.*(?:compaction|stall)""", RegexOption.IGNORE_CASE)
    private val VMSWAP_RE = Regex("""VmSwap:\s*(\d+)\s*kB""", RegexOption.IGNORE_CASE)
    private val FREE_SWAP_USED_RE = Regex("""Swap:\s*\d+\s+(\d+)\s+\d+""", RegexOption.IGNORE_CASE)
    private val CGROUP_OOM_RE = Regex("""\boom_kill[\s:=]+(\d+)""")

    private val WALL_CLOCK_RE = Regex("""(?:T|\b|\[)(\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,3}))?(?:\]|\b|Z)""")
    private val UPTIME_SEC_RE = Regex("""\[\s*(\d+(?:\.\d+)?)s\s*\]""")
    private val THREAD_HEADER_RE = Regex("""\[([^\]]+?)/(?:INFO|WARN|ERROR|FATAL)\]""")

    fun analyzeLoomPinning(text: String, plugins: PluginIndex = PluginIndex.EMPTY): LoomPinningReport {
        val lines = text.lines()
        data class Bucket(
            val firstLine: Int,
            val carrierSample: String,
            val mechanism: PinningMechanism,
            val monitorFrame: String?,
            val blockingOp: String,
            var maxMs: Double?,
            var maxMonitors: Int,
            var count: Int,
            val carriers: MutableSet<String>,
            var blamedPlugin: String?,
            val evidence: MutableList<String>,
        )

        val buckets = LinkedHashMap<String, Bucket>()
        val allCarriers = linkedSetOf<String>()

        var i = 0
        while (i < lines.size) {
            val raw = lines[i]
            val lineNo = i + 1
            val clean = stripLogHeader(raw)

            // 1. JFR jdk.VirtualThreadPinned event block
            if (JFR_PINNED_OPEN_RE.matches(clean)) {
                var j = i + 1
                var durationMs = 0.0
                var carrier = "ForkJoinPool-carrier"
                var reason: String? = null
                val parsedFrames = mutableListOf<ParsedLoomFrame>()
                while (j < lines.size && j < i + 50) {
                    val blockLine = stripLogHeader(lines[j])
                    if (blockLine.trim() == "}") {
                        j++
                        break
                    }
                    JFR_DURATION_RE.find(blockLine)?.let { dm ->
                        durationMs = toMillis(dm.groupValues[1].toDoubleOrNull() ?: 0.0, dm.groupValues[2])
                    }
                    JFR_CARRIER_RE.find(blockLine)?.let { carrier = it.groupValues[1] }
                    JFR_PINNED_REASON_RE.find(blockLine)?.let { reason = it.groupValues[1].trim() }
                    parseLoomFrame(blockLine)?.let { parsedFrames += it }
                    j++
                }

                val hasNative = parsedFrames.any { it.nativeMethod } ||
                    (reason?.contains("native", ignoreCase = true) == true)
                val mechanism = if (hasNative) PinningMechanism.NATIVE_OR_FOREIGN_UPCALL else PinningMechanism.SYNCHRONIZED_MONITOR
                val blockingOp = classifyBlockingSink(parsedFrames, reason)
                val foreign = parsedFrames.firstOrNull { !isInfraOrServerClass(it.className) }
                val monitorHolder = parsedFrames.firstOrNull { it.monitors > 0 } ?: foreign ?: parsedFrames.firstOrNull()
                val blame = resolveBlame(foreign?.className, null, plugins)

                if (durationMs >= 10.0 || parsedFrames.isNotEmpty()) {
                    allCarriers += carrier
                    val key = "${mechanism.name}@${monitorHolder?.let { "${it.className}.${it.method}" } ?: blockingOp}"
                    val ev = buildList {
                        add("jdk.VirtualThreadPinned (${String.format(Locale.ROOT, "%.1f", durationMs)} ms on $carrier, $blockingOp)")
                        parsedFrames.take(3).forEach { add(it.raw) }
                    }
                    val existing = buckets[key]
                    if (existing == null) {
                        buckets[key] = Bucket(
                            firstLine = lineNo,
                            carrierSample = carrier,
                            mechanism = mechanism,
                            monitorFrame = monitorHolder?.let { "${it.className}.${it.method}" },
                            blockingOp = blockingOp,
                            maxMs = durationMs.takeIf { it > 0.0 },
                            maxMonitors = max(1, parsedFrames.maxOfOrNull { it.monitors } ?: 1),
                            count = 1,
                            carriers = linkedSetOf(carrier),
                            blamedPlugin = blame,
                            evidence = ev.toMutableList(),
                        )
                    } else {
                        existing.count++
                        existing.carriers += carrier
                        if (durationMs > (existing.maxMs ?: 0.0)) existing.maxMs = durationMs
                        if (existing.blamedPlugin == null && blame != null) existing.blamedPlugin = blame
                    }
                }
                i = j
                continue
            }

            // 2. -Djdk.tracePinnedThreads=full|short stack dump
            val headerMatch = TRACE_PINNED_HEADER_RE.find(clean)
            val inlineMonitorFrame = if (headerMatch == null && clean.contains("<== monitors:")) parseLoomFrame(clean) else null
            if (headerMatch != null || inlineMonitorFrame != null) {
                val carrier = headerMatch?.groupValues?.get(1)?.trim() ?: "ForkJoinPool-carrier"
                val parsedFrames = mutableListOf<ParsedLoomFrame>()
                if (inlineMonitorFrame != null) parsedFrames += inlineMonitorFrame
                var j = i + 1
                while (j < lines.size && j < i + 40) {
                    val nextClean = stripLogHeader(lines[j])
                    val pf = parseLoomFrame(nextClean)
                    if (pf != null) {
                        parsedFrames += pf
                        j++
                    } else if (nextClean.isBlank()) {
                        break
                    } else {
                        break
                    }
                }

                val monitorFrames = parsedFrames.filter { it.monitors > 0 }
                val hasNative = parsedFrames.any { it.nativeMethod }
                if (monitorFrames.isNotEmpty() || (headerMatch != null && hasNative)) {
                    allCarriers += carrier
                    val mechanism = if (monitorFrames.isEmpty() && hasNative) {
                        PinningMechanism.NATIVE_OR_FOREIGN_UPCALL
                    } else {
                        PinningMechanism.SYNCHRONIZED_MONITOR
                    }
                    val monitorHolder = monitorFrames.firstOrNull() ?: parsedFrames.firstOrNull { it.nativeMethod }
                    val foreign = parsedFrames.firstOrNull { !isInfraOrServerClass(it.className) }
                    val blame = resolveBlame(foreign?.className, null, plugins)
                    val blockingOp = classifyBlockingSink(parsedFrames, null)
                    val totalMonitors = monitorFrames.sumOf { it.monitors }.coerceAtLeast(1)
                    val key = "${mechanism.name}@${monitorHolder?.let { "${it.className}.${it.method}" } ?: blockingOp}"
                    val ev = buildList {
                        add(raw.trim())
                        parsedFrames.take(4).forEach { add(it.raw) }
                    }.distinct()
                    val existing = buckets[key]
                    if (existing == null) {
                        buckets[key] = Bucket(
                            firstLine = lineNo,
                            carrierSample = carrier,
                            mechanism = mechanism,
                            monitorFrame = monitorHolder?.let { "${it.className}.${it.method}" },
                            blockingOp = blockingOp,
                            maxMs = null,
                            maxMonitors = totalMonitors,
                            count = 1,
                            carriers = linkedSetOf(carrier),
                            blamedPlugin = blame,
                            evidence = ev.toMutableList(),
                        )
                    } else {
                        existing.count++
                        existing.carriers += carrier
                        existing.maxMonitors = max(existing.maxMonitors, totalMonitors)
                        if (existing.blamedPlugin == null && blame != null) existing.blamedPlugin = blame
                    }
                    i = j
                    continue
                }
            }

            i++
        }

        val incidents = buckets.values.map { b ->
            LoomPinningIncident(
                line = b.firstLine,
                carrierThread = b.carrierSample,
                mechanism = b.mechanism,
                monitorFrame = b.monitorFrame,
                blockingOperation = b.blockingOp,
                durationMs = b.maxMs,
                monitorCount = b.maxMonitors,
                eventCount = b.count,
                distinctCarriersPinned = b.carriers.size,
                blamedPlugin = b.blamedPlugin,
                evidence = b.evidence,
            )
        }

        return LoomPinningReport(
            totalPinnedEvents = incidents.sumOf { it.eventCount },
            distinctCarriersPinned = allCarriers.size,
            maxDurationMs = incidents.mapNotNull { it.durationMs }.maxOrNull() ?: 0.0,
            incidents = incidents,
        )
    }

    fun analyzeDbStarvation(text: String, plugins: PluginIndex = PluginIndex.EMPTY): DbStarvationReport {
        val lines = text.lines()
        data class Acc(
            val line: Int,
            val kind: DbStarvationKind,
            val poolName: String,
            var active: Int?,
            var total: Int?,
            var waiting: Int?,
            var maxTimeoutMs: Double?,
            var walFrames: Int?,
            var onTickThread: Boolean,
            var count: Int,
            var blamedPlugin: String?,
            val evidence: MutableList<String>,
        )

        val buckets = LinkedHashMap<String, Acc>()

        for (i in lines.indices) {
            val raw = lines[i]
            val lineNo = i + 1
            val threadName = THREAD_HEADER_RE.find(raw)?.groupValues?.get(1) ?: ""
            val tickThread = isTickThreadName(threadName)

            val statsMatch = HIKARI_STATS_RE.find(raw)
            val timeoutMatch = HIKARI_TIMEOUT_RE.find(raw)
            if (statsMatch != null || timeoutMatch != null) {
                val poolName = statsMatch?.groupValues?.get(1)
                    ?: timeoutMatch?.groupValues?.get(1)
                    ?: "HikariPool"
                val total = statsMatch?.groupValues?.get(2)?.toIntOrNull()
                val active = statsMatch?.groupValues?.get(3)?.toIntOrNull()
                val waiting = statsMatch?.groupValues?.get(5)?.toIntOrNull()
                val timeoutMs = timeoutMatch?.groupValues?.get(2)?.toDoubleOrNull()

                val saturated = timeoutMatch != null ||
                    (total != null && active != null && total > 0 && active >= total && (waiting ?: 0) > 0)
                if (saturated) {
                    val stackSlice = lines.subList(i, min(lines.size, i + 12))
                    val frames = StackFrame.parseAll(stackSlice)
                    val foreign = frames.firstOrNull { !isInfraOrServerClass(it.className) }
                    val poolHint = poolName.removeSuffix("-Pool").removeSuffix("Pool").takeIf {
                        !it.startsWith("Hikari", ignoreCase = true) && it.isNotBlank()
                    }
                    val blame = resolveBlame(foreign?.className, poolHint, plugins)
                    val key = "hikari@$poolName"
                    val existing = buckets[key]
                    if (existing == null) {
                        buckets[key] = Acc(
                            line = lineNo,
                            kind = DbStarvationKind.HIKARICP_POOL_EXHAUSTION,
                            poolName = poolName,
                            active = active,
                            total = total,
                            waiting = waiting,
                            maxTimeoutMs = timeoutMs,
                            walFrames = null,
                            onTickThread = tickThread,
                            count = 1,
                            blamedPlugin = blame,
                            evidence = stackSlice.take(4).map { it.trim() }.toMutableList(),
                        )
                    } else {
                        existing.count++
                        if (tickThread) existing.onTickThread = true
                        if (active != null) existing.active = max(existing.active ?: 0, active)
                        if (total != null) existing.total = max(existing.total ?: 0, total)
                        if (waiting != null) existing.waiting = max(existing.waiting ?: 0, waiting)
                        if (timeoutMs != null && timeoutMs > (existing.maxTimeoutMs ?: 0.0)) existing.maxTimeoutMs = timeoutMs
                        if (existing.blamedPlugin == null && blame != null) existing.blamedPlugin = blame
                    }
                    continue
                }
            }

            val busyMatch = SQLITE_BUSY_RE.containsMatchIn(raw)
            val walMatch = SQLITE_WAL_BACKLOG_RE.find(raw)
            if (busyMatch || walMatch != null) {
                val walFrames = walMatch?.groupValues?.get(1)?.toIntOrNull()
                val stackSlice = lines.subList(i, min(lines.size, i + 12))
                val frames = StackFrame.parseAll(stackSlice)
                val foreign = frames.firstOrNull { !isInfraOrServerClass(it.className) }
                val loggerLabel = Regex("""\[([A-Za-z0-9_.-]+)\]""").findAll(raw)
                    .map { it.groupValues[1] }
                    .firstOrNull { !it.contains(':') && !it.contains('/') && !it.startsWith("SQLITE", ignoreCase = true) }
                val blame = resolveBlame(foreign?.className, loggerLabel, plugins)
                val key = "sqlite@${blame ?: "sqlite-db"}"
                val existing = buckets[key]
                if (existing == null) {
                    buckets[key] = Acc(
                        line = lineNo,
                        kind = DbStarvationKind.SQLITE_WAL_OR_BUSY_LOCK,
                        poolName = blame ?: "SQLite database",
                        active = null,
                        total = null,
                        waiting = null,
                        maxTimeoutMs = null,
                        walFrames = walFrames,
                        onTickThread = tickThread,
                        count = 1,
                        blamedPlugin = blame,
                        evidence = stackSlice.take(4).map { it.trim() }.toMutableList(),
                    )
                } else {
                    existing.count++
                    if (tickThread) existing.onTickThread = true
                    if (walFrames != null) existing.walFrames = max(existing.walFrames ?: 0, walFrames)
                }
            }
        }

        val incidents = buckets.values.map { a ->
            DbStarvationIncident(
                line = a.line,
                kind = a.kind,
                poolOrDbName = a.poolName,
                activeConnections = a.active,
                totalConnections = a.total,
                waitingThreads = a.waiting,
                timeoutMs = a.maxTimeoutMs,
                walFrames = a.walFrames,
                onTickThread = a.onTickThread,
                eventCount = a.count,
                blamedPlugin = a.blamedPlugin,
                evidence = a.evidence,
            )
        }
        return DbStarvationReport(
            incidents = incidents,
            tickThreadStalls = incidents.count { it.onTickThread },
        )
    }

    fun analyzeHostPressure(text: String): List<HostPressureIncident> {
        val lines = text.lines()
        val incidents = mutableListOf<HostPressureIncident>()

        var nrPeriods: Long? = null
        var nrThrottled: Long? = null
        var throttledUsec: Long? = null
        var cpuStatLine = 0
        val cpuEvidence = mutableListOf<String>()

        var psiFlagged = false
        var thpFlagged = false
        var swapFlagged = false

        for (i in lines.indices) {
            val raw = lines[i]
            val lineNo = i + 1

            NR_PERIODS_RE.find(raw)?.let {
                nrPeriods = it.groupValues[1].toLongOrNull()
                if (cpuStatLine == 0) cpuStatLine = lineNo
                cpuEvidence += raw.trim()
            }
            NR_THROTTLED_RE.find(raw)?.let {
                nrThrottled = it.groupValues[1].toLongOrNull()
                if (cpuStatLine == 0) cpuStatLine = lineNo
                if (raw.trim() !in cpuEvidence) cpuEvidence += raw.trim()
            }
            THROTTLED_USEC_RE.find(raw)?.let {
                val rawVal = it.groupValues[1].toLongOrNull() ?: 0L
                throttledUsec = if (raw.contains("throttled_time")) rawVal / 1_000L else rawVal
                if (cpuStatLine == 0) cpuStatLine = lineNo
                if (raw.trim() !in cpuEvidence) cpuEvidence += raw.trim()
            }

            if (!psiFlagged) {
                PSI_STALL_RE.find(raw)?.let { pm ->
                    val scope = pm.groupValues[1].lowercase(Locale.ROOT)
                    val avg10 = pm.groupValues[2].toDoubleOrNull() ?: 0.0
                    if (avg10 >= 10.0) {
                        psiFlagged = true
                        incidents += HostPressureIncident(
                            line = lineNo,
                            kind = HostPressureKind.LINUX_PSI_STALL,
                            metricSummary = "Linux PSI ($scope avg10=${String.format(Locale.ROOT, "%.1f", avg10)}%) shows sustained host resource contention stalling JVM threads.",
                            throttleRatio = avg10 / 100.0,
                            swapMegabytes = null,
                            oomKills = null,
                            critical = avg10 >= 25.0 || scope == "full",
                            evidence = listOf(raw.trim()),
                        )
                    }
                }
            }

            if (!thpFlagged && THP_ALWAYS_RE.containsMatchIn(raw)) {
                thpFlagged = true
                incidents += HostPressureIncident(
                    line = lineNo,
                    kind = HostPressureKind.THP_COMPACTION_HAZARD,
                    metricSummary = "Linux Transparent HugePages is set to [always] or triggered khugepaged compaction pauses under a large JVM heap.",
                    throttleRatio = null,
                    swapMegabytes = null,
                    oomKills = null,
                    critical = false,
                    evidence = listOf(raw.trim()),
                )
            }

            if (!swapFlagged) {
                val vmSwapKb = VMSWAP_RE.find(raw)?.groupValues?.get(1)?.toLongOrNull()
                val freeSwapMb = FREE_SWAP_USED_RE.find(raw)?.groupValues?.get(1)?.toLongOrNull()
                val oomKills = CGROUP_OOM_RE.find(raw)?.groupValues?.get(1)?.toLongOrNull()
                val swapMb = vmSwapKb?.div(1024L) ?: freeSwapMb
                if ((swapMb != null && swapMb >= 256L) || (oomKills != null && oomKills > 0L)) {
                    swapFlagged = true
                    val summary = if (oomKills != null && oomKills > 0L) {
                        "Container cgroup memory.events records oom_kill=$oomKills (kernel OOM killer terminated or pressured the JVM)."
                    } else {
                        "Host OS swapped ${swapMb} MiB of memory to disk, turning GC reference scans into multi-second page-fault stalls."
                    }
                    incidents += HostPressureIncident(
                        line = lineNo,
                        kind = HostPressureKind.SWAP_OR_CGROUP_OOM,
                        metricSummary = summary,
                        throttleRatio = null,
                        swapMegabytes = swapMb,
                        oomKills = oomKills,
                        critical = (oomKills ?: 0L) > 0L || (swapMb ?: 0L) >= 1024L,
                        evidence = listOf(raw.trim()),
                    )
                }
            }
        }

        val periods = nrPeriods ?: 0L
        val throttled = nrThrottled ?: 0L
        val throttledMs = (throttledUsec ?: 0L) / 1_000L
        if (throttled > 0L && (periods == 0L || throttled.toDouble() / periods.toDouble() >= 0.05 || throttledMs >= 1_000L)) {
            val ratio = if (periods > 0L) throttled.toDouble() / periods.toDouble() else 1.0
            val pct = String.format(Locale.ROOT, "%.1f", ratio * 100.0)
            incidents.add(
                0,
                HostPressureIncident(
                    line = max(1, cpuStatLine),
                    kind = HostPressureKind.CGROUP_CPU_THROTTLING,
                    metricSummary = "Container cgroup cpu.stat throttled $throttled of ${max(periods, throttled)} CFS periods ($pct%, ${throttledMs} ms total throttled CPU time).",
                    throttleRatio = ratio,
                    swapMegabytes = null,
                    oomKills = null,
                    critical = ratio >= 0.20 || throttledMs >= 10_000L,
                    evidence = cpuEvidence.take(3),
                ),
            )
        }

        return incidents
    }

    /**
     * Aligns timestamped upstream faults and downstream lag/crash symptoms across one or more
     * diagnostic sources within a 5,000 ms causal window.
     */
    fun correlateSignals(
        sources: List<Pair<String, String>>,
        plugins: PluginIndex = PluginIndex.EMPTY,
    ): List<CausalCascade> {
        val rawSignals = mutableListOf<TimelineSignal>()
        var wallMinusUptimeOffsetMs: Long? = null

        for ((sourceName, content) in sources) {
            val lines = content.lines()
            for (i in lines.indices) {
                val raw = lines[i]
                val lineNo = i + 1
                val wallMs = parseWallClockMs(raw)
                val uptimeMs = parseUptimeMs(raw)
                if (wallMs != null && uptimeMs != null && wallMinusUptimeOffsetMs == null) {
                    wallMinusUptimeOffsetMs = wallMs - uptimeMs
                }

                val domain: ClockDomain
                val ts: Long
                when {
                    wallMs != null -> {
                        domain = ClockDomain.WALL_OF_DAY_MS
                        ts = wallMs
                    }
                    uptimeMs != null -> {
                        domain = ClockDomain.UPTIME_MS
                        ts = uptimeMs
                    }
                    else -> continue
                }

                classifySignalLine(sourceName, lineNo, domain, ts, raw, lines, i, plugins)?.let {
                    rawSignals += it
                }
            }
        }

        if (rawSignals.size < 2) return emptyList()

        // Normalize UPTIME_MS signals into WALL_OF_DAY_MS when a dual-timestamp anchor line exists.
        val anchorOffset = wallMinusUptimeOffsetMs
        val normalized = rawSignals.map { sig ->
            if (sig.clockDomain == ClockDomain.UPTIME_MS && anchorOffset != null) {
                sig.copy(
                    clockDomain = ClockDomain.WALL_OF_DAY_MS,
                    timestampMs = sig.timestampMs + anchorOffset,
                )
            } else {
                sig
            }
        }.sortedWith(compareBy<TimelineSignal> { it.clockDomain }.thenBy { it.timestampMs }.thenBy { it.stage.rank })

        val cascades = mutableListOf<CausalCascade>()
        val seenKeys = hashSetOf<String>()

        val symptoms = normalized.filter {
            it.stage == SignalStage.TICK_OR_NETTY_SYMPTOM || it.stage == SignalStage.WATCHDOG_OR_REGION_CRASH
        }

        for (symptom in symptoms) {
            val candidates = normalized.filter { cand ->
                cand.clockDomain == symptom.clockDomain &&
                    cand.stage.rank < symptom.stage.rank &&
                    symptom.timestampMs - cand.timestampMs in 0..CAUSAL_WINDOW_MS
            }
            if (candidates.isEmpty()) continue

            // Lowest rank = furthest upstream root cause; tie-break by earliest timestamp.
            val root = candidates.minWith(
                compareBy<TimelineSignal> { it.stage.rank }.thenBy { it.timestampMs }
            )
            val intermediates = candidates
                .filter { it !== root && it.stage.rank > root.stage.rank && it.stage.rank < symptom.stage.rank }
                .distinctBy { it.stage }

            val dedupKey = "${root.ruleHint}->${symptom.ruleHint}@${root.blamedPlugin ?: symptom.blamedPlugin ?: "server"}"
            if (!seenKeys.add(dedupKey)) continue

            val leadMs = (symptom.timestampMs - root.timestampMs).coerceAtLeast(0L)
            val blame = root.blamedPlugin ?: intermediates.firstOrNull { it.blamedPlugin != null }?.blamedPlugin ?: symptom.blamedPlugin
            val proximityBoost = 1.0 - (leadMs.toDouble() / (CAUSAL_WINDOW_MS.toDouble() * 2.5))
            val hopBoost = if (intermediates.isNotEmpty()) 0.08 else 0.0
            val confidence = (0.72 + 0.20 * proximityBoost + hopBoost).coerceIn(0.65, 0.99)

            val chainParts = buildList {
                add("[${root.ruleHint}] ${root.summary}")
                intermediates.forEach { add("[${it.ruleHint}] ${it.summary}") }
                add("[${symptom.ruleHint}] ${symptom.summary}")
            }
            val chainSummary = buildString {
                append("Causal cascade (delta-t=${leadMs} ms, confidence=${String.format(Locale.ROOT, "%.0f", confidence * 100.0)}%): ")
                append(chainParts.joinToString(" -> "))
                blame?.let { append(" (primary attribution: $it)") }
                append('.')
            }

            val ev = buildList {
                add("${root.sourceName}:${root.line} ${root.rawLine.trim()}")
                intermediates.take(2).forEach { add("${it.sourceName}:${it.line} ${it.rawLine.trim()}") }
                add("${symptom.sourceName}:${symptom.line} ${symptom.rawLine.trim()}")
            }

            cascades += CausalCascade(
                rootSignal = root,
                intermediateSignals = intermediates,
                symptomSignal = symptom,
                leadTimeMs = leadMs,
                confidence = confidence,
                blamedPlugin = blame,
                chainSummary = chainSummary,
                evidence = ev,
            )
        }

        return cascades
    }

    fun diagnose(
        primarySource: LogSource,
        plugins: PluginIndex = PluginIndex.EMPTY,
        gcSource: LogSource? = null,
        jfrSource: LogSource? = null,
    ): ScanReport {
        val primaryText = readBounded(primarySource)
        val gcText = gcSource?.let { readBounded(it) }
        val jfrText = jfrSource?.let { readBounded(it) }

        val combinedAux = buildString {
            append(primaryText)
            if (!gcText.isNullOrBlank()) {
                append('\n')
                append(gcText)
            }
            if (!jfrText.isNullOrBlank()) {
                append('\n')
                append(jfrText)
            }
        }

        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()
        val locPrefix = primarySource.path.fileName?.toString() ?: primarySource.path.toString()

        val loomReport = analyzeLoomPinning(combinedAux, plugins)
        if (loomReport.totalPinnedEvents > 0) {
            facts["virtual thread pinned events"] = loomReport.totalPinnedEvents.toString()
            facts["distinct carriers pinned"] = loomReport.distinctCarriersPinned.toString()
        }
        for (inc in loomReport.incidents) {
            sink.add(
                rule = LogRules.VIRTUAL_THREAD_CARRIER_PINNING,
                location = "$locPrefix:${inc.line}",
                detail = formatLoomDetail(inc),
                evidence = inc.evidence,
            )
        }

        val dbReport = analyzeDbStarvation(combinedAux, plugins)
        if (dbReport.incidents.isNotEmpty()) {
            facts["persistence starvation groups"] = dbReport.incidents.size.toString()
            if (dbReport.tickThreadStalls > 0) {
                facts["tick-thread persistence stalls"] = dbReport.tickThreadStalls.toString()
            }
        }
        for (inc in dbReport.incidents) {
            sink.add(
                rule = LogRules.DB_POOL_OR_SQLITE_WAL_STARVATION,
                location = "$locPrefix:${inc.line}",
                detail = formatDbDetail(inc),
                evidence = inc.evidence,
                severityOverride = if (inc.onTickThread) Severity.CRITICAL else Severity.WARNING,
            )
        }

        val hostIncidents = analyzeHostPressure(combinedAux)
        for (inc in hostIncidents) {
            sink.add(
                rule = LogRules.LINUX_CGROUP_THROTTLE_OR_SWAP_PRESSURE,
                location = "$locPrefix:${inc.line}",
                detail = inc.metricSummary,
                evidence = inc.evidence,
                severityOverride = if (inc.critical) Severity.CRITICAL else Severity.WARNING,
            )
        }

        val namedSources = buildList {
            add(locPrefix to primaryText)
            if (gcSource != null && !gcText.isNullOrBlank()) {
                add((gcSource.path.fileName?.toString() ?: "gc.log") to gcText)
            }
            if (jfrSource != null && !jfrText.isNullOrBlank()) {
                add((jfrSource.path.fileName?.toString() ?: "jfr.txt") to jfrText)
            }
        }
        val cascades = correlateSignals(namedSources, plugins)
        if (cascades.isNotEmpty()) {
            facts["causal incident cascades"] = cascades.size.toString()
        }
        for (cascade in cascades) {
            sink.add(
                rule = LogRules.CAUSAL_INCIDENT_CASCADE,
                location = "${cascade.symptomSignal.sourceName}:${cascade.symptomSignal.line}",
                detail = cascade.chainSummary,
                evidence = cascade.evidence,
            )
        }

        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = primarySource.path.toString(),
            subjectKind = "incident-correlation",
            findings = sink.findings(),
            facts = facts,
        )
    }

    internal fun formatLoomDetail(inc: LoomPinningIncident): String = buildString {
        val mech = if (inc.mechanism == PinningMechanism.NATIVE_OR_FOREIGN_UPCALL) {
            "native/foreign frame"
        } else {
            "synchronized monitor (<== monitors:${inc.monitorCount})"
        }
        append("Virtual thread pinned carrier \"${inc.carrierThread}\" via $mech during ${inc.blockingOperation}")
        inc.monitorFrame?.let { append(" at $it") }
        inc.durationMs?.let { append(" (${String.format(Locale.ROOT, "%.1f", it)} ms)") }
        if (inc.distinctCarriersPinned > 1 || inc.eventCount > 1) {
            append(" across ${inc.eventCount} event(s) on ${inc.distinctCarriersPinned} carrier(s)")
        }
        inc.blamedPlugin?.let { append(", attributed to $it") }
        append('.')
    }

    internal fun formatDbDetail(inc: DbStarvationIncident): String = when (inc.kind) {
        DbStarvationKind.HIKARICP_POOL_EXHAUSTION -> buildString {
            if (inc.onTickThread) append("Synchronous tick-thread DB stall: ")
            append("HikariCP pool '${inc.poolOrDbName}' exhausted")
            if (inc.activeConnections != null && inc.totalConnections != null) {
                append(" (active=${inc.activeConnections}/${inc.totalConnections}")
                inc.waitingThreads?.let { append(", waiting=$it") }
                append(')')
            }
            inc.timeoutMs?.let { append(", request timed out after ${String.format(Locale.ROOT, "%.0f", it)} ms") }
            if (inc.eventCount > 1) append(" (${inc.eventCount} occurrences)")
            inc.blamedPlugin?.let { append(", attributed to $it") }
            append('.')
        }
        DbStarvationKind.SQLITE_WAL_OR_BUSY_LOCK -> buildString {
            if (inc.onTickThread) append("Synchronous tick-thread SQLite lock: ")
            append("SQLite database hit lock/WAL checkpoint contention")
            inc.walFrames?.let { append(" ($it uncheckpointed WAL frames)") }
            if (inc.eventCount > 1) append(" (${inc.eventCount} occurrences)")
            inc.blamedPlugin?.let { append(", attributed to $it") }
            append('.')
        }
    }

    private fun classifySignalLine(
        sourceName: String,
        lineNo: Int,
        domain: ClockDomain,
        ts: Long,
        raw: String,
        allLines: List<String>,
        idx: Int,
        plugins: PluginIndex,
    ): TimelineSignal? {
        val slice = allLines.subList(idx, min(allLines.size, idx + 8))
        val foreign = StackFrame.parseAll(slice).firstOrNull { !isInfraOrServerClass(it.className) }
        val blame = resolveBlame(foreign?.className, null, plugins)

        // Stage 1: Host OS / Cgroup pressure
        if (NR_THROTTLED_RE.containsMatchIn(raw) || PSI_STALL_RE.containsMatchIn(raw) || VMSWAP_RE.containsMatchIn(raw)) {
            return TimelineSignal(
                sourceName, lineNo, domain, ts,
                SignalStage.HOST_PRESSURE, "L044", "Host cgroup CPU throttle or OS memory stall", blame, raw
            )
        }

        // Stage 2: JVM GC pause / To-space exhausted / ZGC Allocation Stall
        if (raw.contains("To-space exhausted", ignoreCase = true) ||
            raw.contains("Allocation Stall", ignoreCase = true) ||
            raw.contains("Pause Full", ignoreCase = true)
        ) {
            return TimelineSignal(
                sourceName, lineNo, domain, ts,
                SignalStage.GC_PAUSE, "L020", "Severe JVM GC stall or evacuation failure", blame, raw
            )
        }
        val gcPauseMatch = Regex("""Pause\s+(?:Young|Remark|Cleanup)[^\r\n]*?\s(\d+(?:[.,]\d+)?)ms""").find(raw)
        if (gcPauseMatch != null) {
            val ms = gcPauseMatch.groupValues[1].replace(',', '.').toDoubleOrNull() ?: 0.0
            if (ms >= 60.0) {
                return TimelineSignal(
                    sourceName, lineNo, domain, ts,
                    SignalStage.GC_PAUSE, "L019", "Stop-the-world GC pause (${String.format(Locale.ROOT, "%.1f", ms)} ms)", blame, raw
                )
            }
        }

        // Stage 3: Persistence starvation or Loom carrier pinning
        if (HIKARI_TIMEOUT_RE.containsMatchIn(raw) || HIKARI_STATS_RE.containsMatchIn(raw) || SQLITE_BUSY_RE.containsMatchIn(raw)) {
            val poolMatch = HIKARI_TIMEOUT_RE.find(raw)?.groupValues?.get(1)
                ?: HIKARI_STATS_RE.find(raw)?.groupValues?.get(1)
            val resolved = blame ?: resolveBlame(null, poolMatch, plugins)
            return TimelineSignal(
                sourceName, lineNo, domain, ts,
                SignalStage.PERSISTENCE_OR_LOOM, "L043", "Database connection pool or SQLite lock starvation", resolved, raw
            )
        }
        if (TRACE_PINNED_HEADER_RE.containsMatchIn(raw) || raw.contains("<== monitors:") || raw.contains("VirtualThreadPinned")) {
            return TimelineSignal(
                sourceName, lineNo, domain, ts,
                SignalStage.PERSISTENCE_OR_LOOM, "L042", "Virtual thread carrier pinning", blame, raw
            )
        }

        // Stage 4: Lock contention
        if (raw.contains("jdk.JavaMonitorEnter") || raw.contains("blocked on", ignoreCase = true)) {
            return TimelineSignal(
                sourceName, lineNo, domain, ts,
                SignalStage.LOCK_CONTENTION, "L041", "Monitor or ReentrantLock contention", blame, raw
            )
        }

        // Stage 6: Watchdog or Folia region crash (check before generic slow tick)
        if (raw.contains("The server has stopped responding") ||
            raw.contains("DO NOT REPORT THIS TO PAPER") ||
            raw.contains("DO NOT REPORT THIS TO FOLIA") ||
            raw.contains("has not responded for", ignoreCase = true) ||
            (raw.contains("region", ignoreCase = true) && raw.contains("stalled", ignoreCase = true)) ||
            raw.contains("FoliaWatchdogThread")
        ) {
            return TimelineSignal(
                sourceName, lineNo, domain, ts,
                SignalStage.WATCHDOG_OR_REGION_CRASH, "L001", "Server or Folia regional watchdog stall", blame, raw
            )
        }

        // Stage 5: Slow tick or Netty keepalive timeout
        if (raw.contains("Slow tick detected", ignoreCase = true) ||
            raw.contains("Can't keep up!", ignoreCase = true) ||
            raw.contains("Timed out", ignoreCase = true) && raw.contains("lost connection", ignoreCase = true)
        ) {
            return TimelineSignal(
                sourceName, lineNo, domain, ts,
                SignalStage.TICK_OR_NETTY_SYMPTOM, "L023", "Tick duration spike or player keepalive timeout", blame, raw
            )
        }

        return null
    }

    private fun parseLoomFrame(line: String): ParsedLoomFrame? {
        val normalized = line.replace(Regex("""/0x[0-9a-fA-F]+(?=\.)"""), "")
        val m = LOOM_FRAME_RE.find(normalized) ?: return null
        val cls = m.groupValues[1].substringBefore("\$\$Lambda")
        val mth = m.groupValues[2]
        val src = m.groupValues[3]
        val monitors = m.groupValues[4].toIntOrNull() ?: 0
        val isNative = src.equals("Native Method", ignoreCase = true)
        return ParsedLoomFrame(
            raw = line.trim(),
            className = cls,
            method = mth,
            monitors = monitors,
            nativeMethod = isNative,
        )
    }

    private fun classifyBlockingSink(frames: List<ParsedLoomFrame>, reason: String?): String {
        val joined = frames.joinToString(" ") { "${it.className}.${it.method}" } + " " + (reason ?: "")
        return when {
            joined.contains("jdbc", ignoreCase = true) ||
                joined.contains("mysql", ignoreCase = true) ||
                joined.contains("postgresql", ignoreCase = true) ||
                joined.contains("sqlite", ignoreCase = true) ||
                joined.contains("hikari", ignoreCase = true) -> "JDBC query / socket I/O"
            joined.contains("Socket", ignoreCase = true) ||
                joined.contains("Http", ignoreCase = true) ||
                joined.contains("Netty", ignoreCase = true) -> "network socket I/O"
            joined.contains("File", ignoreCase = true) ||
                joined.contains("RandomAccessFile", ignoreCase = true) ||
                joined.contains("ZipFile", ignoreCase = true) -> "filesystem / archive I/O"
            frames.any { it.nativeMethod } -> "JNI / foreign native call"
            else -> "blocking park inside monitor"
        }
    }

    private fun parseWallClockMs(line: String): Long? {
        val m = WALL_CLOCK_RE.find(line) ?: return null
        val hh = m.groupValues[1].toLongOrNull() ?: return null
        val mm = m.groupValues[2].toLongOrNull() ?: return null
        val ss = m.groupValues[3].toLongOrNull() ?: return null
        if (hh > 23 || mm > 59 || ss > 59) return null
        val fracRaw = m.groupValues[4]
        val ms = when (fracRaw.length) {
            0 -> 0L
            1 -> (fracRaw.toLongOrNull() ?: 0L) * 100L
            2 -> (fracRaw.toLongOrNull() ?: 0L) * 10L
            else -> fracRaw.take(3).toLongOrNull() ?: 0L
        }
        return ((hh * 3600L + mm * 60L + ss) * 1000L) + ms
    }

    private fun parseUptimeMs(line: String): Long? {
        val m = UPTIME_SEC_RE.find(line) ?: return null
        val sec = m.groupValues[1].toDoubleOrNull() ?: return null
        return (sec * 1000.0).toLong()
    }

    private val INFRA_DRIVER_PREFIXES = listOf(
        "com.zaxxer.hikari.",
        "com.mysql.",
        "org.mariadb.",
        "org.postgresql.",
        "org.sqlite.",
        "org.h2.",
        "okhttp3.",
        "org.apache.http.",
        "redis.clients.",
        "io.lettuce.",
    )

    private fun isInfraOrServerClass(className: String): Boolean =
        ServerPackages.isServerOwned(className) || INFRA_DRIVER_PREFIXES.any { className.startsWith(it) }

    private fun isTickThreadName(name: String): Boolean {
        val lower = name.lowercase(Locale.ROOT)
        return lower.contains("server thread") ||
            lower.contains("primary thread") ||
            lower.contains("tickregionthread") ||
            lower.contains("region scheduler thread") ||
            lower.contains("global region scheduler")
    }

    private fun resolveBlame(className: String?, hintOrLabel: String?, plugins: PluginIndex): String? {
        if (className != null) {
            plugins.owningPlugin(className)?.let { return it.descriptor?.name ?: it.fileName }
        }
        if (!hintOrLabel.isNullOrBlank()) {
            plugins.byLoggerLabel(hintOrLabel)?.let { return it.descriptor?.name ?: it.fileName }
            plugins.jars.firstOrNull {
                it.descriptor?.name?.equals(hintOrLabel, ignoreCase = true) == true
            }?.let { return it.descriptor?.name ?: it.fileName }
        }
        if (className != null && !ServerPackages.isServerOwned(className)) {
            return className
        }
        if (!hintOrLabel.isNullOrBlank() && abs(hintOrLabel.length) >= 3 && !hintOrLabel.startsWith("Hikari", ignoreCase = true)) {
            return hintOrLabel
        }
        return null
    }

    private fun readBounded(source: LogSource, maxLines: Int = 50_000): String {
        val sb = StringBuilder()
        source.forEachLine(limit = maxLines) { line ->
            if (sb.isNotEmpty()) sb.append('\n')
            sb.append(line.text)
        }
        return sb.toString()
    }

    private fun stripLogHeader(raw: String): String =
        raw.replace(Regex("""^\[[^\]]+\]\s*(?:\[[^\]]+\]:\s*)?"""), "")

    private fun toMillis(value: Double, unit: String): Double = when (unit.lowercase(Locale.ROOT)) {
        "s" -> value * 1000.0
        "ms" -> value
        "us", "µs" -> value / 1000.0
        "ns" -> value / 1_000_000.0
        else -> value
    }
}
