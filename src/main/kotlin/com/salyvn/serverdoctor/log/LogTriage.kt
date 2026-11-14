package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.Finding
import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.core.Severity
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.plugins.PluginIndex

/**
 * Reads a server log and reports what went wrong, worst first.
 *
 * Two design decisions shape everything here.
 *
 * The first is aggregation. A broken plugin does not fail once; it fails every tick, and a log with
 * four hundred copies of one stack trace is one problem, not four hundred. Findings are therefore
 * keyed and counted, and the report names the first line where each one appeared.
 *
 * The second is attribution. Naming the wrong plugin is worse than naming none, so each finding says
 * how it was attributed: from the bracketed logger label, from the server's own blame message, or
 * from a stack frame - and when a plugins directory is supplied, the label and the frame are checked
 * against what is actually installed instead of being guessed at.
 */
class LogTriage(private val plugins: PluginIndex = PluginIndex.EMPTY) {

    private data class Key(val ruleId: String, val discriminator: String)

    private class Hit(
        val rule: Rule,
        val location: String,
        val detail: String,
        val evidence: MutableList<String>,
        var count: Int = 1,
    )

    fun analyse(source: LogSource): ScanReport {
        val hits = LinkedHashMap<Key, Hit>()
        val unexplained = LinkedHashMap<String, Hit>()
        val facts = linkedMapOf<String, String>()

        var firstTimestamp: String? = null
        var lastTimestamp: String? = null
        var watchdogThread: String? = null
        var watchdogTargetKey: Key? = null
        var watchdogHitLine = 0

        fun record(rule: Rule, discriminator: String, line: Int, detail: String, evidence: List<String>) {
            val key = Key(rule.id, discriminator)
            val existing = hits[key]
            if (existing == null) {
                hits[key] = Hit(rule, "line $line", detail, evidence.toMutableList())
            } else {
                existing.count++
            }
        }

        val stats = LogParser().parse(source) { event ->
            event.timestamp?.let {
                if (firstTimestamp == null) firstTimestamp = it
                lastTimestamp = it
            }
            captureFacts(event, facts)

            var explained = false

            // The watchdog prints its banner and then the thread dump as separate log lines, all from
            // its own thread. Scoping collection to that thread is what stops the next unrelated
            // stack trace in the log from being read as part of the dump.
            if (watchdogThread != null) {
                val sameThread = event.thread == watchdogThread
                val stale = event.startLine - watchdogHitLine > WATCHDOG_DUMP_WINDOW
                if (!sameThread || stale) {
                    watchdogThread = null
                    watchdogTargetKey = null
                } else {
                    val frame = StackFrame.parse(event.message)
                    val target = watchdogTargetKey?.let { hits[it] }
                    if (frame != null && target != null && target.evidence.size < MAX_EVIDENCE) {
                        val owner = plugins.owningPlugin(frame.className)
                        val suffix = owner?.descriptor?.name?.let { "   <- $it" } ?: ""
                        target.evidence += frame.raw + suffix
                    }
                }
            }

            for (detector in DETECTORS) {
                val match = detector.detect(event, plugins) ?: continue
                explained = true
                record(detector.rule, match.discriminator, event.startLine, match.detail, match.evidence)
                if (detector.rule.id == LogRules.WATCHDOG_FIRED.id ||
                    detector.rule.id == LogRules.FOLIA_REGION_STALL.id
                ) {
                    watchdogThread = event.thread ?: "unknown"
                    watchdogTargetKey = Key(detector.rule.id, match.discriminator)
                    watchdogHitLine = event.startLine
                }
            }

            // Anything severe that no rule explains is still reported, grouped by what threw and
            // where, so a clean report cannot hide an error nobody wrote a signature for.
            if (!explained && event.isProblem && event.exceptions.isNotEmpty()) {
                val exception = event.exceptions.first()
                val blame = attribute(event, plugins)
                val discriminator = "$exception@${blame ?: "unknown"}"
                val existing = unexplained[discriminator]
                if (existing == null) {
                    unexplained[discriminator] = Hit(
                        rule = LogRules.UNCAUGHT_SEVERE,
                        location = "line ${event.startLine}",
                        detail = buildString {
                            append(exception)
                            if (blame != null) append(", in $blame")
                            append(". ")
                            append(event.message.take(160))
                        },
                        evidence = event.frames.take(4).map { it.raw }.toMutableList(),
                    )
                } else {
                    existing.count++
                }
            }
        }

        facts["lines read"] = if (stats.truncated) "${stats.lines} (stopped at the cap)" else stats.lines.toString()
        facts["log entries"] = stats.events.toString()
        stats.dominantFormat?.let { facts["line format"] = it }
        if (firstTimestamp != null) {
            facts["covers"] = if (lastTimestamp != null && lastTimestamp != firstTimestamp) {
                "$firstTimestamp to $lastTimestamp"
            } else {
                firstTimestamp
            }
        }
        if (!plugins.isEmpty) facts["plugins indexed"] = plugins.jars.count { it.isPlugin }.toString()

        val findings = mutableListOf<Finding>()
        for (hit in hits.values) findings += hit.toFinding()
        for (hit in unexplained.values) {
            // The same trace hundreds of times is a different problem from the same trace once: it
            // means a code path is being retried, which is why it gets its own rule and severity.
            val rule = if (hit.count >= REPEAT_THRESHOLD) LogRules.REPEATED_EXCEPTION else LogRules.UNCAUGHT_SEVERE
            findings += Hit(rule, hit.location, hit.detail, hit.evidence, hit.count).toFinding()
        }

        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = source.path.toString(),
            subjectKind = "log",
            findings = findings.sortedWith(
                compareByDescending<Finding> { it.severity.rank }.thenBy { it.ruleId }.thenBy { it.location }
            ),
            facts = facts,
        )
    }

    private fun Hit.toFinding(): Finding {
        val occurrences = if (count > 1) " (x$count)" else ""
        return Finding(
            ruleId = rule.id,
            severity = rule.severity,
            title = rule.title,
            location = location + occurrences,
            detail = detail,
            evidence = evidence.take(MAX_EVIDENCE),
            fix = rule.fix,
            provenance = rule.provenance,
        )
    }

    /** Facts worth printing whether or not anything is wrong. Extraction only, no claims. */
    private fun captureFacts(event: LogEvent, into: MutableMap<String, String>) {
        val message = event.message
        when {
            message.startsWith("This server is running") && !into.containsKey("server") ->
                into["server"] = message.removePrefix("This server is running").trim().take(120)

            message.startsWith("Starting minecraft server version") && !into.containsKey("minecraft") ->
                into["minecraft"] = message.substringAfterLast(' ')

            message.startsWith("Done (") && !into.containsKey("startup") ->
                into["startup"] = message.substringAfter("Done (").substringBefore(')')
        }
    }

    companion object {
        private const val MAX_EVIDENCE = 12
        private const val WATCHDOG_DUMP_WINDOW = 400
        private const val REPEAT_THRESHOLD = 25

        /**
         * Best-effort blame for an event: the label the line was logged under, then the first stack
         * frame that belongs to something other than the server or the runtime.
         */
        internal fun attribute(event: LogEvent, plugins: PluginIndex): String? {
            event.loggerPlugin?.let { label ->
                val known = plugins.byLoggerLabel(label)
                return known?.descriptor?.name ?: label
            }
            val frames = event.frames.ifEmpty { listOfNotNull(StackFrame.parse(event.message)) }
            for (frame in frames) {
                plugins.owningPlugin(frame.className)?.let { return it.descriptor?.name ?: it.fileName }
            }
            return ServerPackages.firstForeignFrame(frames)
                ?.packageName
                ?.takeIf { it.isNotEmpty() }
        }

        private val DETECTORS: List<LogDetector> = LogDetectors.all
    }
}

/** What a detector found: how to group it, what to say, and the lines that back it up. */
data class DetectorMatch(
    val discriminator: String,
    val detail: String,
    val evidence: List<String> = emptyList(),
)

/** One signature: a rule plus the test that decides whether an event is a hit for it. */
interface LogDetector {
    val rule: Rule

    fun detect(event: LogEvent, plugins: PluginIndex): DetectorMatch?
}
