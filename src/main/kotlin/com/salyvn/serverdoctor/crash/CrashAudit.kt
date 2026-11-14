package com.salyvn.serverdoctor.crash

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.log.ServerPackages
import com.salyvn.serverdoctor.log.StackFrame
import com.salyvn.serverdoctor.plugins.PluginIndex

/**
 * Audits the crash reports a server wrote.
 *
 * The reports are read as a set rather than one at a time, because the difference between an accident
 * and a loop is only visible across files: five reports with one description is the finding, and no
 * single report contains it. When a plugins directory is available the traces are attributed to a jar;
 * without one the first foreign package is named and nothing is claimed about which plugin owns it.
 */
class CrashAudit(private val plugins: PluginIndex = PluginIndex.EMPTY) {

    fun analyse(reports: List<CrashReportFile>, subject: String): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()
        val ordered = CrashReportFile.sortedByName(reports)

        facts["crash reports"] = ordered.size.toString()
        if (ordered.isEmpty()) return report(subject, sink, facts)

        for (crash in ordered) {
            if (!crash.ok) {
                sink.add(CrashRules.UNREADABLE, crash.name, crash.parseError ?: "unreadable")
                continue
            }
            if (crash.description == null && crash.exception == null && crash.headFrames.isEmpty()) {
                sink.add(
                    rule = CrashRules.UNREADABLE,
                    location = crash.name,
                    detail = "The file has no Description, no exception and no stack frames, so there " +
                        "was nothing to read. It may not be a crash report.",
                )
                continue
            }
            examine(crash, sink)
        }

        checkRepeats(ordered, sink)
        ordered.lastOrNull { it.ok }?.let { describe(it, ordered, facts) }

        return report(subject, sink, facts)
    }

    private fun examine(crash: CrashReportFile, sink: FindingSink) {
        val trace = crash.headFrames.take(MAX_FRAMES).map { it.raw }
        val top = crash.headFrames.firstOrNull()

        sink.add(
            rule = CrashRules.CRASHED,
            location = crash.name,
            detail = buildString {
                append(crash.description ?: crash.exception ?: "The report gives no description")
                crash.time?.let { append(", at $it") }
                top?.let { append(". The trace starts in ${it.className}.${it.method}") }
                append('.')
            },
            evidence = listOfNotNull(crash.exception) + trace,
        )

        if (crash.outOfMemory) {
            sink.add(
                rule = CrashRules.OUT_OF_MEMORY,
                location = crash.name,
                detail = buildString {
                    append("An OutOfMemoryError is named in this report")
                    crash.memory?.let { append(". Memory at the time: $it") }
                    append('.')
                },
                evidence = listOfNotNull(
                    crash.exception,
                    crash.memory?.let { "Memory: $it" },
                    crash.details["JVM Flags"]?.let { "JVM Flags: $it" },
                ),
            )
        }

        blame(crash)?.let { (who, frame) ->
            sink.add(
                rule = CrashRules.PLUGIN_IN_TRACE,
                location = crash.name,
                detail = "The outermost frame that is not server, JDK or Netty code belongs to $who.",
                evidence = listOf(frame.raw) + trace.filter { it != frame.raw }.take(MAX_FRAMES - 1),
            )
        }

        val ticking = crash.tickingSections
        val describedAsTicking = crash.description?.startsWith("Ticking", ignoreCase = true) == true
        if (ticking.isNotEmpty() || describedAsTicking) {
            val what = ticking.keys.firstOrNull() ?: crash.description!!
            sink.add(
                rule = CrashRules.TICKING_OBJECT,
                location = crash.name,
                detail = "The report says the server was ticking one object: $what.",
                evidence = ticking.values.flatten()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && it != "Details:" && it != "Stacktrace:" }
                    .take(MAX_TICK_DETAILS),
            )
        }
    }

    /** The plugin or package the outermost foreign frame belongs to, with that frame. */
    private fun blame(crash: CrashReportFile): Pair<String, StackFrame>? {
        for (frame in crash.headFrames) {
            plugins.owningPlugin(frame.className)?.let { jar ->
                return (jar.descriptor?.name ?: jar.fileName) to frame
            }
        }
        val foreign = ServerPackages.firstForeignFrame(crash.headFrames) ?: return null
        val where = foreign.packageName.ifEmpty { foreign.className }
        return where to foreign
    }

    /**
     * Reports written for one cause. Grouped on the description because that is what the server writes
     * from the failure itself; the traces below it can differ between two hits of the same bug.
     */
    private fun checkRepeats(reports: List<CrashReportFile>, sink: FindingSink) {
        reports.filter { it.ok }
            .mapNotNull { crash -> crash.description?.let { it to crash } }
            .groupBy({ it.first }, { it.second })
            .filterValues { it.size > 1 }
            .forEach { (description, group) ->
                sink.add(
                    rule = CrashRules.REPEATED_CRASH,
                    location = group.last().name,
                    detail = "${group.size} reports say: $description.",
                    evidence = group.map { crash ->
                        listOfNotNull(crash.name, crash.time).joinToString(" - ")
                    },
                )
            }
    }

    /** Facts from the newest readable report: what it ran on, and what it was given to run with. */
    private fun describe(
        newest: CrashReportFile,
        all: List<CrashReportFile>,
        facts: MutableMap<String, String>,
    ) {
        facts["newest"] = newest.name
        newest.time?.let { facts["crashed at"] = it }
        newest.minecraftVersion?.let { facts["minecraft"] = it }
        newest.serverBrand?.let { facts["server brand"] = it }
        newest.javaVersion?.let { facts["java"] = it }
        newest.memory?.let { facts["memory"] = it }
        newest.playerCount?.let { facts["players"] = it }
        if (newest.plugins.isNotEmpty()) facts["plugins listed"] = newest.plugins.size.toString()
        if (newest.jvmFlags != null) facts["jvm flags"] = "read from ${newest.name}"
        val unreadable = all.count { !it.ok }
        if (unreadable > 0) facts["unreadable"] = unreadable.toString()
    }

    private fun report(subject: String, sink: FindingSink, facts: Map<String, String>) = ScanReport(
        tool = BuildInfo.NAME,
        toolVersion = BuildInfo.version,
        subject = subject,
        subjectKind = "crash",
        findings = sink.findings(),
        facts = facts,
    )

    private companion object {
        const val MAX_FRAMES = 8
        const val MAX_TICK_DETAILS = 10
    }
}
