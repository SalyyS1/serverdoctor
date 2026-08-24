package com.salyvn.serverdoctor.flags

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport

/**
 * Audits a JVM command line.
 *
 * The distinction that keeps this useful is between a fact and a preference. `-Ddisable.watchdog`
 * disables the watchdog — that is a fact, read from the field in Paper that consumes it, and it is
 * reported as critical. Whether a heap should carry `G1MixedGCCountTarget=4` is a preference, so the
 * missing-flag check produces one informational finding listing what differs, and stops there.
 */
class FlagsAudit(private val hostMemoryBytes: Long? = null) {

    fun analyse(source: String, command: JvmCommandLine?): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()

        if (command == null || command.tokens.isEmpty()) {
            sink.add(
                rule = FlagRules.NO_JAVA_COMMAND_FOUND,
                location = source,
                detail = "Nothing in this input looked like a java invocation.",
            )
            return report(source, sink, facts)
        }

        command.javaBinary?.let { facts["java"] = it }
        command.jarPath?.let { facts["jar"] = it }
        facts["heap"] = listOfNotNull(
            command.initialHeapBytes?.let { "-Xms ${JvmCommandLine.humanSize(it)}" },
            command.maxHeapBytes?.let { "-Xmx ${JvmCommandLine.humanSize(it)}" },
        ).joinToString(", ").ifEmpty { "not set" }
        facts["collector"] = command.collectorFlag ?: "JVM default"
        facts["-XX flags"] = command.tuningFlags.size.toString()
        if (command.applicationArguments.isNotEmpty()) {
            facts["server args"] = command.applicationArguments.joinToString(" ")
        }
        hostMemoryBytes?.let { facts["host memory"] = JvmCommandLine.humanSize(it) }

        checkHeap(command, sink, source)
        checkCollectors(command, sink, source)
        checkSystemProperties(command, sink, source)
        checkRecommendedSet(command, sink, source)

        return report(source, sink, facts)
    }

    private fun report(source: String, sink: FindingSink, facts: Map<String, String>) = ScanReport(
        tool = BuildInfo.NAME,
        toolVersion = BuildInfo.version,
        subject = source,
        subjectKind = "flags",
        findings = sink.findings(),
        facts = facts,
    )

    private fun checkHeap(command: JvmCommandLine, sink: FindingSink, source: String) {
        val max = command.maxHeapBytes
        val min = command.initialHeapBytes

        if (max == null) {
            // MaxRAMPercentage is a legitimate way to size a container heap, so it is not the same
            // omission and is not reported as one.
            if (!command.hasFlag("MaxRAMPercentage") && !command.hasFlag("MaxRAMFraction")) {
                sink.add(FlagRules.NO_MAX_HEAP, source, "No -Xmx and no MaxRAMPercentage.")
            }
            return
        }

        if (min != null && min != max) {
            sink.add(
                rule = FlagRules.HEAP_NOT_FIXED,
                location = source,
                detail = "-Xms ${JvmCommandLine.humanSize(min)} against -Xmx ${JvmCommandLine.humanSize(max)}.",
            )
        }

        if (max >= COMPRESSED_OOPS_LIMIT) {
            sink.add(
                rule = FlagRules.HUGE_HEAP,
                location = source,
                detail = "-Xmx is ${JvmCommandLine.humanSize(max)}, at or above the 32 GiB point where " +
                    "compressed object pointers stop being used.",
            )
        } else if (max < RECOMMENDED_FLOOR) {
            sink.add(
                rule = FlagRules.HEAP_BELOW_RECOMMENDED,
                location = source,
                detail = "-Xmx is ${JvmCommandLine.humanSize(max)}; the documented floor is 6 GB.",
            )
        }

        hostMemoryBytes?.let { host ->
            if (max > host - HOST_HEADROOM) {
                sink.add(
                    rule = FlagRules.HEAP_OVER_HOST_MEMORY,
                    location = source,
                    detail = "-Xmx ${JvmCommandLine.humanSize(max)} out of ${JvmCommandLine.humanSize(host)} " +
                        "leaves less than ${JvmCommandLine.humanSize(HOST_HEADROOM)} for the JVM's own " +
                        "overhead and the operating system.",
                )
            }
        }
    }

    private fun checkCollectors(command: JvmCommandLine, sink: FindingSink, source: String) {
        val selected = COLLECTORS.filter { command.toggle(it) == true }
        if (selected.size > 1) {
            sink.add(
                rule = FlagRules.MULTIPLE_COLLECTORS,
                location = source,
                detail = "Selected: ${selected.joinToString(", ")}.",
            )
        }

        val cmsFlags = command.tuningFlags.keys.filter { it in CMS_FLAGS }
        if (cmsFlags.isNotEmpty()) {
            sink.add(
                rule = FlagRules.REMOVED_CMS_FLAGS,
                location = source,
                detail = "CMS-era flags present: ${cmsFlags.joinToString(", ")}.",
            )
        }

        val g1Tuning = command.tuningFlags.keys.filter { it.startsWith("G1") }
        val usesG1 = command.toggle("UseG1GC") == true
        val otherCollector = selected.any { it != "UseG1GC" }
        if (g1Tuning.isNotEmpty() && !usesG1 && otherCollector) {
            sink.add(
                rule = FlagRules.TUNING_WITHOUT_G1,
                location = source,
                detail = "${g1Tuning.size} G1 options are set while ${selected.joinToString(", ")} is selected.",
                evidence = g1Tuning.take(6),
            )
        }
    }

    private fun checkSystemProperties(command: JvmCommandLine, sink: FindingSink, source: String) {
        val properties = command.systemProperties
        if (properties["disable.watchdog"]?.equals("true", ignoreCase = true) == true ||
            properties.containsKey("disable.watchdog") && properties["disable.watchdog"].isNullOrEmpty()
        ) {
            sink.add(
                rule = FlagRules.WATCHDOG_DISABLED,
                location = source,
                detail = "-Ddisable.watchdog is set, so Paper will not dump threads or stop a hung server.",
            )
        }
        if (properties["com.mojang.eula.agree"]?.equals("true", ignoreCase = true) == true) {
            sink.add(
                rule = FlagRules.EULA_BY_FLAG,
                location = source,
                detail = "-Dcom.mojang.eula.agree=true replaces eula.txt.",
            )
        }
    }

    /** One finding for the whole documented set, not one per flag: the point is the comparison. */
    private fun checkRecommendedSet(command: JvmCommandLine, sink: FindingSink, source: String) {
        if (command.toggle("UseG1GC") != true) return
        val missing = RECOMMENDED_G1_FLAGS.filterNot { command.hasFlag(it) }
        if (missing.isEmpty()) return
        sink.add(
            rule = FlagRules.MISSING_RECOMMENDED_FLAGS,
            location = source,
            detail = "${missing.size} of ${RECOMMENDED_G1_FLAGS.size} documented options are not set.",
            evidence = missing.take(10),
        )
    }

    private companion object {
        val COLLECTORS = listOf(
            "UseG1GC",
            "UseZGC",
            "UseShenandoahGC",
            "UseParallelGC",
            "UseSerialGC",
            "UseConcMarkSweepGC",
        )

        val CMS_FLAGS = setOf(
            "UseConcMarkSweepGC",
            "UseParNewGC",
            "CMSInitiatingOccupancyFraction",
            "UseCMSInitiatingOccupancyOnly",
            "CMSParallelRemarkEnabled",
            "CMSScavengeBeforeRemark",
            "CMSIncrementalMode",
        )

        /** The set published on Paper's Aikar's-flags page, minus the heap and the -D markers. */
        val RECOMMENDED_G1_FLAGS = listOf(
            "ParallelRefProcEnabled",
            "MaxGCPauseMillis",
            "UnlockExperimentalVMOptions",
            "DisableExplicitGC",
            "AlwaysPreTouch",
            "G1NewSizePercent",
            "G1MaxNewSizePercent",
            "G1HeapRegionSize",
            "G1ReservePercent",
            "G1HeapWastePercent",
            "G1MixedGCCountTarget",
            "InitiatingHeapOccupancyPercent",
            "G1MixedGCLiveThresholdPercent",
            "G1RSetUpdatingPauseTimePercent",
            "SurvivorRatio",
            "PerfDisableSharedMem",
            "MaxTenuringThreshold",
        )

        const val COMPRESSED_OOPS_LIMIT = 32L * 1024 * 1024 * 1024
        const val RECOMMENDED_FLOOR = 6L * 1024 * 1024 * 1024
        const val HOST_HEADROOM = 1000L * 1024 * 1024
    }
}
