package com.salyvn.serverdoctor.diff

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.flags.JvmCommandLine
import com.salyvn.serverdoctor.plugins.PluginJar

/**
 * Compares two servers.
 *
 * Findings are worded as "left has X, right has Y" and never as "right is wrong", because the tool has
 * no way to know which side is the good one. Keys that are expected to differ between two machines -
 * ports, addresses, secrets, the seed - are skipped, because a diff that lists them buries the ones
 * that matter.
 */
class ServerDiff {

    fun compare(left: ServerSnapshot, right: ServerSnapshot): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()

        facts["left"] = left.root.toString()
        facts["right"] = right.root.toString()
        facts["plugins"] = "${left.plugins.size} against ${right.plugins.size}"

        compareMap("server.properties", left.properties, right.properties, left, right, sink)
        compareConfigFiles(left, right, sink)
        comparePlugins(left, right, sink)
        compareFlags(left, right, sink, facts)

        facts["differences"] = sink.findings().size.toString()

        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = "${left.label} against ${right.label}",
            subjectKind = "diff",
            findings = sink.findings(),
            facts = facts,
        )
    }

    private fun compareConfigFiles(left: ServerSnapshot, right: ServerSnapshot, sink: FindingSink) {
        val names = (left.configFiles.keys + right.configFiles.keys).sorted()
        for (name in names) {
            val onLeft = left.configFiles[name]
            val onRight = right.configFiles[name]
            when {
                onLeft == null -> sink.add(
                    rule = DiffRules.FILE_ON_ONE_SIDE,
                    location = name,
                    detail = "Only ${right.label} has $name (${onRight!!.size} values).",
                )

                onRight == null -> sink.add(
                    rule = DiffRules.FILE_ON_ONE_SIDE,
                    location = name,
                    detail = "Only ${left.label} has $name (${onLeft.size} values).",
                )

                else -> compareMap(name, onLeft, onRight, left, right, sink)
            }
        }
    }

    private fun compareMap(
        file: String,
        onLeft: Map<String, String>,
        onRight: Map<String, String>,
        left: ServerSnapshot,
        right: ServerSnapshot,
        sink: FindingSink,
    ) {
        val differing = mutableListOf<String>()
        val leftOnly = mutableListOf<String>()
        val rightOnly = mutableListOf<String>()

        for (key in (onLeft.keys + onRight.keys).sorted()) {
            if (isExpectedToDiffer(key)) continue
            val a = onLeft[key]
            val b = onRight[key]
            when {
                a == null -> rightOnly += "$key = $b"
                b == null -> leftOnly += "$key = $a"
                a != b -> differing += "$key: $a against $b"
            }
        }

        if (differing.isNotEmpty()) {
            sink.add(
                rule = DiffRules.VALUE_DIFFERS,
                location = file,
                detail = "${count(differing.size, "value")} ${verb(differing.size, "differ")} in $file " +
                    "(${left.label} against ${right.label}).",
                evidence = differing.take(MAX_EVIDENCE),
            )
        }
        if (leftOnly.isNotEmpty()) {
            sink.add(
                rule = DiffRules.KEY_ON_ONE_SIDE,
                location = file,
                detail = "${count(leftOnly.size, "key")} in $file ${verb(leftOnly.size, "exist")} " +
                    "only on ${left.label}.",
                evidence = leftOnly.take(MAX_EVIDENCE),
            )
        }
        if (rightOnly.isNotEmpty()) {
            sink.add(
                rule = DiffRules.KEY_ON_ONE_SIDE,
                location = file,
                detail = "${count(rightOnly.size, "key")} in $file ${verb(rightOnly.size, "exist")} " +
                    "only on ${right.label}.",
                evidence = rightOnly.take(MAX_EVIDENCE),
            )
        }
    }

    private fun comparePlugins(left: ServerSnapshot, right: ServerSnapshot, sink: FindingSink) {
        val names = (left.pluginsByName.keys + right.pluginsByName.keys).sorted()
        val leftOnly = mutableListOf<PluginJar>()
        val rightOnly = mutableListOf<PluginJar>()

        for (name in names) {
            val a = left.pluginsByName[name]
            val b = right.pluginsByName[name]
            when {
                b == null -> leftOnly += a!!
                a == null -> rightOnly += b
                else -> comparePlugin(a, b, left, right, sink)
            }
        }

        if (leftOnly.isNotEmpty()) {
            sink.add(
                rule = DiffRules.PLUGIN_ON_ONE_SIDE,
                location = left.label,
                detail = "${count(leftOnly.size, "plugin")} only on ${left.label}: " +
                    leftOnly.take(NAMES_IN_DETAIL).joinToString(", ") { it.displayName } + ".",
                evidence = leftOnly.map { "${it.displayName} ${it.descriptor?.version ?: "?"} (${it.fileName})" },
            )
        }
        if (rightOnly.isNotEmpty()) {
            sink.add(
                rule = DiffRules.PLUGIN_ON_ONE_SIDE,
                location = right.label,
                detail = "${count(rightOnly.size, "plugin")} only on ${right.label}: " +
                    rightOnly.take(NAMES_IN_DETAIL).joinToString(", ") { it.displayName } + ".",
                evidence = rightOnly.map { "${it.displayName} ${it.descriptor?.version ?: "?"} (${it.fileName})" },
            )
        }
    }

    private fun comparePlugin(
        a: PluginJar,
        b: PluginJar,
        left: ServerSnapshot,
        right: ServerSnapshot,
        sink: FindingSink,
    ) {
        val versionA = a.descriptor?.version
        val versionB = b.descriptor?.version

        if (versionA != versionB) {
            sink.add(
                rule = DiffRules.PLUGIN_VERSION_DIFFERS,
                location = a.displayName,
                detail = "${a.displayName}: ${versionA ?: "no version"} on ${left.label}, " +
                    "${versionB ?: "no version"} on ${right.label}.",
                evidence = listOf(
                    "${left.label}: ${a.fileName} ${versionA ?: ""} sha1 ${a.sha1.take(SHA_PREFIX)}".trim(),
                    "${right.label}: ${b.fileName} ${versionB ?: ""} sha1 ${b.sha1.take(SHA_PREFIX)}".trim(),
                ),
            )
            return
        }

        // Same declared version, different bytes. Only reported when both hashes were computed, so a
        // file that could not be read never becomes an accusation.
        if (a.sha1.isNotEmpty() && b.sha1.isNotEmpty() && a.sha1 != b.sha1) {
            sink.add(
                rule = DiffRules.PLUGIN_SAME_VERSION_DIFFERENT_FILE,
                location = a.displayName,
                detail = "${a.displayName} ${versionA ?: "with no declared version"} is a different file " +
                    "on each side.",
                evidence = listOf(
                    "${left.label}: ${a.fileName} ${a.sizeBytes} bytes sha1 ${a.sha1}",
                    "${right.label}: ${b.fileName} ${b.sizeBytes} bytes sha1 ${b.sha1}",
                ),
            )
        }
    }

    private fun compareFlags(
        left: ServerSnapshot,
        right: ServerSnapshot,
        sink: FindingSink,
        facts: MutableMap<String, String>,
    ) {
        val a = left.flags
        val b = right.flags
        left.flagsSource?.let { facts["left start script"] = it }
        right.flagsSource?.let { facts["right start script"] = it }
        if (a == null || b == null) return

        val differences = mutableListOf<String>()

        if (a.maxHeapBytes != b.maxHeapBytes) {
            differences += "-Xmx: ${size(a.maxHeapBytes)} against ${size(b.maxHeapBytes)}"
        }
        if (a.initialHeapBytes != b.initialHeapBytes) {
            differences += "-Xms: ${size(a.initialHeapBytes)} against ${size(b.initialHeapBytes)}"
        }
        if (a.collectorFlag != b.collectorFlag) {
            differences += "collector: ${a.collectorFlag ?: "JVM default"} against ${b.collectorFlag ?: "JVM default"}"
        }

        for (name in (a.tuningFlags.keys + b.tuningFlags.keys).sorted()) {
            val left1 = a.tuningFlags[name]
            val right1 = b.tuningFlags[name]
            if (left1 == right1) continue
            differences += "-XX:$name: ${left1 ?: "not set"} against ${right1 ?: "not set"}"
        }

        for (name in (a.systemProperties.keys + b.systemProperties.keys).sorted()) {
            val left1 = a.systemProperties[name]
            val right1 = b.systemProperties[name]
            if (left1 == right1) continue
            differences += "-D$name: ${left1 ?: "not set"} against ${right1 ?: "not set"}"
        }

        if (differences.isEmpty()) return
        sink.add(
            rule = DiffRules.FLAGS_DIFFER,
            location = listOfNotNull(left.flagsSource, right.flagsSource).joinToString(" against "),
            detail = "${count(differences.size, "difference")} between the two command " +
                "lines (${left.label} against ${right.label}).",
            evidence = differences.take(MAX_EVIDENCE),
        )
    }

    private fun size(bytes: Long?): String = bytes?.let { JvmCommandLine.humanSize(it) } ?: "not set"

    private fun count(count: Int, noun: String) = "$count $noun${if (count == 1) "" else "s"}"

    /** `differs` for one, `differ` for several, so a finding reads as a sentence either way. */
    private fun verb(count: Int, stem: String) = if (count == 1) "${stem}s" else stem

    /**
     * Keys two machines are supposed to disagree on. A diff that reports the port and the seed trains
     * whoever reads it to skip the list.
     */
    private fun isExpectedToDiffer(key: String): Boolean = EXPECTED.any { key.contains(it, ignoreCase = true) }

    private companion object {
        const val MAX_EVIDENCE = 25
        const val NAMES_IN_DETAIL = 6
        const val SHA_PREFIX = 12

        val EXPECTED = listOf(
            "server-port",
            "query.port",
            "rcon.port",
            "rcon.password",
            "server-ip",
            "level-seed",
            "motd",
            "secret",
            "token",
            "password",
            "bstats",
            "uuid",
        )
    }
}
