package com.salyvn.serverdoctor.plugins

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.core.Severity
import java.time.Duration
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * Audits a plugins directory: what is installed, what is broken about the set, and - when asked - what
 * the public indexes say about where each file came from.
 *
 * The provenance half is opt-in because it is the only thing in this tool that talks to the network.
 * Everything else works on a box with no route out, which is the box people are usually on when a
 * server is down.
 *
 * Two indexes are consulted in order, and the order matters. Modrinth answers to a digest, so it either
 * knows a file or it does not. Hangar has to be asked by name, which can only ever be a weaker claim,
 * so it is asked second and its answers are worded as provenance rather than as identification.
 */
class PluginsAudit(
    private val modrinth: ModrinthClient? = null,
    private val hangar: HangarClient? = null,
) {

    /** Loader names a Paper-family server can load, used to decide what "newer" means. */
    private val platforms = setOf("paper", "folia", "bukkit", "spigot", "purpur")

    fun analyse(index: PluginIndex, subject: String): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()

        val plugins = index.jars.filter { it.isPlugin }
        facts["jars"] = index.jars.size.toString()
        facts["plugins"] = plugins.size.toString()
        val totalBytes = index.jars.sumOf { it.sizeBytes.coerceAtLeast(0) }
        facts["total size"] = "%.1f MiB".format(java.util.Locale.ROOT, totalBytes.toDouble() / (1L shl 20))
        plugins.count { it.descriptor?.foliaSupported == true }.takeIf { it > 0 }?.let {
            facts["declare folia"] = it.toString()
        }

        checkStructure(index, sink)
        checkDescriptors(index, sink)
        checkDependencies(index, sink)
        if (modrinth != null) checkProvenance(plugins, sink, facts, modrinth)

        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = subject,
            subjectKind = "plugins",
            findings = sink.findings(),
            facts = facts,
        )
    }

    private fun checkStructure(index: PluginIndex, sink: FindingSink) {
        for (jar in index.jars) {
            val problem = jar.problem ?: continue
            if (problem.startsWith("not a readable jar")) {
                sink.add(
                    rule = PluginRules.UNREADABLE_JAR,
                    location = jar.fileName,
                    detail = problem,
                )
            } else {
                sink.add(
                    rule = PluginRules.NOT_A_PLUGIN,
                    location = jar.fileName,
                    detail = problem.trimEnd('.') + "." + describeLibrary(jar),
                    evidence = jar.mavenCoordinates.take(3),
                )
            }
        }

        for ((name, jars) in index.duplicateNames()) {
            sink.add(
                rule = PluginRules.DUPLICATE_PLUGIN,
                location = name,
                detail = "${jars.size} jars declare the name $name.",
                evidence = jars.map { "${it.fileName} declares version ${it.descriptor?.version ?: "?"}" },
            )
        }
    }

    /** Maven coordinates or a manifest title make "this is a library" concrete rather than a guess. */
    private fun describeLibrary(jar: PluginJar): String {
        val coordinate = jar.mavenCoordinates.firstOrNull()
        val title = jar.manifest["Implementation-Title"]
        return when {
            coordinate != null -> " It identifies itself as $coordinate."
            title != null -> " Its manifest calls it $title."
            else -> ""
        }
    }

    private fun checkDescriptors(index: PluginIndex, sink: FindingSink) {
        for (jar in index.jars) {
            val descriptor = jar.descriptor ?: continue

            if (descriptor.apiVersion == null && descriptor.kind == "plugin.yml") {
                sink.add(
                    rule = PluginRules.NO_API_VERSION,
                    location = jar.fileName,
                    detail = "${descriptor.name ?: jar.fileName} declares no api-version.",
                )
            }

            if (descriptor.foliaSupported == true) {
                sink.add(
                    rule = PluginRules.FOLIA_CLAIM,
                    location = jar.fileName,
                    detail = "${descriptor.name ?: jar.fileName} declares folia-supported: true.",
                )
            }

            val declared = descriptor.version
            if (declared != null && declared.isNotBlank() && !jar.fileName.contains(declared)) {
                val nameHasVersion = FILENAME_VERSION.containsMatchIn(jar.fileName)
                if (nameHasVersion) {
                    sink.add(
                        rule = PluginRules.VERSION_MISMATCH,
                        location = jar.fileName,
                        detail = "The descriptor says $declared.",
                    )
                }
            }
        }
    }

    private fun checkDependencies(index: PluginIndex, sink: FindingSink) {
        for ((jar, missing) in index.missingDependencies()) {
            sink.add(
                rule = PluginRules.MISSING_DEPENDENCY,
                location = jar.fileName,
                detail = "${jar.displayName} requires ${missing.joinToString(", ")}, which " +
                    if (missing.size == 1) "is not installed." else "are not installed.",
            )
        }
    }

    private fun checkProvenance(
        plugins: List<PluginJar>,
        sink: FindingSink,
        facts: MutableMap<String, String>,
        client: ModrinthClient,
    ) {
        var identified = 0
        var viaHangar = 0
        var unknown = 0

        for (jar in plugins) {
            val match = client.findByHash(jar.sha1)
            if (match == null) {
                when (val fallback = askHangar(jar, sink)) {
                    is HangarLookup.Matched -> {
                        identified++
                        viaHangar++
                        describeHangarMatch(jar, fallback, sink)
                    }

                    else -> {
                        unknown++
                        if (fallback !is HangarLookup.NotAmongVersions) {
                            sink.add(
                                rule = PluginRules.UNKNOWN_ORIGIN,
                                location = jar.fileName,
                                detail = "This exact file is not in the indexes that were queried. That " +
                                    "is expected for a paid or private build.",
                                evidence = listOf("sha1 ${jar.sha1}", "sha256 ${jar.sha256}"),
                            )
                        }
                    }
                }
                continue
            }

            identified++
            describeModrinthMatch(jar, match, client, sink)
        }

        facts["identified by hash"] = "$identified of ${plugins.size}"
        if (viaHangar > 0) facts["identified on hangar"] = viaHangar.toString()
        if (unknown > 0) facts["not in an index"] = unknown.toString()
        val failures = client.failures + (hangar?.failures ?: 0)
        if (failures > 0) facts["lookup failures"] = failures.toString()
    }

    /**
     * Hangar, only for a file the digest-indexed source did not know. The "project exists, this is not
     * one of its builds" answer is reported here rather than by the caller, because it is the only
     * finding in this audit that comes from a name rather than from a hash and it has to say so.
     */
    private fun askHangar(jar: PluginJar, sink: FindingSink): HangarLookup? {
        val client = hangar ?: return null
        val name = jar.descriptor?.name ?: return null
        val lookup = client.lookup(name, jar.sha256)

        if (lookup !is HangarLookup.NotAmongVersions) return lookup

        val declared = jar.descriptor.version
        val samePublishedVersion = declared != null && lookup.versionNames.any { it.equals(declared, true) }

        if (samePublishedVersion) {
            sink.add(
                rule = PluginRules.PUBLISHED_VERSION_DIFFERS,
                location = jar.fileName,
                detail = "${lookup.owner}/${lookup.slug} publishes a version $declared, and the file it " +
                    "publishes is not this file.",
                evidence = listOf(
                    "installed sha256 ${jar.sha256}",
                    "hangar.papermc.io/${lookup.owner}/${lookup.slug}/versions/$declared",
                ),
                provenanceOverride = PluginRules.HANGAR,
            )
            return lookup
        }

        sink.add(
            rule = PluginRules.NOT_A_PUBLISHED_BUILD,
            location = jar.fileName,
            detail = "${lookup.owner}/${lookup.slug} exists on Hangar and none of its " +
                "${lookup.versionsChecked} most recent " +
                (if (lookup.versionsChecked == 1) "file has" else "files have") +
                " this file's digest. It declares ${declared ?: "no version"}; the newest published is " +
                "${lookup.latestVersion ?: "unknown"}.",
            evidence = listOf("installed sha256 ${jar.sha256}"),
            provenanceOverride = PluginRules.HANGAR,
        )
        return lookup
    }

    private fun describeHangarMatch(jar: PluginJar, match: HangarLookup.Matched, sink: FindingSink) {
        val where = "${match.owner}/${match.slug}"

        if (match.latestVersion != null && match.latestVersion != match.version) {
            sink.add(
                rule = PluginRules.OUTDATED,
                location = jar.fileName,
                detail = "$where ${match.version} is installed; ${match.latestVersion} is published on " +
                    "Hangar.",
                evidence = listOfNotNull(
                    match.gameVersions.takeIf { it.isNotEmpty() }
                        ?.let { "installed build targets ${it.joinToString(", ")}" },
                    match.channel?.let { "channel $it" },
                ),
                provenanceOverride = PluginRules.HANGAR,
            )
        }

        match.projectUpdated?.let { updated ->
            monthsSince(updated)?.let { months ->
                if (months >= STALE_MONTHS) {
                    sink.add(
                        rule = PluginRules.UPSTREAM_STALE,
                        location = jar.fileName,
                        detail = "$where last published $months months ago ($updated).",
                        severityOverride = Severity.INFO,
                        provenanceOverride = PluginRules.HANGAR,
                    )
                }
            }
        }
    }

    private fun describeModrinthMatch(
        jar: PluginJar,
        match: VersionMatch,
        client: ModrinthClient,
        sink: FindingSink,
    ) {
        val project = client.project(match.projectId, platforms)
        val projectName = project?.title ?: match.projectId

        if (project?.status?.lowercase() in ARCHIVED_STATUSES) {
            sink.add(
                rule = PluginRules.UPSTREAM_ARCHIVED,
                location = jar.fileName,
                detail = "$projectName is marked ${project?.status} upstream.",
            )
        }

        val latest = project?.latestForPlatform
        if (latest != null && latest != match.versionNumber) {
            sink.add(
                rule = PluginRules.OUTDATED,
                location = jar.fileName,
                detail = "$projectName ${match.versionNumber} is installed; $latest is published.",
                evidence = listOfNotNull(
                    match.gameVersions.takeIf { it.isNotEmpty() }
                        ?.let { "installed build targets ${it.joinToString(", ")}" },
                ),
            )
        }

        project?.updated?.let { updated ->
            monthsSince(updated)?.let { months ->
                if (months >= STALE_MONTHS) {
                    sink.add(
                        rule = PluginRules.UPSTREAM_STALE,
                        location = jar.fileName,
                        detail = "$projectName last published $months months ago ($updated).",
                        severityOverride = Severity.INFO,
                    )
                }
            }
        }
    }

    private fun monthsSince(timestamp: String): Long? = try {
        val then = Instant.parse(timestamp)
        Duration.between(then, Instant.now()).toDays() / 30
    } catch (_: DateTimeParseException) {
        null
    }

    private companion object {
        val ARCHIVED_STATUSES = setOf("archived", "deprecated", "withheld", "rejected")

        /** A file name that already carries a version, so a mismatch is worth mentioning. */
        val FILENAME_VERSION = Regex("""[-_]v?\d+\.\d+""")

        const val STALE_MONTHS = 18L
    }
}
