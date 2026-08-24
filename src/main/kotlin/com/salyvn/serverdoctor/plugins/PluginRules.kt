package com.salyvn.serverdoctor.plugins

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.Severity

/**
 * Rules about what is actually installed in a `plugins/` directory.
 *
 * The honest limit of this audit is worth stating at the top, because it shapes every rule below:
 * almost everything a jar says about itself is self-declared and therefore only as reliable as its
 * author. The one exception is its hash, which is why provenance findings key on that and why nothing
 * here claims a plugin is "safe" or "genuine". The most it can say is "this file is byte-for-byte a
 * build published under that name" or "nothing recognised this file".
 */
object PluginRules {

    private const val MODRINTH = "Modrinth API v2 GET /version_file/{sha1}, verified 2026-08-24"
    private const val MANAGER = "PaperMC/Paper paper-api/src/main/java/org/bukkit/plugin/SimplePluginManager.java"
    private const val MAGIC = "PaperMC/Paper paper-server/src/main/java/org/bukkit/craftbukkit/util/CraftMagicNumbers.java"
    private const val FOLIA_PATCH = "PaperMC/Folia folia-api/paper-patches/features/0003-Require-plugins-to-be-explicitly-marked-as-Folia-sup.patch:42-51"

    val MISSING_DEPENDENCY = Rule(
        id = "P001",
        area = RuleArea.PLUGINS,
        severity = Severity.BLOCKER,
        title = "A hard dependency is not installed",
        rationale = "A plugin listing another under depend: does not load without it, and the server " +
            "says so in one line of a start-up log thousands of lines long.",
        provenance = "$MANAGER:390 and the depend: contract in the plugin descriptor",
        fix = "Install the named plugin, or remove the one that needs it.",
    )

    val DUPLICATE_PLUGIN = Rule(
        id = "P002",
        area = RuleArea.PLUGINS,
        severity = Severity.BLOCKER,
        title = "Two jars declare the same plugin name",
        rationale = "The server loads one and refuses the other, and which one it picks is not " +
            "something the operator chose. This is what an update that was copied rather than " +
            "replaced leaves behind.",
        provenance = "$MANAGER:198,208",
        fix = "Delete the copy you do not want. Compare versions before choosing.",
    )

    val NOT_A_PLUGIN = Rule(
        id = "P003",
        area = RuleArea.PLUGINS,
        severity = Severity.WARNING,
        title = "A jar in plugins/ is not a plugin",
        rationale = "No plugin.yml and no paper-plugin.yml, so the server ignores it. It is usually a " +
            "library another plugin expects on the classpath, or a mod downloaded by mistake.",
        provenance = "Read from the jar: neither descriptor is present",
        fix = "If a plugin documented it as a required library, leave it. Otherwise remove it.",
    )

    val UNREADABLE_JAR = Rule(
        id = "P004",
        area = RuleArea.PLUGINS,
        severity = Severity.CRITICAL,
        title = "A jar cannot be read",
        rationale = "A truncated or corrupt archive fails at load. It is the normal result of a " +
            "download that was interrupted, or of a file copied while the server held it open.",
        provenance = "Read from the jar: the zip central directory could not be parsed",
        fix = "Download it again and compare the file size against the source.",
    )

    val VERSION_MISMATCH = Rule(
        id = "P005",
        area = RuleArea.PLUGINS,
        severity = Severity.INFO,
        title = "The file name disagrees with the declared version",
        rationale = "Harmless to the server, which reads the descriptor and ignores the name. It " +
            "matters to the human who is about to conclude which version is installed by looking at " +
            "the directory listing.",
        provenance = "Compared: the version in the descriptor against the version in the file name",
        fix = "Rename the file to match, so the next person to look is not misled.",
    )

    val NO_API_VERSION = Rule(
        id = "P006",
        area = RuleArea.PLUGINS,
        severity = Severity.WARNING,
        title = "A plugin declares no api-version",
        rationale = "The server runs it in legacy mode and translates materials and data values for " +
            "it. The translation is lossy and is not maintained for content added since 1.13.",
        provenance = "$MAGIC:407",
        fix = "Ask the author for a build that declares api-version, or replace the plugin.",
    )

    val FOLIA_CLAIM = Rule(
        id = "P007",
        area = RuleArea.PLUGINS,
        severity = Severity.INFO,
        title = "A plugin declares Folia support",
        rationale = "folia-supported: true is the only thing Folia checks at load, and it is a claim " +
            "by the author rather than a verified property. A jar can carry it and still call the " +
            "legacy scheduler on its first tick.",
        provenance = FOLIA_PATCH,
        fix = "On Folia, treat the declaration as a starting point and check the scheduler calls.",
    )

    val UNKNOWN_ORIGIN = Rule(
        id = "P008",
        area = RuleArea.PLUGINS,
        severity = Severity.INFO,
        title = "No public source recognised this file",
        rationale = "Says only what it says: the hash is not in the index that was queried. Paid " +
            "plugins, private builds and anything from a forum attachment are all expected to land " +
            "here, so this is not a safety finding. It is a gap in provenance.",
        provenance = MODRINTH,
        fix = "For a plugin you expect to be public, check you downloaded it from where you think " +
            "you did.",
    )

    val OUTDATED = Rule(
        id = "P009",
        area = RuleArea.PLUGINS,
        severity = Severity.WARNING,
        title = "A newer published version exists",
        rationale = "The installed file was matched by hash to a published build, and the project has " +
            "released a later one since.",
        provenance = MODRINTH,
        fix = "Read the changelog before updating: on a live server, a version jump is a change too.",
    )

    val UPSTREAM_ARCHIVED = Rule(
        id = "P010",
        area = RuleArea.PLUGINS,
        severity = Severity.WARNING,
        title = "The project it came from is archived or deprecated",
        rationale = "The publisher has marked it as no longer maintained. It will not be fixed for the " +
            "next Minecraft version, which makes it the thing that blocks the next upgrade.",
        provenance = "$MODRINTH — the project's own status field",
        fix = "Plan a replacement before the next version bump rather than during it.",
    )

    val UPSTREAM_STALE = Rule(
        id = "P011",
        area = RuleArea.PLUGINS,
        severity = Severity.INFO,
        title = "Nothing has been published for a long time",
        rationale = "Reported as a date, not as a verdict. Plenty of finished plugins need no changes " +
            "for years; the point is to know which of your dependencies is in that category before " +
            "you need a fix from one.",
        provenance = "$MODRINTH — the project's own updated timestamp",
        fix = null,
    )

    val all: List<Rule> = listOf(
        MISSING_DEPENDENCY,
        DUPLICATE_PLUGIN,
        NOT_A_PLUGIN,
        UNREADABLE_JAR,
        VERSION_MISMATCH,
        NO_API_VERSION,
        FOLIA_CLAIM,
        UNKNOWN_ORIGIN,
        OUTDATED,
        UPSTREAM_ARCHIVED,
        UPSTREAM_STALE,
    )
}
