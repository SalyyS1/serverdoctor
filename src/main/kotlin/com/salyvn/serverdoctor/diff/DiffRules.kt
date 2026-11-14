package com.salyvn.serverdoctor.diff

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.Severity

/**
 * Rules about the difference between two servers.
 *
 * These rules do not say that either side is wrong, because a diff cannot know that: the reason to run
 * one is that a staging box works and a production box does not, or that one node in a network behaves
 * unlike its siblings. So the severities are low by design and the value is in the list, not the
 * verdict - with one exception. Two files that claim the same plugin and the same version and are not
 * the same bytes is not a difference of opinion, and that is reported as one.
 */
object DiffRules {

    val VALUE_DIFFERS = Rule(
        id = "D001",
        area = RuleArea.DIFF,
        severity = Severity.INFO,
        title = "A setting is set to different values",
        rationale = "The keys both servers have and disagree on. On two boxes that are supposed to be " +
            "the same, this list is the whole answer.",
        provenance = "Both files read here and compared key by key",
        fix = null,
    )

    val KEY_ON_ONE_SIDE = Rule(
        id = "D002",
        area = RuleArea.DIFF,
        severity = Severity.INFO,
        title = "A setting exists on only one side",
        rationale = "A key present on one server and absent on the other usually means different " +
            "versions of the same file, so one of the two is running on a default nobody chose.",
        provenance = "Both files read here and compared key by key",
        fix = "Check which release each file came from before copying keys between them.",
    )

    val FILE_ON_ONE_SIDE = Rule(
        id = "D003",
        area = RuleArea.DIFF,
        severity = Severity.INFO,
        title = "A configuration file exists on only one side",
        rationale = "Which files a server has says which fork and which generation it is. A file on one " +
            "side only is either a fork-specific config or a leftover.",
        provenance = "Read from both directories",
        fix = null,
    )

    val PLUGIN_ON_ONE_SIDE = Rule(
        id = "D004",
        area = RuleArea.DIFF,
        severity = Severity.WARNING,
        title = "A plugin is installed on only one side",
        rationale = "The first thing to know when one server misbehaves and the other does not.",
        provenance = "Both plugins directories read here; matched on the name each jar declares",
        fix = null,
    )

    val PLUGIN_VERSION_DIFFERS = Rule(
        id = "D005",
        area = RuleArea.DIFF,
        severity = Severity.WARNING,
        title = "One plugin is at two different versions",
        rationale = "A version gap between two servers explains behaviour that looks impossible, and it " +
            "is invisible from a file listing when the file names match.",
        provenance = "The version each jar's descriptor declares",
        fix = "Bring both to one version before comparing anything else.",
    )

    val PLUGIN_SAME_VERSION_DIFFERENT_FILE = Rule(
        id = "D006",
        area = RuleArea.DIFF,
        severity = Severity.WARNING,
        title = "One plugin version, two different files",
        rationale = "Two jars claim the same plugin and the same version and do not have the same bytes. " +
            "One of them was rebuilt, patched, repacked or replaced, and the version number no longer " +
            "identifies what is running.",
        provenance = "SHA-1 of both files, computed here",
        fix = "Establish which file came from the author - by hash, against the download - and replace " +
            "the other.",
    )

    val FLAGS_DIFFER = Rule(
        id = "D007",
        area = RuleArea.DIFF,
        severity = Severity.INFO,
        title = "The two servers start with different JVM flags",
        rationale = "Heap size, collector and system properties decide how a server behaves under load " +
            "more than most of its configuration does.",
        provenance = "The start script found in each directory",
        fix = null,
    )

    val all: List<Rule> = listOf(
        VALUE_DIFFERS,
        KEY_ON_ONE_SIDE,
        FILE_ON_ONE_SIDE,
        PLUGIN_ON_ONE_SIDE,
        PLUGIN_VERSION_DIFFERS,
        PLUGIN_SAME_VERSION_DIFFERENT_FILE,
        FLAGS_DIFFER,
    )
}
