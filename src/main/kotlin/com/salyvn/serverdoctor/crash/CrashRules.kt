package com.salyvn.serverdoctor.crash

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.Severity

/**
 * Rules about the crash reports a server left behind.
 *
 * A crash report is the one artefact that describes a failure from the inside, and it survives the
 * server that produced it: the flags, the game version and the trace are all in the file, so a report
 * mailed by a host is enough to work from. These rules read what the report states and stop there.
 * Nothing here infers a cause from a stack trace beyond naming the first frame that is not the server's
 * own code, because that inference is where crash triage usually goes wrong.
 */
object CrashRules {

    val CRASHED = Rule(
        id = "X001",
        area = RuleArea.CRASH,
        severity = Severity.CRITICAL,
        title = "The server crashed",
        rationale = "The report exists because the server stopped in a way it could not recover from. " +
            "The description and the first frames say what it was doing at the time, which is the part " +
            "that gets lost when only the tail of the console is kept.",
        provenance = "The report's own Description, Time and the first frames of its trace",
        fix = "Work from the frame this names rather than from the last console line before the stop.",
    )

    val PLUGIN_IN_TRACE = Rule(
        id = "X002",
        area = RuleArea.CRASH,
        severity = Severity.CRITICAL,
        title = "A plugin's code is in the crash trace",
        rationale = "The server, the JDK and Netty are all present in every trace. A frame that belongs " +
            "to none of them is code the server was running on someone else's behalf, and it is the " +
            "first thing to test with by removing it.",
        provenance = "The first frame of the report's trace outside the server, JDK and Netty packages",
        fix = "Reproduce with that plugin removed. If the crash stops, report it upstream with this file.",
    )

    val OUT_OF_MEMORY = Rule(
        id = "X003",
        area = RuleArea.CRASH,
        severity = Severity.CRITICAL,
        title = "The crash was out of memory",
        rationale = "An OutOfMemoryError is thrown wherever the next allocation happened to be, so the " +
            "trace names a bystander rather than a cause. The heap size at the time is in this same " +
            "report, and it is the number to look at first.",
        provenance = "java.lang.OutOfMemoryError named in the report, with the Memory and JVM Flags lines",
        fix = "Compare the heap in this report against what the host has. If the heap was already " +
            "generous, look for what grew rather than raising it again.",
    )

    val TICKING_OBJECT = Rule(
        id = "X004",
        area = RuleArea.CRASH,
        severity = Severity.WARNING,
        title = "The crash happened while ticking one specific object",
        rationale = "The report names the entity, block entity or chunk being ticked. That object is " +
            "still saved in the world, so the same crash happens again as soon as it is loaded - which " +
            "is why a restart appears to fix it until somebody walks back there.",
        provenance = "The report's Description and its Entity/Block entity being ticked section",
        fix = "Note the coordinates from the section below and remove or repair that object before the " +
            "chunk is loaded again.",
    )

    val REPEATED_CRASH = Rule(
        id = "X005",
        area = RuleArea.CRASH,
        severity = Severity.CRITICAL,
        title = "The same crash was written more than once",
        rationale = "Several reports with one description is a loop rather than an accident: the server " +
            "is being restarted into the same failure, and each attempt writes the world again.",
        provenance = "The crash-reports directory: more than one report shares a Description",
        fix = "Stop restarting until the cause is out of the way. Take a copy of the world now, while " +
            "the reports still agree.",
    )

    val UNREADABLE = Rule(
        id = "X006",
        area = RuleArea.CRASH,
        severity = Severity.WARNING,
        title = "A crash report could not be read",
        rationale = "A report that cannot be read is still evidence that something wrote it. Reading it " +
            "failed here, so nothing in it was audited.",
        provenance = "Read from this directory; the message is the reason the read stopped",
        fix = "Check the file's encoding and permissions, then open it by hand.",
    )

    val all: List<Rule> = listOf(
        CRASHED,
        PLUGIN_IN_TRACE,
        OUT_OF_MEMORY,
        TICKING_OBJECT,
        REPEATED_CRASH,
        UNREADABLE,
    )
}
