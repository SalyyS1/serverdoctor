package com.salyvn.serverdoctor.flags

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.Severity

/**
 * Rules about the JVM command line.
 *
 * Two sources, kept apart on purpose. Facts about the server come from Paper's own code - a system
 * property that turns the watchdog off does exactly what the field reading it says it does. Advice
 * about garbage collection comes from Paper's documented flag set, and is reported as advice: a
 * missing tuning flag is INFO, never a defect, because the person running the server may have
 * measured something this tool cannot see.
 */
object FlagRules {

    private const val AIKAR = "PaperMC/docs src/content/docs/paper/admin/how-to/aikars-flags.md"
    private const val WATCHDOG = "PaperMC/Paper paper-server/src/main/java/org/spigotmc/WatchdogThread.java:16"
    private const val EULA = "PaperMC/Paper paper-server/patches/sources/net/minecraft/server/Main.java.patch:76-80"

    val HEAP_NOT_FIXED = Rule(
        id = "F001",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "-Xms and -Xmx differ",
        rationale = "A heap that grows is a heap the collector keeps resizing, and the memory between " +
            "the two numbers is reserved from the host either way. Paper's documented flags set both " +
            "to the same value for that reason.",
        provenance = "$AIKAR:67",
        fix = "Set -Xms to the same value as -Xmx.",
    )

    val NO_MAX_HEAP = Rule(
        id = "F002",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "No -Xmx, so the heap size is whatever the JVM guesses",
        rationale = "Without it the JVM picks a maximum from the memory it can see, which on a shared " +
            "or containerised host is not the memory this server may use. The number then changes " +
            "when the host does, with no edit to any file.",
        provenance = "JVM ergonomics: the default maximum heap is a fraction of observed physical memory",
        fix = "Set -Xms and -Xmx explicitly to what this server is allowed to use.",
    )

    val WATCHDOG_DISABLED = Rule(
        id = "F003",
        area = RuleArea.FLAGS,
        severity = Severity.CRITICAL,
        title = "The watchdog is switched off",
        rationale = "disable.watchdog stops Paper from dumping threads and ending a hung server. A " +
            "deadlock then presents as a server that is up, accepts connections and never ticks, " +
            "and no diagnosis is written to the log.",
        provenance = WATCHDOG,
        fix = "Remove -Ddisable.watchdog and fix the hang it was hiding.",
    )

    val EULA_BY_FLAG = Rule(
        id = "F004",
        area = RuleArea.FLAGS,
        severity = Severity.INFO,
        title = "The EULA is accepted by a command-line flag",
        rationale = "Paper accepts -Dcom.mojang.eula.agree=true in place of eula.txt and warns three " +
            "times in the log when it is used. Worth noticing on a server somebody else set up, " +
            "because the agreement was made by whoever wrote the start script.",
        provenance = EULA,
        fix = null,
    )

    val MULTIPLE_COLLECTORS = Rule(
        id = "F005",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "More than one garbage collector is selected",
        rationale = "The JVM resolves this itself, and which one wins is not something the start " +
            "script says. Whatever tuning follows was written for one of them.",
        provenance = "Collector selection flags are mutually exclusive by definition",
        fix = "Keep exactly one collector flag.",
    )

    val REMOVED_CMS_FLAGS = Rule(
        id = "F006",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "Flags for a collector that no longer exists",
        rationale = "The Concurrent Mark Sweep collector was removed in Java 14. Its flags are copied " +
            "between start scripts long after they stopped doing anything, and on a modern JVM they " +
            "either fail the launch or are ignored.",
        provenance = "JEP 363: Remove the Concurrent Mark Sweep (CMS) Garbage Collector, delivered in JDK 14",
        fix = "Delete them and use the documented G1 set instead.",
    )

    val HUGE_HEAP = Rule(
        id = "F007",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "The heap is large enough to lose compressed object pointers",
        rationale = "Above roughly 32 GiB the JVM can no longer compress object references, so every " +
            "reference gets wider and the effective capacity gain is much smaller than the number " +
            "suggests.",
        provenance = "HotSpot uses compressed oops only below a ~32 GiB heap",
        fix = "Either stay below 32 GiB, or accept that the extra memory buys less than it looks like.",
    )

    val MISSING_RECOMMENDED_FLAGS = Rule(
        id = "F008",
        area = RuleArea.FLAGS,
        severity = Severity.INFO,
        title = "Some of Paper's documented G1 flags are not set",
        rationale = "Reported as information, not as a fault. The documented set is a good default for " +
            "a Minecraft heap; a server that was tuned deliberately may differ from it on purpose.",
        provenance = "$AIKAR:17",
        fix = "Compare against the published command line if garbage collection pauses are a problem.",
    )

    val TUNING_WITHOUT_G1 = Rule(
        id = "F009",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "G1 tuning flags with a different collector selected",
        rationale = "G1-prefixed options do nothing under ZGC, Shenandoah or Parallel. The command line " +
            "then reads as tuned while none of the tuning applies.",
        provenance = "$AIKAR:17",
        fix = "Either select G1 or drop the G1-specific flags.",
    )

    val HEAP_BELOW_RECOMMENDED = Rule(
        id = "F010",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "The heap is smaller than Paper's documented floor",
        rationale = "Paper's guidance is 6-10 GB regardless of player count, because the heap is sized " +
            "by world and plugin data rather than by how many people are online.",
        provenance = "$AIKAR:36",
        fix = "Give it more, or expect collection pauses under any real chunk load.",
    )

    val HEAP_OVER_HOST_MEMORY = Rule(
        id = "F011",
        area = RuleArea.FLAGS,
        severity = Severity.CRITICAL,
        title = "The heap leaves the host too little memory",
        rationale = "The JVM needs memory beyond the heap for thread stacks, metaspace, direct buffers " +
            "and the operating system. When -Xmx alone approaches the machine's total, the process " +
            "gets killed from outside and the log ends mid-line with no error.",
        provenance = "$AIKAR:22-25",
        fix = "Reduce -Xmx to leave 1000-1500 MB for everything else.",
    )

    val NO_JAVA_COMMAND_FOUND = Rule(
        id = "F012",
        area = RuleArea.FLAGS,
        severity = Severity.INFO,
        title = "No java command line could be read",
        rationale = "Reported instead of guessing. A panel-managed server keeps its flags outside the " +
            "directory, and an argument file referenced by @file is not followed.",
        provenance = "Parsed from the file or string given on the command line",
        fix = "Pass the command line directly with --command, or point at the script that runs java.",
    )

    val ZGC_HEADROOM_OR_LEGACY = Rule(
        id = "F013",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "ZGC is enabled without generational mode or sufficient heap headroom",
        rationale = "ZGC collects concurrently while server tick threads continue allocating. Disabling " +
            "generational ZGC (-XX:-ZGenerational), setting SoftMaxHeapSize above -Xmx, or running ZGC " +
            "on a tight heap below 8 GiB starves concurrent relocation under chunk generation and " +
            "forces tick threads into Allocation Stall pauses.",
        provenance = "JEP 439 (Generational ZGC in JDK 21) and JEP 474 (Generational ZGC default in JDK 23)",
        fix = "Enable -XX:+ZGenerational on JDK 21-22, allocate at least 8 to 12 GiB with -Xms equal " +
            "to -Xmx, and keep SoftMaxHeapSize at or below -Xmx.",
    )

    val G1_PAUSE_OR_BOUNDS_INVALID = Rule(
        id = "F014",
        area = RuleArea.FLAGS,
        severity = Severity.WARNING,
        title = "G1GC pause target or young-generation bounds are counterproductive",
        rationale = "Setting MaxGCPauseMillis below 25 ms forces G1 into tiny Eden regions and constant " +
            "evacuations, while values above 250 ms permit multi-tick freezes. Setting G1NewSizePercent " +
            "above G1MaxNewSizePercent is rejected by HotSpot before the server even starts.",
        provenance = "OpenJDK HotSpot G1Arguments::initialize and PaperMC/docs aikars-flags.md " +
            "(MaxGCPauseMillis=200, G1NewSizePercent=30..40)",
        fix = "Keep MaxGCPauseMillis between 50 and 200 ms and ensure G1NewSizePercent is less than or " +
            "equal to G1MaxNewSizePercent.",
    )

    val all: List<Rule> = listOf(
        HEAP_NOT_FIXED,
        NO_MAX_HEAP,
        WATCHDOG_DISABLED,
        EULA_BY_FLAG,
        MULTIPLE_COLLECTORS,
        REMOVED_CMS_FLAGS,
        HUGE_HEAP,
        MISSING_RECOMMENDED_FLAGS,
        TUNING_WITHOUT_G1,
        HEAP_BELOW_RECOMMENDED,
        HEAP_OVER_HOST_MEMORY,
        NO_JAVA_COMMAND_FOUND,
        ZGC_HEADROOM_OR_LEGACY,
        G1_PAUSE_OR_BOUNDS_INVALID,
    )
}
