package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.Severity

/**
 * What a server log says when something is wrong.
 *
 * Every rule keys on a string the server itself emits, and its provenance names the file and line
 * that emits it. That matters more here than anywhere else in the tool: a log line is the only
 * evidence available after a crash, and a signature copied from a forum post is how a diagnosis ends
 * up confidently wrong. Where the string comes from a fork rather than from Paper, the rule says so.
 */
object LogRules {

    private const val WATCHDOG = "PaperMC/Paper paper-server/src/main/java/org/spigotmc/WatchdogThread.java:78-84"
    private const val ASYNC = "PaperMC/Paper paper-server/src/main/java/org/spigotmc/AsyncCatcher.java"
    private const val MANAGER = "PaperMC/Paper paper-api/src/main/java/org/bukkit/plugin/SimplePluginManager.java"
    private const val MAGIC = "PaperMC/Paper paper-server/src/main/java/org/bukkit/craftbukkit/util/CraftMagicNumbers.java"
    private const val FOLIA = "PaperMC/Folia folia-server/paper-patches/features/0001-Region-Threading-Base.patch:737,4076"
    private const val TICK_LOOP = "PaperMC/Paper paper-server/patches/sources/net/minecraft/server/MinecraftServer.java.patch:810-831 (the vanilla warning is deleted)"
    private const val BIND = "PaperMC/Paper paper-server/patches/sources/net/minecraft/server/dedicated/DedicatedServer.java.patch:157-160"
    private const val EULA_SRC = "PaperMC/Paper paper-server/patches/sources/net/minecraft/server/Main.java.patch:76-83"
    private const val JVM_SPEC = "JVM specification: class file major version, 52 is Java 8 and each release adds one"

    val WATCHDOG_FIRED = Rule(
        id = "L001",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "The watchdog fired: a tick took longer than the timeout",
        rationale = "Paper's watchdog dumps every thread and kills the server when the main thread " +
            "has not finished a tick within timeout-time. The dump that follows names the code that " +
            "was running, which is the one moment a hang is attributable.",
        provenance = WATCHDOG,
        fix = "Read the Server thread dump below the message: the topmost plugin frame is what was " +
            "blocking. Raising timeout-time hides the crash and converts it into lag.",
    )

    val ASYNC_API_MISUSE = Rule(
        id = "L002",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "A plugin touched the server from the wrong thread",
        rationale = "AsyncCatcher logs a failed main-thread check and throws IllegalStateException " +
            "with the operation name. The world state it was mutating has no thread safety, so the " +
            "outcome ranges from a lost update to a corrupted chunk.",
        provenance = ASYNC,
        fix = "The named operation has to run on the owning thread: the main thread on Paper, the " +
            "region or entity scheduler on Folia.",
    )

    val EVENT_HANDLER_THREW = Rule(
        id = "L003",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "A plugin's event handler threw",
        rationale = "The server names the plugin and the event, then continues. Every later handler " +
            "for that event still runs, so the visible symptom is usually somewhere else entirely.",
        provenance = "$MANAGER:670",
        fix = "Report it to the named plugin with the stack trace. If it fires on a common event, " +
            "expect knock-on breakage in unrelated features.",
    )

    val PLUGIN_LOAD_FAILED = Rule(
        id = "L004",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "A plugin could not be loaded",
        rationale = "The server logs the jar path and the reason. The plugin is absent for the whole " +
            "run, and anything that soft-depends on it silently loses features.",
        provenance = "$MANAGER:184,187,191,390",
        fix = "Fix the named cause: a restricted or space-containing name, a circular dependency, or " +
            "a descriptor the server would not parse.",
    )

    val AMBIGUOUS_PLUGIN_NAME = Rule(
        id = "L005",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "Two jars claim the same plugin name",
        rationale = "Only one of them loads and which one is not something the operator chose. This " +
            "is what an interrupted update leaves behind.",
        provenance = "$MANAGER:198,208",
        fix = "Delete the copy you did not mean to keep, then restart.",
    )

    val UNSUPPORTED_CLASS_VERSION = Rule(
        id = "L006",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "A plugin was compiled for a newer Java release than the server runs",
        rationale = "The class file is rejected by the class loader before any of the plugin's own " +
            "code runs, so it cannot report the problem itself.",
        provenance = JVM_SPEC,
        fix = "Run the server on the Java release the plugin needs, or install a build of the plugin " +
            "compiled for yours.",
    )

    val FOLIA_UNSUPPORTED_PLUGIN = Rule(
        id = "L007",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "Folia refused a plugin that is not marked as supporting it",
        rationale = "Folia requires folia-supported: true in the descriptor and refuses to load " +
            "anything else, because a plugin written for one main thread has no correct behaviour " +
            "under regionised threading.",
        provenance = FOLIA,
        fix = "Use a build that supports Folia, or run Paper. The declaration is a claim by the " +
            "author, not a check by the server.",
    )

    val UNSUPPORTED_API_VERSION = Rule(
        id = "L008",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "A plugin declares an api-version this server does not know",
        rationale = "A plugin built against a newer API than the server implements is rejected at " +
            "load. It is the common symptom of putting a plugin for a newer Minecraft on an older " +
            "server.",
        provenance = "$MAGIC:394",
        fix = "Install the build that matches this server's Minecraft version, or update the server.",
    )

    val LEGACY_PLUGIN = Rule(
        id = "L009",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "A plugin declares no api-version and runs in legacy mode",
        rationale = "The server treats it as pre-1.13 and translates material and data values for it. " +
            "That translation is lossy and is not maintained for new content.",
        provenance = "$MAGIC:407",
        fix = "Ask the author for a build that declares api-version, or replace the plugin.",
    )

    val DEPRECATED_API_NAG = Rule(
        id = "L010",
        area = RuleArea.LOG,
        severity = Severity.INFO,
        title = "The server nagged a plugin author about deprecated API",
        rationale = "Harmless today, and a reliable predictor of which plugin breaks at the next " +
            "Minecraft version.",
        provenance = "$MANAGER:662",
        fix = "No action needed on the server. Worth passing to the plugin author.",
    )

    val PORT_BIND_FAILED = Rule(
        id = "L011",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "The server could not bind its port",
        rationale = "Something already holds the port: usually the previous instance that has not " +
            "exited. Paper turns the vanilla warning into a propagated IllegalStateException, so on " +
            "Paper the start-up ends here rather than continuing half-initialised.",
        provenance = BIND,
        fix = "Stop the process holding the port, or change server-port. Check for an orphaned java " +
            "process before restarting.",
    )

    val EULA_NOT_ACCEPTED = Rule(
        id = "L012",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "The server stopped because the EULA has not been accepted",
        rationale = "This is logged at INFO, not at ERROR, so it scrolls past unnoticed in a start-up " +
            "log while the server exits cleanly and looks like it simply did not start.",
        provenance = EULA_SRC,
        fix = "Set eula=true in eula.txt if you accept Mojang's EULA.",
    )

    val OUT_OF_MEMORY = Rule(
        id = "L013",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "The JVM ran out of memory",
        rationale = "After an OutOfMemoryError the process state is not trustworthy: allocations " +
            "failed in arbitrary places, and what gets reported afterwards is often the second " +
            "victim rather than the cause.",
        provenance = "java.lang.OutOfMemoryError, whose message names the exhausted region",
        fix = "Restart, then find what grew: heap space points at load or a leak, `unable to create " +
            "native thread` points at thread exhaustion, Metaspace at class loading.",
    )

    val NOT_PAPER_TICK_WARNING = Rule(
        id = "L014",
        area = RuleArea.LOG,
        severity = Severity.INFO,
        title = "This log carries vanilla's overload warning, which Paper does not emit",
        rationale = "Paper deletes `Can't keep up! Is the server overloaded?` and replaces the tick " +
            "loop with catch-up logic bounded by misc.catchup-ticks. Seeing the line therefore says " +
            "the server is CraftBukkit, Spigot, vanilla or a fork that kept it — and on Paper its " +
            "absence says nothing about tick health.",
        provenance = TICK_LOOP,
        fix = "Judge tick health with a profiler rather than with this line. On Paper, use spark.",
    )

    val REPEATED_EXCEPTION = Rule(
        id = "L015",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "The same exception repeats, so the server is looping on it",
        rationale = "One stack trace is an incident; the same one hundreds of times is a broken code " +
            "path being retried every tick, and it is usually the reason the log is unreadable.",
        provenance = "Derived from this log: identical exception type and top frame, counted",
        fix = "Fix or remove the plugin at the top of the trace before looking at anything else in " +
            "this log.",
    )

    val UNCAUGHT_SEVERE = Rule(
        id = "L016",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "An error was logged that no other rule explains",
        rationale = "Reported so the log's severe lines are all accounted for, rather than leaving " +
            "the impression that a clean report means a clean log.",
        provenance = "Derived from this log: ERROR/FATAL level with a stack trace",
        fix = "Read the trace. If a plugin package appears in it, start with that plugin.",
    )

    val all: List<Rule> = listOf(
        WATCHDOG_FIRED,
        ASYNC_API_MISUSE,
        EVENT_HANDLER_THREW,
        PLUGIN_LOAD_FAILED,
        AMBIGUOUS_PLUGIN_NAME,
        UNSUPPORTED_CLASS_VERSION,
        FOLIA_UNSUPPORTED_PLUGIN,
        UNSUPPORTED_API_VERSION,
        LEGACY_PLUGIN,
        DEPRECATED_API_NAG,
        PORT_BIND_FAILED,
        EULA_NOT_ACCEPTED,
        OUT_OF_MEMORY,
        NOT_PAPER_TICK_WARNING,
        REPEATED_EXCEPTION,
        UNCAUGHT_SEVERE,
    )
}
