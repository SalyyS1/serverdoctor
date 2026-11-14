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
            "the server is CraftBukkit, Spigot, vanilla or a fork that kept it - and on Paper its " +
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

    val FOLIA_TICK_THREAD_VIOLATION = Rule(
        id = "L017",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "A plugin violated Folia's region TickThread ownership check",
        rationale = "Folia partitions the world across concurrent TickRegionThreads so no single main " +
            "thread owns every chunk and entity. Mutating or reading world state off the owning region " +
            "thread, calling synchronous Entity.teleport instead of teleportAsync, or scheduling tasks " +
            "on legacy CraftScheduler throws immediately or corrupts neighbouring regions.",
        provenance = "PaperMC/Folia ca.spottedleaf.moonrise.common.util.TickThread.ensureTickThread, " +
            "CraftEntity.teleport, and CraftScheduler",
        fix = "Dispatch the work onto Folia's RegionScheduler, EntityScheduler, or GlobalRegionScheduler, " +
            "and replace synchronous teleport calls with teleportAsync.",
    )

    val FOLIA_REGION_STALL = Rule(
        id = "L018",
        area = RuleArea.LOG,
        severity = Severity.BLOCKER,
        title = "A Folia region tick thread stalled past the watchdog timeout",
        rationale = "Folia monitors each active TickRegionThread independently from other regions. When " +
            "one region thread blocks on synchronous network I/O, lock contention, or unbounded world " +
            "iteration, Folia's regional watchdog dumps that region thread and stops the server before " +
            "cross-region state diverges.",
        provenance = "PaperMC/Folia folia-server/src/main/java/io/papermc/paper/threadedregions/FoliaWatchdogThread.java",
        fix = "Inspect the stalled TickRegionThread stack frames below the banner and move blocking I/O " +
            "or lock waits onto AsyncScheduler.",
    )

    val GC_PAUSE_OVER_TICK = Rule(
        id = "L019",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Stop-the-world garbage collection pause exceeded a server tick",
        rationale = "Minecraft budgets 50 milliseconds per tick at 20 TPS. When a stop-the-world collector " +
            "pause exceeds 50 ms, every tick and network thread freezes for the entire pause duration, " +
            "causing movement rubber-banding, delayed keepalives, and catch-up tick bursts afterwards.",
        provenance = "OpenJDK HotSpot Unified GC Logging (JEP 158 / JEP 271): pause duration measured " +
            "against the 50 ms server tick budget",
        fix = "Size -Xms equal to -Xmx, apply Paper's documented G1GC tuning flags or Generational ZGC " +
            "(-XX:+UseZGC -XX:+ZGenerational) on heaps of 12 GiB or more, and profile allocations with spark.",
    )

    val GC_HEAP_PRESSURE = Rule(
        id = "L020",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Garbage collector hit severe heap pressure, Full GC, or allocation stall",
        rationale = "A Full GC compaction pause, G1 To-space exhausted evacuation failure, ZGC Allocation " +
            "Stall, or post-GC live set above 85 percent of -Xmx means mutator threads are allocating " +
            "faster than concurrent collection can reclaim memory. Multi-second freezes and " +
            "OutOfMemoryError follow shortly.",
        provenance = "OpenJDK HotSpot G1CollectedHeap (Pause Full / To-space exhausted) and ZGC " +
            "ZAllocationStall (JEP 439)",
        fix = "Capture a spark heap summary to locate retained chunks or plugin caches, or raise -Xmx " +
            "if host memory leaves at least 25 percent post-GC headroom.",
    )

    val SYNC_CHUNK_LOAD = Rule(
        id = "L021",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Synchronous chunk load or generation blocked a tick thread",
        rationale = "Calling World.getChunkAt, Location.getChunk, or Block lookups inside an unloaded " +
            "chunk forces the tick thread to wait synchronously on Moonrise disk reads or world " +
            "generation stages instead of ticking entities and players.",
        provenance = "PaperMC/Paper paper-server/src/main/java/io/papermc/paper/chunk/system/scheduling/" +
            "ChunkTaskScheduler.java and SyncLoadFinder.java",
        fix = "Switch the named plugin call path to World.getChunkAtAsync and pre-generate world borders " +
            "before opening the server.",
    )

    val CHUNK_IO_BOTTLENECK = Rule(
        id = "L022",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Paper chunk system I/O error, oversized chunk, or save queue stall",
        rationale = "Moonrise's RegionFileIOThread serialises chunk reads and Anvil .mca sector writes " +
            "asynchronously. Failed chunk saves, oversized chunk external .mcc overflows, or stalled " +
            "I/O queues risk chunk rollbacks, duplicate entities, or hung shutdowns.",
        provenance = "PaperMC/Paper ca.spottedleaf.moonrise.patches.chunk_system.io.MoonriseRegionFileIO " +
            "and net.minecraft.world.level.chunk.storage.RegionFile",
        fix = "Check free disk space, filesystem permissions, and storage I/O latency, and inspect " +
            "oversized chunk coordinates for excessive block-entity or book NBT data.",
    )

    val SPARK_JFR_HOTSPOT = Rule(
        id = "L023",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Spark or JFR profiler detected severe tick duration spike or CPU hotspot",
        rationale = "Spark tick monitoring and JFR execution profiling identify severe tick duration " +
            "spikes (ticks exceeding 100ms or 250ms) or hot call-paths where a plugin or native " +
            "method dominates CPU time. Exporting or analyzing the flamegraph pinpoints the blocking " +
            "method without guessing.",
        provenance = "lucko/spark spark-common/src/main/java/me/lucko/spark/common/monitor/TickMonitor.java and JDK Flight Recorder (JFR)",
        fix = "Open the reported spark.lucko.me profile URL or inspect the top frames in the " +
            "flamegraph/sampler breakdown to eliminate blocking operations, slow database calls, " +
            "or unindexed lookups from the tick thread.",
    )

    val NETTY_PACKET_CONTENTION = Rule(
        id = "L024",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Netty networking pipeline packet compression failure or direct memory leak",
        rationale = "Netty worker threads handle client packet encode, decode, and socket flushes. " +
            "Netty direct-memory exhaustion (OutOfDirectMemoryError), oversized packet encoder exceptions " +
            "(EncoderException: Packet too large), or connection flush drops cause mass player disconnects, " +
            "ghost inventories, and network stall cascades.",
        provenance = "io.netty.handler.codec.EncoderException, io.netty.util.internal.OutOfDirectMemoryError, and net.minecraft.network.Connection",
        fix = "Tune network-compression-threshold in server.properties, verify JVM direct memory bounds " +
            "(-XX:MaxDirectMemorySize), and audit custom packet-listener plugins for unreleased ByteBuf allocations.",
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
        FOLIA_TICK_THREAD_VIOLATION,
        FOLIA_REGION_STALL,
        GC_PAUSE_OVER_TICK,
        GC_HEAP_PRESSURE,
        SYNC_CHUNK_LOAD,
        CHUNK_IO_BOTTLENECK,
        SPARK_JFR_HOTSPOT,
        NETTY_PACKET_CONTENTION,
    )
}
