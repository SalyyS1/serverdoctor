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

    val FOLIA_REGION_ENTITY_DENSITY = Rule(
        id = "L025",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Folia or Paper regional tick lag with concentrated entity-type density",
        rationale = "Under Folia region threading (and Paper per-world entity ticking), entities clustered " +
            "inside one chunk island cannot be split across multiple TickRegionThreads: one region thread " +
            "must tick every entity in that merged region. When regional MSPT exceeds the 50 ms budget or " +
            "single-region entity counts spike, parsing the entity-type breakdown distinguishes villager " +
            "POI brain scans from minecart hopper collisions and unmerged item piles.",
        provenance = "PaperMC/Folia io.papermc.paper.threadedregions.TickRegions and CommandServerHealth, " +
            "and PaperMC/Paper io.papermc.paper.command.subcommands.EntityCommand",
        fix = "Target the dominant entity class in the named region: raise tick-rates.behavior.villager." +
            "validatenearbypoi and secondarypoisensor for trading halls, cap collisions.max-entity-collisions " +
            "for mob farms, or enable hopper.cooldown-when-full and item merge radii.",
    )

    val ASYNC_CHUNK_GENERATION_STALL = Rule(
        id = "L026",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Moonrise async chunk generation worker stall, re-entrant load, or stage failure",
        rationale = "Paper 26.3 and Folia execute world generation stages (BIOME, NOISE, SURFACE, FEATURES, " +
            "LIGHT) on Moonrise chunk worker threads. When a custom ChunkGenerator, BlockPopulator, or " +
            "datapack feature blocks synchronously on another chunk future, deadlocks a worker thread, or " +
            "stalls a generation stage for multiple seconds, chunk loading queues back up across regions.",
        provenance = "PaperMC/Paper ca.spottedleaf.moonrise.patches.chunk_system.scheduling." +
            "ChunkTaskScheduler and NewChunkHolder",
        fix = "Remove blocking getChunkAt or CompletableFuture.join calls from custom ChunkGenerator and " +
            "BlockPopulator implementations, confine worldgen mutations to LimitedRegion, and keep " +
            "chunk-system.worker-threads at -1.",
    )

    val SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY = Rule(
        id = "L027",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Spark profiler call-tree or flamegraph shows a dominant tick-thread hotspot",
        rationale = "When Spark sampler call-trees, collapsed flamegraph stacks, or JSON thread profiles " +
            "show a server or Folia region tick thread spending 20 percent or more of sampled execution " +
            "time inside one non-idle subsystem, categorizing the full call branch distinguishes " +
            "synchronous JDBC/HTTP socket waits, filesystem I/O, lock or CompletableFuture parking, " +
            "entity pathfinding and villager POI scans, hopper container sweeps, and synchronous chunk " +
            "generation while attributing the hotspot to the calling plugin frame rather than the " +
            "underlying driver or JDK class.",
        provenance = "lucko/spark CallTree / StackTraceNode sampler format and collapsed flamegraph stack profiles",
        fix = "Move JDBC, HTTP, Redis, and disk I/O onto AsyncScheduler or Folia async pools, eliminate " +
            "blocking CompletableFuture.join and contended locks from tick threads, or apply targeted " +
            "Paper/Folia entity and hopper tuning for the reported hotspot category.",
    )

    val FOLIA_THREAD_STALL_TRIAGE = Rule(
        id = "L028",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Folia region thread stall root-cause classified: cross-region wait, lock contention, or blocking I/O",
        rationale = "Folia's RegionizedServer executes independent TickRegionThreads in parallel and merges " +
            "adjacent regions dynamically when chunks load near each other. When a region thread blocks on " +
            "CompletableFuture.join/get for work scheduled on another region, waits on a contended monitor " +
            "or ReentrantLock held by a peer region thread, stalls inside ThreadedRegionizer split/merge " +
            "barriers, or performs synchronous JDBC/socket/file I/O, both the stalled region and any " +
            "neighbouring region attempting to merge with it freeze until FoliaWatchdogThread halts the server.",
        provenance = "PaperMC/Folia FoliaWatchdogThread.java, ThreadedRegionizer.java, and RegionizedTaskQueue.java",
        fix = "Never call CompletableFuture.join or Future.get on a TickRegionThread; chain callbacks onto " +
            "EntityScheduler or RegionScheduler via thenAccept, replace cross-region shared locks with " +
            "lock-free message passing or ConcurrentHashMap, and move all JDBC, HTTP, and disk I/O to AsyncScheduler.",
    )

    val PAPER_PLUGIN_REMAPPER_OR_LINKAGE = Rule(
        id = "L029",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Paper 1.21.4+ plugin remapper failure or legacy CraftBukkit v1_* linkage error",
        rationale = "Paper 1.20.5 through 26.3+ ships Mojang-mapped server internals without legacy " +
            "org.bukkit.craftbukkit.v1_* package relocation and rewrites Spigot-compiled plugin jars " +
            "through io.papermc.paper.pluginremap.PluginRemapper on first boot. When PluginRemapper " +
            "fails on malformed bytecode or a plugin accesses versioned v1_* or obfuscated NMS symbols " +
            "through reflection or an unremapped classloader, startup or runtime fails with LinkageError, " +
            "NoSuchMethodError, or NoClassDefFoundError.",
        provenance = "PaperMC/Paper io.papermc.paper.pluginremap.PluginRemapper and PaperPluginClassLoader " +
            "(Mojang runtime mappings without CraftBukkit v1_* relocation)",
        fix = "Install a Paper 1.21.4+ or 26.3+ Mojang-mapped build of the named plugin " +
            "(paperweight-mappings-namespace: mojang), or delete plugins/.paper-remapped if an " +
            "interrupted first-boot remap left a corrupt cached jar.",
    )

    val DATA_COMPONENT_CODEC_OR_REGISTRY_ERROR = Rule(
        id = "L030",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Minecraft 1.21.4+ DataComponent codec parse failure or datapack registry error",
        rationale = "Minecraft 1.20.5 and 1.21.4+ replaced unstructured item and block NBT compounds " +
            "with strict Mojang DataFixerUpper Codecs (minecraft:item_model, minecraft:equippable, " +
            "minecraft:consumable, minecraft:custom_model_data, DataComponentPatch) and validated " +
            "RegistryDataLoader datapack registries at bootstrap. Invalid component payloads in saved " +
            "inventories, chunks, plugin packets, or custom datapacks fail codec decoding and drop " +
            "items, disconnect clients, or abort world registry startup.",
        provenance = "PaperMC/Paper net.minecraft.core.component.DataComponentPatch, " +
            "net.minecraft.resources.RegistryDataLoader, and Mojang DataFixerUpper DataResult.Error",
        fix = "Inspect the named component key or registry resource location in the codec error, " +
            "migrate legacy raw NBT tags to structured 1.21.4+ item components, and validate custom " +
            "datapack JSON files before startup.",
    )

    val CHAT_SIGNATURE_OR_CONFIG_PHASE_REJECT = Rule(
        id = "L031",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Minecraft 1.21.4+ signed chat chain rejection, configuration-phase disconnect, or packet rate kick",
        rationale = "Minecraft 1.21.4+ verifies sequential SignedMessageChain links for player chat and " +
            "synchronizes KnownPacks registry entries during the CONFIGURATION protocol state prior to " +
            "PLAY. Leaving enforce-secure-profile=true behind a proxy, mutating signed chat packets in a " +
            "plugin without system-chat conversion, mismatched proxy/backend datapack registries, or " +
            "exceeding Paper's PacketLimiter threshold disconnects players.",
        provenance = "PaperMC/Paper net.minecraft.network.chat.SignedMessageChain, " +
            "ServerConfigurationPacketListenerImpl, and ServerCommonPacketListenerImpl (PacketLimiter)",
        fix = "Behind Velocity or BungeeCord, ensure modern forwarding is active and set " +
            "enforce-secure-profile=false when chat plugins rewrite messages; keep datapack registries " +
            "identical across proxy backends; or review packet-limiter settings in paper-global.yml.",
    )

    val SPARK_ASYNC_POOL_SATURATION = Rule(
        id = "L032",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Spark profiler shows async scheduler worker pool saturation, connection starvation, or lock convoy",
        rationale = "Offloading database and HTTP calls onto Paper or Folia async pools protects tick " +
            "threads only while async workers remain unblocked. When Spark sampler profiles show async " +
            "scheduler or ForkJoinPool workers spending 35 percent or more of active samples blocked on " +
            "HikariCP connection starvation, un-timed network sockets, contended locks, or runaway CPU " +
            "loops, login authentication, economy callbacks, and async chunk continuations stall.",
        provenance = "lucko/spark async thread sampler profiles, FoliaAsyncScheduler, CraftAsyncScheduler, " +
            "and com.zaxxer.hikari.pool.HikariPool",
        fix = "Size HikariCP maximumPoolSize within database limits and configure explicit connection " +
            "and socket timeouts, remove shared monitor locks across async workers, and cap runaway " +
            "background polling loops.",
    )

    val FOLIA_CROSS_REGION_AFFINITY_MISMATCH = Rule(
        id = "L033",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Folia scheduler trace shows cross-context thread affinity violation (Global, Region, Entity, or Async)",
        rationale = "Folia separates execution into four incompatible affinity domains: " +
            "GlobalRegionScheduler owns weather, world time, and console state but zero chunks or " +
            "entities; RegionScheduler pins a task to fixed chunk coordinates that do not follow moving " +
            "players or entities; EntityScheduler tracks one entity across region merges and splits; " +
            "and FoliaAsyncScheduler owns no world state at all. Calling chunk or entity mutations from " +
            "the wrong scheduler context throws immediately or corrupts regionized world data.",
        provenance = "PaperMC/Folia FoliaGlobalRegionScheduler.java, FoliaRegionScheduler.java, " +
            "EntityScheduler.java, and FoliaAsyncScheduler.java",
        fix = "Match the scheduler to the state owner: dispatch entity/player work via " +
            "entity.getScheduler().run(plugin, task, retired), fixed-coordinate block/chunk work via " +
            "RegionScheduler.execute(plugin, location, task), and reserve GlobalRegionScheduler strictly " +
            "for global server state.",
    )

    val FOLIA_SCHEDULER_TASK_EXCEPTION_OR_BACKLOG = Rule(
        id = "L034",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Folia scheduled task threw an uncaught exception or RegionizedTaskQueue reported backlog",
        rationale = "Uncaught exceptions thrown inside Folia EntityScheduler, RegionScheduler, " +
            "GlobalRegionScheduler, or FoliaAsyncScheduler callbacks abort the scheduled task without " +
            "emitting Bukkit's event-blame header, while excessive cross-region task bursts or wide " +
            "multi-chunk scans trigger RegionizedTaskQueue backlogs and ThreadedRegionizer merge pressure.",
        provenance = "PaperMC/Folia EntityScheduler.java, RegionizedTaskQueue.java, and ThreadedRegionizer.java",
        fix = "Fix the named plugin callback in the Folia scheduler trace, supply a retired callback " +
            "when scheduling delayed EntityScheduler tasks, and batch cross-region task dispatches.",
    )

    val JVM_HEAP_HISTO_PLUGIN_RETENTION = Rule(
        id = "L035",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "JVM heap histogram (jmap -histo) attributes dominant live memory or instance leak to a plugin class or classloader",
        rationale = "Heap histograms (jmap -histo, jcmd GC.class_histogram, or Spark heap summaries) record live instance counts and byte sizes by class name. When a single non-primitive plugin class or plugin classloader retains more than 20 percent of total live heap or accumulates more than 100,000 instances, it identifies an uncollected memory leak (unbounded cache, static collection, uncancelled listener, or classloader retention) that degrades garbage collection until OutOfMemoryError occurs.",
        provenance = "JDK jmap -histo output, JVM ClassHistogram, and CraftChatMessage/PluginClassLoader retention",
        fix = "Audit the named plugin's static collections, clear caches on world unload, unregister event listeners and tasks on disable, and eliminate references held across plugin reloads.",
    )

    val G1GC_CONCURRENT_MARK_OR_TO_SPACE_EXHAUSTION = Rule(
        id = "L036",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "G1GC log records concurrent cycle pause spike, humongous allocation fragmentation, or to-space exhaustion",
        rationale = "Unified JVM GC logging (-Xlog:gc*) for the Garbage-First (G1) collector reports pause durations, evacuation phases, and humongous allocations. When logs record 'To-space exhausted' (Evacuation Failure), Humongous allocations exceeding 50 percent of the G1 region size that force premature concurrent cycles, or concurrent mark pauses exceeding 50ms (one Minecraft tick), tick threads stall and memory fragmentation prevents survivor copying.",
        provenance = "OpenJDK HotSpot G1CollectedHeap.cpp, G1ParScanThreadState.cpp, and -Xlog:gc* unified tags",
        fix = "Increase -XX:G1HeapRegionSize (e.g. 8m, 16m, or 32m) to prevent humongous allocations from fragmenting the heap, ensure -XX:InitiatingHeapOccupancyPercent (IHOP) starts concurrent marking early, and ensure adequate heap headroom.",
    )

    val GENERATIONAL_ZGC_ALLOCATION_STALL_OR_RATE_SPIKE = Rule(
        id = "L037",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Generational ZGC log records allocation stall, worker thread preemption, or young-generation rate spike",
        rationale = "Generational ZGC (JDK 21+) provides sub-millisecond pauses under normal allocation rates. When unified GC logs show 'Allocation Stall' pauses where mutator threads freeze waiting for GC workers to free pages, or the young-generation allocation rate outpaces concurrent collection, tick threads pause unpredictably and TPS collapses.",
        provenance = "OpenJDK HotSpot Generational ZGC zGeneration.cpp, zAllocationStall.cpp, and -Xlog:gc* tags",
        fix = "Allocate more heap headroom, increase -XX:ConcGCThreads to give concurrent workers more CPU time, or reduce excessive per-tick object churn in the identified plugin.",
    )

    val GC_PAUSE_JITTER_AND_METASPACE_EXPANSION = Rule(
        id = "L038",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Unified GC log records Metaspace expansion pauses, class unloading pauses, or concurrent phase jitter",
        rationale = "Frequent 'Metadata GC Threshold' triggers, CompressedClassSpace expansion pauses, or class unloading STW phases occur when dynamic bytecode generation, scripting runtimes, or repeated /reload commands allocate transient classloaders, causing non-heap pauses and cache invalidations.",
        provenance = "OpenJDK HotSpot Metaspace.cpp, SystemDictionary.cpp, and -Xlog:gc,metaspace* tags",
        fix = "Set initial -XX:MetaspaceSize to avoid runtime expansion pauses (e.g. 512M), avoid server reloads, and configure script engines to reuse compiled classes.",
    )

    val NETTY_DIRECT_BYTEBUF_LEAK = Rule(
        id = "L039",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Netty ResourceLeakDetector or Native Memory Tracking shows unreleased DirectByteBuffer off-heap leak",
        rationale = "Custom packet listeners and Netty ChannelHandlers that slice, retain, or allocate pooled direct ByteBuf instances without calling ReferenceCountUtil.release leak native off-heap memory outside -Xmx. Netty's ResourceLeakDetector records recent touch hints and allocation frames before native RSS exhausts MaxDirectMemorySize or triggers container OOM kills.",
        provenance = "io.netty.util.ResourceLeakDetector, io.netty.buffer.PooledByteBufAllocator, and OpenJDK HotSpot VM.native_memory",
        fix = "Ensure every custom Netty ChannelInboundHandler, ByteToMessageDecoder, or packet-listener callback releases unforwarded ByteBuf instances inside a try/finally block via ReferenceCountUtil.release, and run with -Dio.netty.leakDetection.level=ADVANCED while verifying the fix.",
    )

    val PAPER_CHUNK_TICKET_LEAK = Rule(
        id = "L040",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Paper 26.3 Moonrise chunk system shows persistent plugin chunk ticket or force-loaded chunk leak",
        rationale = "Paper and Folia's Moonrise ChunkHolderManager keeps chunks loaded and entity-ticking whenever a plugin_ticket, forced ticket, or portal/ender_pearl ticket holds ticket level 31 or 32, propagating load levels across neighbouring chunks. Unremoved addPluginChunkTicket or setForceLoaded calls pin hundreds of chunks and their entities in memory even when zero players are online.",
        provenance = "PaperMC/Paper ca.spottedleaf.moonrise.patches.chunk_system.scheduling.ChunkHolderManager, TicketType, and org.bukkit.World.addPluginChunkTicket",
        fix = "Call removePluginChunkTicket or removePluginChunkTickets(plugin) when temporary tasks, arenas, or teleports finish, audit force-loaded chunks per world, and avoid holding persistent level-31 tickets across unloaded regions.",
    )

    val JFR_ASYNC_PROFILER_LOCK_CONTENTION = Rule(
        id = "L041",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "JFR or async-profiler wall-clock profile shows severe tick-thread monitor or lock contention",
        rationale = "CPU-only execution profilers miss threads parked off-CPU waiting on synchronized monitors or java.util.concurrent locks. JDK Flight Recorder jdk.JavaMonitorEnter and jdk.ThreadPark events and async-profiler lock/wall-clock profiles expose exact blocked durations and lock-inversion convoys where a Server thread or Folia TickRegionThread stalls waiting on an async worker or Netty I/O thread.",
        provenance = "OpenJDK JFR jdk.JavaMonitorEnter and jdk.ThreadPark events, and async-profiler lock profiling",
        fix = "Eliminate shared synchronized locks and contended ReentrantLocks between tick threads and async workers, replace coarse caches with ConcurrentHashMap or immutable snapshots, and never hold a lock across database, disk, or network I/O.",
    )

    val VIRTUAL_THREAD_CARRIER_PINNING = Rule(
        id = "L042",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Project Loom virtual thread pinned its ForkJoinPool carrier platform thread",
        rationale = "Plugins using Java 21+ virtual threads (Thread.ofVirtual) share a bounded ForkJoinPool of platform carrier threads sized to CPU cores. Entering a synchronized monitor (<== monitors:1) or native frame while blocking on JDBC, network sockets, or disk I/O pins the underlying carrier thread so it cannot unmount and schedule other virtual threads, starving async tasks across the server.",
        provenance = "OpenJDK JEP 444 Virtual Threads (-Djdk.tracePinnedThreads and JFR jdk.VirtualThreadPinned)",
        fix = "Replace synchronized blocks around blocking JDBC, HTTP, or file I/O with java.util.concurrent.locks.ReentrantLock, upgrade JDBC drivers to Loom-safe versions, or run on JDK 24+ where JEP 491 unpins object monitors.",
    )

    val DB_POOL_OR_SQLITE_WAL_STARVATION = Rule(
        id = "L043",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "HikariCP connection pool exhaustion or SQLite WAL lock starvation stalled persistence",
        rationale = "When every connection in a HikariCP pool is active and threads queue up until connectionTimeout expires, or when concurrent writers hit SQLITE_BUSY / uncheckpointed WAL lock contention, persistence callbacks stall. If a plugin checks out a connection or executes SQL on the Server thread or a Folia TickRegionThread, the entire region freezes until the timeout elapses.",
        provenance = "brettwooldridge/HikariCP HikariPool.createTimeoutException, PoolStats, and SQLite SQLITE_BUSY / WAL checkpointing",
        fix = "Move all database queries onto AsyncScheduler, close JDBC Connections inside try-with-resources blocks, enable PRAGMA journal_mode=WAL and busy_timeout=5000 for SQLite, or switch multi-writer workloads to MariaDB/PostgreSQL with bounded pool sizes.",
    )

    val LINUX_CGROUP_THROTTLE_OR_SWAP_PRESSURE = Rule(
        id = "L044",
        area = RuleArea.LOG,
        severity = Severity.WARNING,
        title = "Host Linux cgroup CPU CFS throttling, PSI stall, Transparent HugePages compaction, or swap pressure",
        rationale = "Containerized Minecraft hosts enforce CPU quotas via Linux cgroup cpu.max / CFS bandwidth periods. High nr_throttled ratios, Linux Pressure Stall Information (PSI) CPU/memory/IO stalls, Transparent HugePages [always] khugepaged compaction pauses, or active JVM swap-out (VmSwap) freeze every JVM thread simultaneously from outside Java without leaving plugin frames.",
        provenance = "Linux Kernel Documentation admin-guide/cgroup-v2.rst (cpu.stat, memory.events), PSI (/proc/pressure), and transhuge.rst",
        fix = "Raise container CPU quota limits or lower -XX:ParallelGCThreads / Folia region threads to match allocated vCPUs, set Transparent HugePages to madvise, disable swap or lower vm.swappiness, and keep -Xmx + native overhead within container memory limits.",
    )

    val CAUSAL_INCIDENT_CASCADE = Rule(
        id = "L045",
        area = RuleArea.LOG,
        severity = Severity.CRITICAL,
        title = "Cross-signal causal timeline correlates upstream root cause with downstream tick or watchdog stall",
        rationale = "During a server outage, one upstream fault (such as a stop-the-world GC pause, container CPU throttle, HikariCP pool exhaustion, virtual-thread carrier pinning, or async lock convoy) triggers downstream victim symptoms within seconds (tick duration spikes, Netty keepalive timeouts, or Paper/Folia watchdog dumps). Aligning timestamps into a causal chain separates the root cause from downstream victims.",
        provenance = "PaperMC/Paper WatchdogThread, OpenJDK JEP 158 Unified Logging, JFR event timestamps, and ServerDoctor causal timeline correlation",
        fix = "Remediate the earliest upstream root-cause node in the reported causal chain first rather than raising watchdog timeouts or tuning downstream victim components.",
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
        FOLIA_REGION_ENTITY_DENSITY,
        ASYNC_CHUNK_GENERATION_STALL,
        SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY,
        FOLIA_THREAD_STALL_TRIAGE,
        PAPER_PLUGIN_REMAPPER_OR_LINKAGE,
        DATA_COMPONENT_CODEC_OR_REGISTRY_ERROR,
        CHAT_SIGNATURE_OR_CONFIG_PHASE_REJECT,
        SPARK_ASYNC_POOL_SATURATION,
        FOLIA_CROSS_REGION_AFFINITY_MISMATCH,
        FOLIA_SCHEDULER_TASK_EXCEPTION_OR_BACKLOG,
        JVM_HEAP_HISTO_PLUGIN_RETENTION,
        G1GC_CONCURRENT_MARK_OR_TO_SPACE_EXHAUSTION,
        GENERATIONAL_ZGC_ALLOCATION_STALL_OR_RATE_SPIKE,
        GC_PAUSE_JITTER_AND_METASPACE_EXPANSION,
        NETTY_DIRECT_BYTEBUF_LEAK,
        PAPER_CHUNK_TICKET_LEAK,
        JFR_ASYNC_PROFILER_LOCK_CONTENTION,
        VIRTUAL_THREAD_CARRIER_PINNING,
        DB_POOL_OR_SQLITE_WAL_STARVATION,
        LINUX_CGROUP_THROTTLE_OR_SWAP_PRESSURE,
        CAUSAL_INCIDENT_CASCADE,
    )
}
