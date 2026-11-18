package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.plugins.PluginIndex

/**
 * The signature tests, one per rule.
 *
 * Each one keys on a string the server emits, quoted here only as far as needed to recognise it. The
 * strings were read out of Paper's and Folia's sources rather than collected from support threads,
 * because a signature that is subtly wrong produces a diagnosis that is confidently wrong.
 */
object LogDetectors {

    private class Signature(
        override val rule: Rule,
        private val test: (LogEvent, PluginIndex) -> DetectorMatch?,
    ) : LogDetector {
        override fun detect(event: LogEvent, plugins: PluginIndex) = test(event, plugins)
    }

    private val EVENT_BLAME = Regex("""Could not pass event (\S+) to (.+)""")
    private val LOAD_FAILED = Regex("""Could not load '([^']+)'(?::\s*(.+))?""")
    private val CLASS_VERSION = Regex("""class file version (\d+)\.\d+""")
    private val ACCEPTED_VERSION = Regex("""class file versions up to (\d+)\.\d+""")
    private val COMPILED_BY = Regex("""([\w./$]+) has been compiled by a more recent version""")
    private val QUOTED_NAME = Regex("""'([^']+)'""")
    private val BEHIND = Regex("""Running (\d+)ms or (\d+) ticks behind""")
    private val ASYNC_REASON = Regex("""failed main thread check: (.+?)\s*$""")
    private val ASYNC_THROWN = Regex("""Asynchronous ([^!\n]+)!""")

    private val FOLIA_STALL = Regex(
        """(?:Tick region|Region thread|TickRegionThread)[^\n]*(?:stalled|has not responded|stopped responding)""",
        RegexOption.IGNORE_CASE,
    )
    private val FOLIA_CHECK_MSG = Regex(
        """(?:Cannot (?:read|modify|access|move|tick|get|add|remove) [^\n!]+(?:asynchronously|off[- ]main|off[- ]owning region)|Thread [^\n]+ failed main thread check: (Cannot [^\n]+)|Thread [^\n]+ failed region thread check: ([^\n]+))""",
    )
    private val GC_PAUSE = Regex(
        """GC\((\d+)\)\s+Pause\s+([A-Za-z0-9 ()_-]+?)\s+(?:(\d+)([KMG])->(\d+)([KMG])\((\d+)([KMG])\)\s+)?(\d+(?:[.,]\d+)?)ms""",
    )
    private val ZGC_STALL = Regex("""Allocation Stall\s+\(([^)]+)\)\s+(\d+(?:[.,]\d+)?)ms""")
    private val CHUNK_COORDS = Regex("""\((-?\d+,\s*-?\d+)\)""")
    private val SPARK_SLOW_TICK = Regex(
        """(?:(?:Slow tick detected|The server is lagging! Tick duration|Long tick detected|Server tick exceeded)[:\s]+(\d+(?:\.\d+)?)\s*ms|(?:Flame\s*graph|Profile)\s*(?:exported|uploaded)\s*(?:to\s*)?(https?://spark\.lucko\.me/\S+))""",
        RegexOption.IGNORE_CASE,
    )
    private val NETTY_PACKET_OVERFLOW = Regex(
        """(?:Packet too large|Packet was larger than I expected|String too big)""",
        RegexOption.IGNORE_CASE,
    )
    private val REGION_LAG_HEADER = Regex(
        """(?:Region around|Lowest region TPS|Tick region|Region tick|Region\s*\(-?\d+,\s*-?\d+\)|High entity density|Entity density|entity cramming|Chunk\s*\(-?\d+,\s*-?\d+\)[^\n]*contains\s+\d+\s+entities)""",
        RegexOption.IGNORE_CASE,
    )
    private val DENSITY_ONLY_HEADER = Regex(
        """(?:High entity density|Entity density|entity cramming|contains\s+\d+\s+entities)""",
        RegexOption.IGNORE_CASE,
    )
    private val MSPT_VALUE = Regex("""(\d+(?:\.\d+)?)\s*mspt""", RegexOption.IGNORE_CASE)
    private val TPS_VALUE = Regex("""(\d+(?:\.\d+)?)\s*tps\b""", RegexOption.IGNORE_CASE)
    private val TOTAL_ENTITIES = Regex("""(?:entities\s*[:=]\s*(\d+)|(\d+)\s+entities)""", RegexOption.IGNORE_CASE)
    private val WORLD_NAME = Regex("""(?:in\s+world|of\s+world|in)\s+'([^']+)'|world\s+'([^']+)'""", RegexOption.IGNORE_CASE)
    private val REGION_CHUNK_COORDS = Regex("""(?:chunk\s*)?\((-?\d+,\s*-?\d+)\)|chunk\s+(-?\d+,\s*-?\d+)""", RegexOption.IGNORE_CASE)
    private val ENTITY_KV = Regex("""(?:minecraft:)?([a-z][a-z0-9_]{1,40})\s*(?::|=|\s+x)\s*(\d+)\b(?!\.\d)""", RegexOption.IGNORE_CASE)
    private val ENTITY_COUNT_FIRST = Regex("""\b(\d+)x\s*(?:minecraft:)?([a-z][a-z0-9_]{1,40})\b""", RegexOption.IGNORE_CASE)
    private val NON_ENTITY_TOKENS = setOf(
        "tps", "mspt", "chunks", "chunk", "entities", "entity", "players", "player",
        "sections", "world", "region", "tick", "ticks", "line", "threshold", "threads",
        "ms", "top", "count", "total", "block", "blocks", "overloaded", "duration",
    )

    private val CHUNK_GEN_STALL_MSG = Regex(
        """(?:Chunk (?:generation|task|system)[^\n]*(?:stalled|deadlock|blocked|timed out|has not progressed)|(?:Deadlock|Re-entrant chunk load)[^\n]*chunk (?:system|task|worker|generation))""",
        RegexOption.IGNORE_CASE,
    )
    private val CHUNK_GEN_SLOW_STAGE = Regex(
        """Chunk generation[^\n]*took\s+(\d+(?:\.\d+)?)\s*ms""",
        RegexOption.IGNORE_CASE,
    )
    private val CHUNK_STAGE_NAME = Regex(
        """\b(STRUCTURE_STARTS|STRUCTURE_REFERENCES|BIOMES|NOISE|SURFACE|CARVERS|FEATURES|INITIALIZE_LIGHT|LIGHT|SPAWN|FULL)\b""",
    )
    private val LEGACY_CB_NMS_SYMBOL_RE = Regex(
        """(?:org[./]bukkit[./]craftbukkit[./]v1_\d+_R\d+|net[./]minecraft[./]server[./]v1_\d+_R\d+)""",
    )
    private val REMAP_JAR_RE = Regex("""(?:remap(?:ping)?\s+plugin\s+|plugins/)([^\s':"]+\.jar)""", RegexOption.IGNORE_CASE)
    private val COMPONENT_ID_RE = Regex(
        """\b(minecraft:(?:item_model|equippable|consumable|custom_model_data|attribute_modifiers|enchantments|custom_data|food|tool|death_protection|glider|tooltip_style|damage_resistant|repairable|enchantable|use_cooldown|use_remainder|trim|lore|item_name|custom_name)|[a-z0-9_.-]+:[a-z0-9_/.-]+)\b""",
    )
    private val COMPONENT_OR_REGISTRY_SIGNAL_RE = Regex(
        """(?:DataComponentPatch|DataComponentMap|DataComponentType|DataComponents|RegistryDataLoader|RegistrySynchronization|Failed to load registries due to above errors|Tried to load invalid item|Failed to parse\s+item|DataResult\.Error)""",
    )

    /** Class file major 52 is Java 8, and each release adds one, so the release is major - 44. */
    private const val JAVA_CLASS_FILE_OFFSET = 44
    private const val SERVER_TICK_MS = 50.0
    private const val HIGH_LIVE_OCCUPANCY = 0.85
    private const val CHUNK_GEN_SLOW_MS = 2000.0

    private data class RegionalLagHit(
        val discriminator: String,
        val detail: String,
        val evidence: List<String>,
    )

    private data class ChunkGenStallHit(
        val discriminator: String,
        val detail: String,
        val evidence: List<String>,
    )

    private fun isChunkWorkerThread(thread: String?): Boolean {
        if (thread == null) return false
        return thread.contains("Chunk System Worker", ignoreCase = true) ||
            thread.contains("Chunk Task Worker", ignoreCase = true) ||
            thread.contains("Moonrise Chunk Worker", ignoreCase = true) ||
            thread.contains("WorldGen-Worker", ignoreCase = true)
    }

    private fun analyzeRegionalEntityLag(event: LogEvent): RegionalLagHit? {
        if (isFoliaWatchdog(event)) return null
        val text = event.fullText
        if (!REGION_LAG_HEADER.containsMatchIn(text)) return null

        val mspt = MSPT_VALUE.find(text)?.groupValues?.get(1)?.toDoubleOrNull()
        val tps = TPS_VALUE.find(text)?.groupValues?.get(1)?.toDoubleOrNull()
        val explicitTotal = TOTAL_ENTITIES.find(text)?.let { m ->
            m.groupValues.drop(1).firstOrNull { it.isNotEmpty() }?.toIntOrNull()
        }

        val counts = linkedMapOf<String, Int>()
        for (m in ENTITY_KV.findAll(text)) {
            val rawType = m.groupValues[1].lowercase()
            val count = m.groupValues[2].toIntOrNull() ?: continue
            if (rawType !in NON_ENTITY_TOKENS && count > 0) {
                counts[rawType] = maxOf(counts[rawType] ?: 0, count)
            }
        }
        for (m in ENTITY_COUNT_FIRST.findAll(text)) {
            val count = m.groupValues[1].toIntOrNull() ?: continue
            val rawType = m.groupValues[2].lowercase()
            if (rawType !in NON_ENTITY_TOKENS && count > 0) {
                counts[rawType] = maxOf(counts[rawType] ?: 0, count)
            }
        }

        val breakdownSum = counts.values.sum()
        val effectiveTotal = explicitTotal ?: breakdownSum
        val isLagging = (mspt != null && mspt > SERVER_TICK_MS) || (tps != null && tps < 18.0)
        val isDensityReport = DENSITY_ONLY_HEADER.containsMatchIn(text)
        val isDense = effectiveTotal >= 500 || (isDensityReport && effectiveTotal >= 200)
        if (!isLagging && !isDense) return null

        val world = WORLD_NAME.find(text)?.let { m ->
            m.groupValues.drop(1).firstOrNull { it.isNotBlank() }
        }
        val coords = REGION_CHUNK_COORDS.find(text)?.let { m ->
            m.groupValues.drop(1).firstOrNull { it.isNotBlank() }
        }
        val top = counts.entries.sortedByDescending { it.value }.take(3)
        val dominant = top.firstOrNull()
        val bottleneckHint = when {
            dominant == null -> null
            dominant.key.contains("villager") -> "villager AI/POI brain scans"
            dominant.key.contains("minecart") || dominant.key.contains("hopper") -> "minecart/hopper inventory and collision sweeps"
            dominant.key == "item" || dominant.key.contains("orb") -> "unmerged dropped item/XP sweeps"
            dominant.key.contains("armor_stand") -> "armor stand tick and collision lookups"
            else -> "concentrated ${dominant.key} entity ticking"
        }

        val detail = buildString {
            append("Regional tick overload")
            if (world != null) append(" in world '$world'")
            if (coords != null) append(" around chunk ($coords)")
            append(": ")
            val metrics = mutableListOf<String>()
            if (mspt != null) metrics += String.format(java.util.Locale.ROOT, "%.1f mspt", mspt)
            if (tps != null) metrics += String.format(java.util.Locale.ROOT, "%.1f TPS", tps)
            if (effectiveTotal > 0) metrics += "$effectiveTotal entities"
            append(metrics.joinToString(", "))
            if (top.isNotEmpty()) {
                val breakdown = top.joinToString(", ") { (k, v) ->
                    if (effectiveTotal > 0) {
                        val pct = (v * 100) / effectiveTotal
                        "$k=$v ($pct%)"
                    } else {
                        "$k=$v"
                    }
                }
                append(" [top: ").append(breakdown).append(']')
            }
            if (bottleneckHint != null) {
                append(", dominated by ").append(bottleneckHint)
            }
            append('.')
        }

        val disc = "region-density@${world ?: "default"}:${coords?.replace(" ", "") ?: "summary"}"
        return RegionalLagHit(
            discriminator = disc,
            detail = detail,
            evidence = listOf(event.message.trim()),
        )
    }

    private fun analyzeChunkGenStall(event: LogEvent, plugins: PluginIndex = PluginIndex.EMPTY): ChunkGenStallHit? {
        val text = event.fullText
        val workerThread = isChunkWorkerThread(event.thread)
        val reentrantSyncLoad = workerThread && (
            text.contains("synchronous chunk load", ignoreCase = true) ||
                text.contains("sync chunk load", ignoreCase = true) ||
                text.contains("Blocking on chunk task", ignoreCase = true) ||
                event.frames.any { it.className.endsWith("SyncLoadFinder") }
            )
        val explicitStall = CHUNK_GEN_STALL_MSG.containsMatchIn(text)
        val slowStageMs = CHUNK_GEN_SLOW_STAGE.find(text)?.groupValues?.get(1)?.toDoubleOrNull()
        val isSlowStage = slowStageMs != null && slowStageMs >= CHUNK_GEN_SLOW_MS
        val workerWorldgenException = workerThread && event.exceptions.isNotEmpty() && (
            text.contains("ChunkGenerator") ||
                text.contains("BlockPopulator") ||
                text.contains("WorldGenRegion") ||
                text.contains("ChunkTaskScheduler") ||
                text.contains("Starlight")
            )

        if (!reentrantSyncLoad && !explicitStall && !isSlowStage && !workerWorldgenException) {
            return null
        }

        val stage = CHUNK_STAGE_NAME.find(text)?.groupValues?.get(1)
        val coords = CHUNK_COORDS.find(text)?.groupValues?.get(1)
        val blame = LogTriage.attribute(event, plugins)
        val kind = when {
            reentrantSyncLoad -> "re-entrant-worker-chunk-load"
            workerWorldgenException -> "chunk-worker-exception"
            isSlowStage -> "slow-chunk-gen-${stage ?: "stage"}"
            else -> "chunk-gen-stall"
        }

        val detail = buildString {
            when {
                reentrantSyncLoad -> append("Re-entrant synchronous chunk wait inside Moonrise worker thread ")
                    .append(event.thread ?: "Chunk Worker")
                workerWorldgenException -> append("Unhandled worldgen exception on Moonrise worker thread ")
                    .append(event.thread ?: "Chunk Worker")
                isSlowStage -> append("Async chunk generation stalled for ")
                    .append(String.format(java.util.Locale.ROOT, "%.0f ms", slowStageMs))
                else -> append("Moonrise async chunk generation pipeline stalled or deadlocked")
            }
            if (stage != null) append(" during stage $stage")
            if (coords != null) append(" at chunk ($coords)")
            if (blame != null) append(", involving $blame")
            append('.')
        }

        val evidence = event.frames.take(4).map { it.raw }.ifEmpty { listOf(event.message.trim()) }
        return ChunkGenStallHit(
            discriminator = "$kind@${blame ?: (stage ?: "moonrise")}",
            detail = detail,
            evidence = evidence,
        )
    }

    private fun isFoliaWatchdog(event: LogEvent): Boolean {
        if (event.message.contains("DO NOT REPORT THIS TO FOLIA")) return true
        if (FOLIA_STALL.containsMatchIn(event.fullText)) return true
        val foliaThread = event.thread?.let {
            it.contains("Folia", ignoreCase = true) || it.contains("Region Watchdog", ignoreCase = true)
        } ?: false
        return foliaThread && event.message.contains("stopped responding")
    }

    private fun extractFoliaTickThreadViolation(event: LogEvent): String? {
        val text = event.fullText
        if (text.contains("Must use teleportAsync while in region threading")) {
            return "Entity.teleport (must use teleportAsync in region threading)"
        }
        if (text.contains("CraftScheduler") &&
            (text.contains("UnsupportedOperationException") ||
                text.contains("handleCraftSchedulerUnsupported") ||
                text.contains("region threading", ignoreCase = true) ||
                text.contains("Folia"))
        ) {
            return "Bukkit CraftScheduler task submission under Folia region threading"
        }
        FOLIA_CHECK_MSG.find(text)?.let { match ->
            val specific = match.groupValues.drop(1).firstOrNull { it.isNotBlank() } ?: match.value
            return specific.trim()
        }
        val hasTickThreadFrame = event.frames.any {
            it.className.endsWith(".TickThread") && it.method.startsWith("ensureTickThread")
        }
        if (hasTickThreadFrame) {
            val reason = ASYNC_REASON.find(event.message)?.groupValues?.get(1)?.trim()
                ?: event.message.lineSequence().firstOrNull()?.take(100)
                ?: "TickThread ownership check"
            return reason
        }
        return null
    }

    private fun toBytes(amount: Long, unit: String): Long = when (unit.uppercase()) {
        "K" -> amount * 1024L
        "M" -> amount * 1024L * 1024L
        "G" -> amount * 1024L * 1024L * 1024L
        else -> amount
    }

    val all: List<LogDetector> = listOf(

        Signature(LogRules.FOLIA_REGION_STALL) { event, plugins ->
            if (!isFoliaWatchdog(event)) return@Signature null
            val blame = LogTriage.attribute(event, plugins)
            val coords = CHUNK_COORDS.find(event.fullText)?.groupValues?.get(1)
            DetectorMatch(
                discriminator = "folia-region-stall",
                detail = buildString {
                    append("A Folia region tick thread stalled past the watchdog timeout")
                    coords?.let { append(" around chunk ($it)") }
                    blame?.let { append(", with $it on the stack") }
                    append(". Watchdog thread: ").append(event.thread ?: "Folia Watchdog")
                },
                evidence = event.frames.take(4).map { it.raw },
            )
        },

        Signature(LogRules.WATCHDOG_FIRED) { event, _ ->
            if (isFoliaWatchdog(event)) return@Signature null
            if (!event.message.contains("The server has stopped responding")) return@Signature null
            DetectorMatch(
                discriminator = "watchdog",
                detail = "A tick did not finish before the watchdog timeout, so the server was " +
                    "considered hung. The thread dump that follows names what was running.",
            )
        },

        Signature(LogRules.FOLIA_TICK_THREAD_VIOLATION) { event, plugins ->
            val violation = extractFoliaTickThreadViolation(event) ?: return@Signature null
            val blame = LogTriage.attribute(event, plugins)
            DetectorMatch(
                discriminator = "${violation.take(80)}@${blame ?: "unknown"}",
                detail = buildString {
                    append("\"").append(violation).append("\" violated Folia region thread ownership")
                    if (blame != null) append(", reached from $blame")
                    append(". Thread: ").append(event.thread ?: "unknown")
                },
                evidence = event.frames.take(4).map { it.raw },
            )
        },

        Signature(LogRules.ASYNC_API_MISUSE) { event, plugins ->
            if (extractFoliaTickThreadViolation(event) != null) return@Signature null
            val reason = ASYNC_REASON.find(event.message)?.groupValues?.get(1)
                ?: ASYNC_THROWN.find(event.fullText)?.groupValues?.get(1)
                ?: return@Signature null
            val blame = LogTriage.attribute(event, plugins)
            DetectorMatch(
                discriminator = reason.trim(),
                detail = buildString {
                    append("\"").append(reason.trim()).append("\" ran off the owning thread")
                    if (blame != null) append(", reached from $blame")
                    append(". Thread: ").append(event.thread ?: "unknown")
                },
                evidence = event.frames.take(4).map { it.raw },
            )
        },

        Signature(LogRules.EVENT_HANDLER_THREW) { event, _ ->
            val match = EVENT_BLAME.find(event.message) ?: return@Signature null
            val (eventName, plugin) = match.destructured
            val exception = event.exceptions.firstOrNull()
            DetectorMatch(
                // Grouped per plugin and event, not per occurrence: the same handler failing all
                // evening is one defect.
                discriminator = "$eventName@$plugin",
                detail = "$plugin threw while handling $eventName" +
                    (exception?.let { ": $it" } ?: ""),
                evidence = event.frames.take(4).map { it.raw },
            )
        },

        Signature(LogRules.PLUGIN_LOAD_FAILED) { event, _ ->
            val match = LOAD_FAILED.find(event.message) ?: return@Signature null
            val jar = match.groupValues[1]
            val reason = match.groupValues[2].ifBlank { event.exceptions.firstOrNull() ?: "no reason given on the line" }
            DetectorMatch(
                discriminator = jar,
                detail = "$jar did not load: $reason",
                evidence = event.frames.take(3).map { it.raw },
            )
        },

        Signature(LogRules.AMBIGUOUS_PLUGIN_NAME) { event, _ ->
            if (!event.message.contains("Ambiguous plugin name")) return@Signature null
            DetectorMatch(
                discriminator = event.message.take(120),
                detail = event.message,
            )
        },

        Signature(LogRules.UNSUPPORTED_CLASS_VERSION) { event, plugins ->
            if (!event.fullText.contains("UnsupportedClassVersionError")) return@Signature null
            val major = CLASS_VERSION.find(event.fullText)?.groupValues?.get(1)?.toIntOrNull()
            val accepted = ACCEPTED_VERSION.find(event.fullText)?.groupValues?.get(1)?.toIntOrNull()
            val className = COMPILED_BY.find(event.fullText)?.groupValues?.get(1)
            val blame = className?.let { plugins.owningPlugin(it.replace('/', '.')) }
            DetectorMatch(
                discriminator = className ?: "class-version",
                detail = buildString {
                    append(className?.replace('/', '.') ?: "A class")
                    append(" needs ")
                    append(major?.let { "Java ${it - JAVA_CLASS_FILE_OFFSET} (class file major $it)" } ?: "a newer Java release")
                    append(accepted?.let { "; this runtime accepts up to Java ${it - JAVA_CLASS_FILE_OFFSET}" } ?: "; this runtime is older")
                    blame?.descriptor?.name?.let { append(". Installed as $it") }
                    append(".")
                },
                evidence = event.fullText.lineSequence().filter { it.contains("UnsupportedClassVersionError") }.take(2).toList(),
            )
        },

        Signature(LogRules.FOLIA_UNSUPPORTED_PLUGIN) { event, _ ->
            val text = event.fullText
            val marked = text.contains("not marked as supporting Folia") ||
                text.contains("not marked as supporting regionised multithreading")
            if (!marked) return@Signature null
            val name = QUOTED_NAME.find(text)?.groupValues?.get(1)
                ?: text.substringAfter("Plugin ", "").substringBefore(" is not marked").ifBlank { "a plugin" }
            DetectorMatch(
                discriminator = name,
                detail = "$name has no folia-supported: true in its descriptor, so Folia refused it.",
            )
        },

        Signature(LogRules.UNSUPPORTED_API_VERSION) { event, _ ->
            if (!event.fullText.contains("Unsupported API version")) return@Signature null
            val declared = event.fullText.substringAfter("Unsupported API version").trim().take(40)
            DetectorMatch(
                discriminator = declared,
                detail = "A plugin declares api-version $declared, which this server does not implement.",
            )
        },

        Signature(LogRules.LEGACY_PLUGIN) { event, _ ->
            if (!event.message.contains("does not specify an api-version")) return@Signature null
            val name = event.message.removePrefix("Legacy plugin ").substringBefore(" does not").trim()
            DetectorMatch(
                discriminator = name,
                detail = "$name declares no api-version, so the server runs it in legacy mode.",
            )
        },

        Signature(LogRules.DEPRECATED_API_NAG) { event, _ ->
            if (!event.message.contains("Nag author(s)")) return@Signature null
            DetectorMatch(
                discriminator = event.message.take(120),
                detail = event.message,
            )
        },

        Signature(LogRules.PORT_BIND_FAILED) { event, _ ->
            if (!event.fullText.contains("FAILED TO BIND TO PORT")) return@Signature null
            DetectorMatch(
                discriminator = "port",
                detail = "The server could not bind its port. On Paper this is fatal rather than a " +
                    "warning, so start-up ended here.",
                evidence = event.fullText.lineSequence().filter { it.contains("Exception") }.take(2).toList(),
            )
        },

        Signature(LogRules.EULA_NOT_ACCEPTED) { event, _ ->
            if (!event.message.contains("You need to agree to the EULA")) return@Signature null
            DetectorMatch(
                discriminator = "eula",
                detail = "The server exited because eula.txt has not been accepted. This is logged " +
                    "at INFO, which is why it reads like a normal shutdown.",
            )
        },

        Signature(LogRules.OUT_OF_MEMORY) { event, plugins ->
            if (!event.fullText.contains("OutOfMemoryError")) return@Signature null
            val region = event.fullText.substringAfter("OutOfMemoryError: ", "").substringBefore('\n')
                .trim().ifBlank { "unspecified region" }
            DetectorMatch(
                discriminator = region,
                detail = "The JVM exhausted $region. Anything logged after this point may be a " +
                    "consequence rather than a cause." +
                    (LogTriage.attribute(event, plugins)?.let { " First non-server frame: $it." } ?: ""),
                evidence = event.frames.take(4).map { it.raw },
            )
        },

        Signature(LogRules.NOT_PAPER_TICK_WARNING) { event, _ ->
            if (!event.message.contains("Can't keep up")) return@Signature null
            val behind = BEHIND.find(event.message)
            DetectorMatch(
                discriminator = "keep-up",
                detail = buildString {
                    append("Vanilla's overload warning is present")
                    behind?.let { append(" (").append(it.groupValues[2]).append(" ticks behind)") }
                    append(", which Paper does not emit, so this log is from CraftBukkit, Spigot, ")
                    append("vanilla or a fork that kept the line.")
                },
            )
        },

        Signature(LogRules.GC_PAUSE_OVER_TICK) { event, _ ->
            val match = GC_PAUSE.find(event.message) ?: return@Signature null
            val pauseMs = match.groupValues[9].replace(',', '.').toDoubleOrNull() ?: return@Signature null
            if (pauseMs < SERVER_TICK_MS) return@Signature null
            val kind = match.groupValues[2].trim()
            val phase = kind.substringBefore('(').trim().ifEmpty { "Pause" }
            val heapSummary = if (match.groupValues[3].isNotEmpty()) {
                "${match.groupValues[3]}${match.groupValues[4]}->${match.groupValues[5]}${match.groupValues[6]}(${match.groupValues[7]}${match.groupValues[8]})"
            } else {
                null
            }
            val formattedMs = String.format(java.util.Locale.ROOT, "%.1f", pauseMs)
            DetectorMatch(
                discriminator = "gc-pause-$phase",
                detail = buildString {
                    append("GC Pause ").append(kind).append(" froze the JVM for ").append(formattedMs).append(" ms")
                    heapSummary?.let { append(" (heap ").append(it).append(")") }
                    append('.')
                },
                evidence = listOf(event.message.trim()),
            )
        },

        Signature(LogRules.GC_HEAP_PRESSURE) { event, _ ->
            val text = event.message
            ZGC_STALL.find(text)?.let { stall ->
                val stalledThread = stall.groupValues[1]
                val stallMs = stall.groupValues[2]
                return@Signature DetectorMatch(
                    discriminator = "zgc-allocation-stall",
                    detail = "ZGC Allocation Stall blocked thread \"$stalledThread\" for ${stallMs} ms while waiting for free heap pages.",
                    evidence = listOf(text.trim()),
                )
            }
            if (text.contains("To-space exhausted", ignoreCase = true) ||
                text.contains("Retried waiting for GCLocker too often", ignoreCase = true)
            ) {
                return@Signature DetectorMatch(
                    discriminator = "gc-evacuation-exhausted",
                    detail = "Collector evacuation reserve was exhausted under heavy allocation pressure: ${text.trim().take(140)}.",
                    evidence = listOf(text.trim()),
                )
            }
            val pause = GC_PAUSE.find(text) ?: return@Signature null
            val kind = pause.groupValues[2].trim()
            val isFullGc = kind.startsWith("Full", ignoreCase = true)
            val afterAmount = pause.groupValues[5].toLongOrNull()
            val afterUnit = pause.groupValues[6]
            val capAmount = pause.groupValues[7].toLongOrNull()
            val capUnit = pause.groupValues[8]
            val occupancy = if (afterAmount != null && capAmount != null && capAmount > 0L) {
                toBytes(afterAmount, afterUnit).toDouble() / toBytes(capAmount, capUnit).toDouble()
            } else {
                0.0
            }
            if (!isFullGc && occupancy < HIGH_LIVE_OCCUPANCY) return@Signature null
            val pct = (occupancy * 100.0).toInt()
            DetectorMatch(
                discriminator = if (isFullGc) "gc-full" else "gc-high-occupancy",
                detail = if (isFullGc) {
                    "Full GC compaction pause ($kind) ran; heap is under severe pressure."
                } else {
                    "Post-GC live set remained at $pct% of capacity (${pause.groupValues[5]}$afterUnit of ${pause.groupValues[7]}$capUnit), indicating heap thrashing."
                },
                evidence = listOf(text.trim()),
            )
        },

        Signature(LogRules.ASYNC_CHUNK_GENERATION_STALL) { event, plugins ->
            val hit = analyzeChunkGenStall(event, plugins) ?: return@Signature null
            DetectorMatch(
                discriminator = hit.discriminator,
                detail = hit.detail,
                evidence = hit.evidence,
            )
        },

        Signature(LogRules.SYNC_CHUNK_LOAD) { event, plugins ->
            if (analyzeChunkGenStall(event, plugins) != null) return@Signature null
            val text = event.fullText
            val syncSignalled = text.contains("Catching synchronous chunk load", ignoreCase = true) ||
                text.contains("synchronous chunk load", ignoreCase = true) ||
                text.contains("sync chunk load", ignoreCase = true) ||
                event.frames.any { it.className.endsWith("SyncLoadFinder") }
            if (!syncSignalled) return@Signature null
            val blame = LogTriage.attribute(event, plugins)
            val coords = CHUNK_COORDS.find(text)?.groupValues?.get(1)
            DetectorMatch(
                discriminator = "sync-chunk@${blame ?: "server"}",
                detail = buildString {
                    append("Synchronous chunk load stalled ")
                    append(event.thread ?: "a tick thread")
                    coords?.let { append(" at chunk ($it)") }
                    blame?.let { append(", triggered by $it") }
                    append('.')
                },
                evidence = event.frames.take(4).map { it.raw }.ifEmpty { listOf(event.message.trim()) },
            )
        },

        Signature(LogRules.CHUNK_IO_BOTTLENECK) { event, plugins ->
            val msg = event.message
            val full = event.fullText
            val isChunkIo = msg.contains("Failed to save chunk") ||
                msg.contains("Failed to load chunk") ||
                msg.contains("Saving oversized chunk") ||
                msg.contains("Oversized chunk") ||
                msg.contains("Timed out waiting for chunk") ||
                full.contains("MoonriseRegionFileIO") ||
                full.contains("RegionFileIOThread")
            if (!isChunkIo) return@Signature null
            val blame = LogTriage.attribute(event, plugins)
            val coords = CHUNK_COORDS.find(full)?.groupValues?.get(1)
            val kind = when {
                msg.contains("oversized chunk", ignoreCase = true) -> "oversized-chunk"
                msg.contains("Failed to save chunk") -> "save-chunk-failed"
                msg.contains("Failed to load chunk") -> "load-chunk-failed"
                else -> "chunk-io-stall"
            }
            DetectorMatch(
                discriminator = kind,
                detail = buildString {
                    append(msg.trim().take(160))
                    if (coords != null && !msg.contains(coords)) append(" at chunk ($coords)")
                    if (blame != null) append(" (involving $blame)")
                },
                evidence = event.frames.take(4).map { it.raw },
            )
        },

        Signature(LogRules.SPARK_JFR_HOTSPOT) { event, plugins ->
            val text = event.fullText
            val match = SPARK_SLOW_TICK.find(text)
            val isSparkOrJfr = match != null ||
                (text.contains("[spark]", ignoreCase = true) && (text.contains("lagging", ignoreCase = true) || text.contains("TPS", ignoreCase = true) || text.contains("flame", ignoreCase = true))) ||
                (text.contains("JFR", ignoreCase = true) && text.contains("Execution sample", ignoreCase = true))
            if (!isSparkOrJfr) return@Signature null

            val blame = LogTriage.attribute(event, plugins)
            val url = match?.groupValues?.get(2)?.takeIf { it.isNotBlank() }
                ?: Regex("""https?://spark\.lucko\.me/\S+""").find(text)?.value
            val duration = match?.groupValues?.get(1)?.takeIf { it.isNotBlank() }
                ?: Regex("""(?:Slow tick detected|Tick duration)[:\s]+(\d+(?:\.\d+)?)\s*ms""").find(text)?.groupValues?.get(1)

            val disc = url ?: (duration?.let { "spark-slow-tick-${it}ms" } ?: "spark-hotspot")
            DetectorMatch(
                discriminator = disc,
                detail = buildString {
                    if (url != null) {
                        append("Spark profiler flamegraph exported to $url")
                        duration?.let { append(" (slow tick: ${it}ms)") }
                    } else if (duration != null) {
                        append("Spark profiler detected slow tick duration of ${duration}ms")
                    } else {
                        append("Spark or JFR profiler captured an execution hotspot or tick latency spike")
                    }
                    blame?.let { append(", attributed to $it") }
                    append('.')
                },
                evidence = listOfNotNull(url?.let { "Flamegraph: $it" }, duration?.let { "Tick duration: ${it}ms" })
                    .ifEmpty { event.frames.take(4).map { it.raw } }
                    .ifEmpty { listOf(event.message.trim()) },
            )
        },

        Signature(LogRules.NETTY_PACKET_CONTENTION) { event, plugins ->
            val full = event.fullText
            val msg = event.message
            val isNetty = full.contains("io.netty") || event.thread?.contains("Netty", ignoreCase = true) == true
            val hasEncoderExc = full.contains("EncoderException") || full.contains("DecoderException")
            val hasOom = full.contains("OutOfDirectMemoryError") || (isNetty && full.contains("Direct buffer memory"))
            val hasOverflow = NETTY_PACKET_OVERFLOW.containsMatchIn(full)

            if (!(isNetty && (hasEncoderExc || hasOom || hasOverflow))) return@Signature null

            val blame = LogTriage.attribute(event, plugins)
            val kind = when {
                hasOom -> "netty-direct-memory-exhaustion"
                hasOverflow -> "netty-packet-too-large"
                full.contains("DecoderException") -> "netty-decoder-exception"
                else -> "netty-encoder-exception"
            }
            DetectorMatch(
                discriminator = kind,
                detail = buildString {
                    append("Netty network pipeline exception: ")
                    when {
                        hasOom -> append("Direct memory exhausted (OutOfDirectMemoryError).")
                        hasOverflow -> append("Packet payload exceeded Netty compression/size limit.")
                        else -> append(msg.trim().take(120)).append('.')
                    }
                    blame?.let { append(" Involves $it.") }
                },
                evidence = event.frames.take(4).map { it.raw }.ifEmpty { listOf(msg.trim()) },
            )
        },

        Signature(LogRules.FOLIA_REGION_ENTITY_DENSITY) { event, _ ->
            val hit = analyzeRegionalEntityLag(event) ?: return@Signature null
            DetectorMatch(
                discriminator = hit.discriminator,
                detail = hit.detail,
                evidence = hit.evidence,
            )
        },

        Signature(LogRules.FOLIA_THREAD_STALL_TRIAGE) { event, plugins ->
            val thread = event.thread ?: return@Signature null
            if (thread.contains("Watchdog", ignoreCase = true)) return@Signature null
            if (isFoliaWatchdog(event)) return@Signature null
            if (!FoliaStallTriager.isFoliaRegionOrWatchdogThread(thread)) return@Signature null
            val lines = listOf(event.message) + event.continuation
            val hit = FoliaStallTriager.triageDump(event.startLine, lines, plugins, isWatchdogDump = false)
                ?: return@Signature null
            DetectorMatch(
                discriminator = hit.discriminator,
                detail = hit.detail,
                evidence = hit.evidence,
            )
        },

        Signature(LogRules.PAPER_PLUGIN_REMAPPER_OR_LINKAGE) { event, plugins ->
            val full = event.fullText
            val msg = event.message
            val isRemapperFailure = full.contains("PluginRemapper") ||
                msg.contains("Failed to remap plugin", ignoreCase = true) ||
                msg.contains("Encountered exception remapping plugins", ignoreCase = true)
            val hasLinkageType = full.contains("NoSuchMethodError") ||
                full.contains("NoClassDefFoundError") ||
                full.contains("ClassNotFoundException") ||
                full.contains("IncompatibleClassChangeError") ||
                full.contains("LinkageError")
            val legacySymbol = LEGACY_CB_NMS_SYMBOL_RE.find(full)?.value?.replace('/', '.')

            if (!isRemapperFailure && !(hasLinkageType && legacySymbol != null)) {
                return@Signature null
            }

            val blamed = LogTriage.attribute(event, plugins)
            val jarName = REMAP_JAR_RE.find(full)?.groupValues?.get(1)
            val matchedJar = plugins.jars.firstOrNull { jar ->
                (blamed != null && (jar.descriptor?.name == blamed || jar.fileName == blamed)) ||
                    (jarName != null && jar.fileName.equals(jarName, ignoreCase = true))
            }
            val nsNote = matchedJar?.manifest?.get("paperweight-mappings-namespace")?.let { ns ->
                " (jar manifest mappings: $ns)"
            } ?: ""

            val subject = blamed ?: jarName ?: "a plugin"
            val detail = if (isRemapperFailure) {
                "Paper PluginRemapper failed while rewriting $subject$nsNote: ${msg.trim().take(130)}."
            } else {
                "$subject referenced removed CraftBukkit/NMS versioned package $legacySymbol on a Mojang-mapped Paper runtime$nsNote."
            }

            DetectorMatch(
                discriminator = "paper-remap-linkage@${blamed ?: jarName ?: (legacySymbol ?: "remap")}",
                detail = detail,
                evidence = event.frames.take(4).map { it.raw }.ifEmpty { listOf(msg.trim()) },
            )
        },

        Signature(LogRules.DATA_COMPONENT_CODEC_OR_REGISTRY_ERROR) { event, plugins ->
            val full = event.fullText
            val msg = event.message
            val hasCoreSignal = COMPONENT_OR_REGISTRY_SIGNAL_RE.containsMatchIn(full)
            val hasCodecWithComponent = (full.contains("Failed to parse", ignoreCase = true) ||
                full.contains("Failed to decode", ignoreCase = true) ||
                full.contains("Codec", ignoreCase = true) ||
                full.contains("MalformedJsonException")) &&
                (full.contains("minecraft:item_model") ||
                    full.contains("minecraft:equippable") ||
                    full.contains("minecraft:consumable") ||
                    full.contains("minecraft:custom_model_data") ||
                    full.contains("minecraft:attribute_modifiers") ||
                    full.contains("minecraft:enchantments") ||
                    full.contains("DataComponent"))

            if (!hasCoreSignal && !hasCodecWithComponent) return@Signature null

            val isRegistryBootFailure = full.contains("RegistryDataLoader") ||
                full.contains("Failed to load registries", ignoreCase = true) ||
                full.contains("RegistrySynchronization")
            val resourceKey = COMPONENT_ID_RE.find(full)?.groupValues?.get(1)
            val blame = LogTriage.attribute(event, plugins)
            val kind = if (isRegistryBootFailure) "registry-codec" else "data-component-codec"

            DetectorMatch(
                discriminator = "$kind@${resourceKey ?: (blame ?: "codec")}",
                detail = buildString {
                    if (isRegistryBootFailure) {
                        append("Minecraft 1.21.4+ datapack registry validation failed")
                    } else {
                        append("Minecraft 1.21.4+ DataComponent codec failed to decode payload")
                    }
                    if (resourceKey != null) append(" for '$resourceKey'")
                    if (blame != null) append(" (involving $blame)")
                    append(": ").append(msg.trim().take(120)).append('.')
                },
                evidence = event.frames.take(3).map { it.raw }.ifEmpty { listOf(msg.trim()) },
            )
        },

        Signature(LogRules.CHAT_SIGNATURE_OR_CONFIG_PHASE_REJECT) { event, plugins ->
            val full = event.fullText
            val msg = event.message
            val isChatSig = full.contains("SignedMessageChain") ||
                msg.contains("Chat message validation failure", ignoreCase = true) ||
                msg.contains("Out-of-order chat packet", ignoreCase = true) ||
                msg.contains("Received chat packet with missing or invalid signature", ignoreCase = true) ||
                msg.contains("expired profile public key", ignoreCase = true)
            val isConfigPhase = full.contains("ServerConfigurationPacketListenerImpl") &&
                (event.isProblem ||
                    msg.contains("Failed to handle packet", ignoreCase = true) ||
                    msg.contains("Missing registry entries", ignoreCase = true) ||
                    msg.contains("KnownPacks", ignoreCase = true) ||
                    msg.contains("disconnect", ignoreCase = true))
            val isPacketRateKick = msg.contains("exceeding packet rate limit", ignoreCase = true) ||
                msg.contains("kicked for exceeding packet rate", ignoreCase = true) ||
                (full.contains("PacketLimiter") && event.isProblem)

            if (!isChatSig && !isConfigPhase && !isPacketRateKick) return@Signature null

            val blame = LogTriage.attribute(event, plugins)
            val kind = when {
                isChatSig -> "signed-chat-reject"
                isConfigPhase -> "configuration-phase-disconnect"
                else -> "packet-rate-limiter-kick"
            }

            DetectorMatch(
                discriminator = "$kind@${blame ?: "protocol"}",
                detail = buildString {
                    when {
                        isChatSig -> append("Signed chat chain validation rejected a player message (check enforce-secure-profile and proxy/plugin chat rewriting)")
                        isConfigPhase -> append("Client disconnected during Minecraft 1.21.4+ CONFIGURATION protocol negotiation")
                        else -> append("Paper PacketLimiter disconnected a client for exceeding configured packet rate limits")
                    }
                    if (blame != null) append(", involving $blame")
                    append(": ").append(msg.trim().take(120)).append('.')
                },
                evidence = event.frames.take(3).map { it.raw }.ifEmpty { listOf(msg.trim()) },
            )
        },

        Signature(LogRules.FOLIA_CROSS_REGION_AFFINITY_MISMATCH) { event, plugins ->
            val hit = FoliaAffinityAnalyzer.analyzeAffinityMismatch(event, plugins) ?: return@Signature null
            DetectorMatch(
                discriminator = hit.discriminator,
                detail = hit.detail,
                evidence = hit.evidence,
            )
        },

        Signature(LogRules.FOLIA_SCHEDULER_TASK_EXCEPTION_OR_BACKLOG) { event, plugins ->
            val hit = FoliaAffinityAnalyzer.analyzeSchedulerFaultOrBacklog(event, plugins) ?: return@Signature null
            DetectorMatch(
                discriminator = hit.discriminator,
                detail = hit.detail,
                evidence = hit.evidence,
            )
        },
    )
}
