package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.Finding
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.plugins.PluginIndex
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Locale

/**
 * Categorizes Spark profiler call-trees, collapsed flamegraph stacks, and JSON sampler exports,
 * and classifies Folia region thread stall dumps into concrete root-cause categories.
 */
object SparkFlamegraphAnalyzer {

    enum class HotspotCategory(
        val slug: String,
        val label: String,
        val minSharePercent: Double,
        val advice: String,
    ) {
        JDBC_OR_NETWORK_IO(
            slug = "jdbc-network-io",
            label = "Synchronous JDBC/SQL or network socket I/O on tick thread",
            minSharePercent = 15.0,
            advice = "Dispatch database queries, HTTP calls, and Redis/socket I/O onto AsyncScheduler or Folia async pools and apply results back via RegionScheduler or EntityScheduler.",
        ),
        DISK_OR_CONFIG_IO(
            slug = "disk-config-io",
            label = "Synchronous filesystem, YAML, or NBT disk I/O on tick thread",
            minSharePercent = 15.0,
            advice = "Cache parsed YAML/JSON configurations in memory and move file writes, archive compression, and NBT serialization off tick threads.",
        ),
        LOCK_OR_FUTURE_WAIT(
            slug = "lock-future-wait",
            label = "Contended lock parking or blocking CompletableFuture wait on tick thread",
            minSharePercent = 15.0,
            advice = "Eliminate CompletableFuture.join/get and contended synchronized/ReentrantLock blocks on tick threads; compose async stages with thenAccept instead.",
        ),
        ENTITY_AI_AND_COLLISIONS(
            slug = "entity-ai-collisions",
            label = "Entity pathfinding, villager POI brain scans, or AABB collision sweeps",
            minSharePercent = 20.0,
            advice = "Raise paper-world-defaults.yml tick-rates.sensor.villager.secondarypoisensor (40..80) and validatenearbypoi (60), cap collisions.max-entity-collisions (2..8), and align entity-activation-range with simulation-distance.",
        ),
        HOPPER_AND_BLOCK_ENTITIES(
            slug = "hopper-block-entities",
            label = "Hopper item-transfer sweeps and ticking block entities",
            minSharePercent = 20.0,
            advice = "Enable hopper.cooldown-when-full and hopper.disable-move-event (where compatible) in paper-world-defaults.yml, or place composters/blocks over exposed hoppers.",
        ),
        SYNC_CHUNK_AND_WORLDGEN(
            slug = "sync-chunk-worldgen",
            label = "Synchronous chunk load, lighting, or structure lookup on tick thread",
            minSharePercent = 20.0,
            advice = "Replace synchronous getChunkAt and locateStructure calls with getChunkAtAsync, pre-generate world borders, and keep chunk-system.worker-threads at -1.",
        ),
        PLUGIN_CPU_HOTSPOT(
            slug = "plugin-cpu-hotspot",
            label = "Plugin CPU hotspot dominating tick execution",
            minSharePercent = 25.0,
            advice = "Inspect the named plugin method for per-tick world/entity scans, uncached reflection, or quadratic collection lookups.",
        ),
    }

    data class SparkHotspotHit(
        val line: Int,
        val discriminator: String,
        val category: HotspotCategory,
        val threadName: String,
        val sharePercent: Double,
        val durationMs: Double?,
        val hotFrame: String,
        val blamedPlugin: String?,
        val detail: String,
        val evidence: List<String>,
    )

    data class AsyncPoolSaturationHit(
        val line: Int,
        val discriminator: String,
        val category: HotspotCategory,
        val threadName: String,
        val sharePercent: Double,
        val hotFrame: String,
        val blamedPlugin: String?,
        val detail: String,
        val evidence: List<String>,
    )

    class DeobfStats(
        var remappedFrames: Int = 0,
        var demangledLambdas: Int = 0,
    )

    private data class TreeFrame(
        val depth: Int,
        val line: Int,
        val rawFrame: String,
        val normalizedFrame: String,
        val percent: Double,
        val durationMs: Double?,
    )

    private val INFRA_LIBRARY_PREFIXES = listOf(
        "com.mysql.",
        "org.mariadb.",
        "org.postgresql.",
        "org.sqlite.",
        "org.h2.",
        "com.zaxxer.hikari.",
        "org.hibernate.",
        "redis.clients.",
        "io.lettuce.",
        "com.mongodb.",
        "okhttp3.",
        "okio.",
        "org.apache.hc.",
        "org.apache.http.",
        "org.yaml.snakeyaml.",
        "com.google.gson.",
        "com.fasterxml.jackson.",
        "me.lucko.spark.",
        "org.slf4j.",
        "org.apache.logging.",
    )

    private val IDLE_WAIT_TOKENS = listOf(
        "MinecraftServer.waitUntilNextTick",
        "MinecraftServer.sleepForTick",
        "DedicatedServer.sleepForTick",
        "ScheduledThreadPoolExecutor\$DelayedWorkQueue",
        "ThreadPoolExecutor.getTask",
        "ForkJoinPool.awaitWork",
        "SynchronousQueue.poll",
        "SynchronousQueue\$TransferStack.transfer",
        "SelectorImpl.lockAndDoSelect",
        "EPoll.wait",
    )

    private val THREAD_HEADER_RE = Regex(
        """^\s*(?:\[spark]\s*)?(Server thread|Primary thread|Region Scheduler Thread[^(\n%]*|TickRegionThread[^(\n%]*|Global Region Scheduler[^(\n%]*|Folia[^\n(%]*?|Craft Scheduler Thread[^(\n%]*|Paper Async[^\n(%]*|ForkJoinPool\.commonPool-worker[^\n(%]*|Netty[^\n(%]*)(?:\s+\(?(\d+(?:\.\d+)?)%\)?)?(?:\s*\((\d+(?:\.\d+)?)\s*ms\))?\s*$""",
        RegexOption.IGNORE_CASE,
    )

    private val TREE_NODE_RE = Regex(
        """^([\s\u2502|\u251c\u2514\u2500+\\-]*?)([A-Za-z_$][\w$.<>/-]*\.[A-Za-z0-9_$<>]+(?:\([^)\n]*\))?)\s+(?:\u2014|--|-)?\s*(\d+(?:\.\d+)?)%(?:\s*\((\d+(?:\.\d+)?)\s*ms\))?""",
    )

    private val COLLAPSED_STACK_RE = Regex(
        """^\s*([^;\n]+(?:;[^;\n]+){2,})\s+(\d+(?:\.\d+)?)\s*$""",
    )

    private val SPARK_PREFIX_STRIP = Regex("""^\s*\[spark]\s*""", RegexOption.IGNORE_CASE)

    fun isCandidateProfileLine(text: String): Boolean {
        if (text.isBlank()) return false
        if (text.contains("[spark]", ignoreCase = true)) return true
        if (text.contains('%') && (text.contains('.') || text.contains("thread", ignoreCase = true))) return true
        if (text.contains(';') && COLLAPSED_STACK_RE.containsMatchIn(text)) return true
        val trimmed = text.trimStart()
        return trimmed.startsWith("{") || trimmed.startsWith("\"threads\"") || trimmed.startsWith("\"children\"")
    }

    fun analyseSource(
        source: LogSource,
        plugins: PluginIndex = PluginIndex.EMPTY,
        mappings: SparkMappingDictionary = SparkMappingDictionary.EMPTY,
    ): ScanReport {
        val rawLines = mutableListOf<Pair<Int, String>>()
        val urlHits = mutableListOf<Finding>()
        var totalLines = 0
        source.forEachLine(limit = MAX_SPARK_LINES) { ln ->
            totalLines = ln.number
            rawLines += ln.number to ln.text
            Regex("""https?://spark\.lucko\.me/\S+""").find(ln.text)?.value?.let { url ->
                if (urlHits.none { it.detail.contains(url) }) {
                    urlHits += Finding(
                        ruleId = LogRules.SPARK_JFR_HOTSPOT.id,
                        severity = LogRules.SPARK_JFR_HOTSPOT.severity,
                        title = LogRules.SPARK_JFR_HOTSPOT.title,
                        location = "line ${ln.number}",
                        detail = "Spark profiler viewer link exported to $url.",
                        evidence = listOf(ln.text.trim()),
                        fix = LogRules.SPARK_JFR_HOTSPOT.fix,
                        provenance = LogRules.SPARK_JFR_HOTSPOT.provenance,
                    )
                }
            }
        }

        val stats = DeobfStats()
        val hits = detectHotspotsFromLines(rawLines, plugins, mappings, stats)
        val asyncHits = detectAsyncPoolSaturationFromLines(rawLines, plugins, mappings)
        val hotspotFindings = hits.map { hit ->
            Finding(
                ruleId = LogRules.SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY.id,
                severity = LogRules.SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY.severity,
                title = LogRules.SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY.title,
                location = "line ${hit.line}",
                detail = hit.detail,
                evidence = hit.evidence,
                fix = hit.category.advice,
                provenance = LogRules.SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY.provenance,
            )
        }
        val asyncFindings = asyncHits.map { hit ->
            Finding(
                ruleId = LogRules.SPARK_ASYNC_POOL_SATURATION.id,
                severity = LogRules.SPARK_ASYNC_POOL_SATURATION.severity,
                title = LogRules.SPARK_ASYNC_POOL_SATURATION.title,
                location = "line ${hit.line}",
                detail = hit.detail,
                evidence = hit.evidence,
                fix = LogRules.SPARK_ASYNC_POOL_SATURATION.fix,
                provenance = LogRules.SPARK_ASYNC_POOL_SATURATION.provenance,
            )
        }
        val findings = (hotspotFindings + asyncFindings + urlHits).sortedWith(
            compareByDescending<Finding> { it.severity.rank }.thenBy { it.ruleId }.thenBy { it.location },
        )
        val facts = linkedMapOf(
            "lines read" to totalLines.toString(),
            "hotspots categorized" to hits.size.toString(),
        )
        if (asyncHits.isNotEmpty()) {
            facts["async pool bottlenecks"] = asyncHits.size.toString()
        }
        if (!mappings.isEmpty || stats.remappedFrames > 0) {
            facts["frames deobfuscated"] = stats.remappedFrames.toString()
        }
        if (stats.demangledLambdas > 0) {
            facts["lambda frames demangled"] = stats.demangledLambdas.toString()
        }
        if (!plugins.isEmpty) {
            facts["plugins indexed"] = plugins.jars.count { it.isPlugin }.toString()
        }
        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = source.path.toString(),
            subjectKind = "spark",
            findings = findings,
            facts = facts,
        )
    }

    fun analyseText(
        subject: String,
        text: String,
        plugins: PluginIndex = PluginIndex.EMPTY,
        mappings: SparkMappingDictionary = SparkMappingDictionary.EMPTY,
    ): ScanReport {
        val indexed = text.lineSequence().mapIndexed { idx, s -> (idx + 1) to s }.toList()
        val stats = DeobfStats()
        val hits = detectHotspotsFromLines(indexed, plugins, mappings, stats)
        val asyncHits = detectAsyncPoolSaturationFromLines(indexed, plugins, mappings)
        val hotspotFindings = hits.map { hit ->
            Finding(
                ruleId = LogRules.SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY.id,
                severity = LogRules.SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY.severity,
                title = LogRules.SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY.title,
                location = "line ${hit.line}",
                detail = hit.detail,
                evidence = hit.evidence,
                fix = hit.category.advice,
                provenance = LogRules.SPARK_FLAMEGRAPH_HOTSPOT_CATEGORY.provenance,
            )
        }
        val asyncFindings = asyncHits.map { hit ->
            Finding(
                ruleId = LogRules.SPARK_ASYNC_POOL_SATURATION.id,
                severity = LogRules.SPARK_ASYNC_POOL_SATURATION.severity,
                title = LogRules.SPARK_ASYNC_POOL_SATURATION.title,
                location = "line ${hit.line}",
                detail = hit.detail,
                evidence = hit.evidence,
                fix = LogRules.SPARK_ASYNC_POOL_SATURATION.fix,
                provenance = LogRules.SPARK_ASYNC_POOL_SATURATION.provenance,
            )
        }
        val findings = (hotspotFindings + asyncFindings).sortedWith(
            compareByDescending<Finding> { it.severity.rank }.thenBy { it.ruleId }.thenBy { it.location },
        )
        val facts = linkedMapOf(
            "lines read" to indexed.size.toString(),
            "hotspots categorized" to hits.size.toString(),
        )
        if (asyncHits.isNotEmpty()) {
            facts["async pool bottlenecks"] = asyncHits.size.toString()
        }
        if (!mappings.isEmpty || stats.remappedFrames > 0) {
            facts["frames deobfuscated"] = stats.remappedFrames.toString()
        }
        if (stats.demangledLambdas > 0) {
            facts["lambda frames demangled"] = stats.demangledLambdas.toString()
        }
        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = subject,
            subjectKind = "spark",
            findings = findings,
            facts = facts,
        )
    }

    fun detectHotspotsFromLines(
        lines: List<Pair<Int, String>>,
        plugins: PluginIndex = PluginIndex.EMPTY,
        mappings: SparkMappingDictionary = SparkMappingDictionary.EMPTY,
        stats: DeobfStats? = null,
    ): List<SparkHotspotHit> {
        if (lines.isEmpty()) return emptyList()
        val results = LinkedHashMap<String, SparkHotspotHit>()

        for (hit in parseCollapsedFlamegraph(lines, plugins, mappings, stats)) {
            val prev = results[hit.discriminator]
            if (prev == null || hit.sharePercent > prev.sharePercent) {
                results[hit.discriminator] = hit
            }
        }
        for (hit in parseTextCallTree(lines, plugins, mappings, stats)) {
            val prev = results[hit.discriminator]
            if (prev == null || hit.sharePercent > prev.sharePercent) {
                results[hit.discriminator] = hit
            }
        }
        for (hit in parseJsonProfile(lines, plugins, mappings, stats)) {
            val prev = results[hit.discriminator]
            if (prev == null || hit.sharePercent > prev.sharePercent) {
                results[hit.discriminator] = hit
            }
        }

        return results.values.sortedByDescending { it.sharePercent }
    }

    private fun isTickThreadName(name: String): Boolean {
        val trimmed = name.trim()
        return trimmed.equals("Server thread", ignoreCase = true) ||
            trimmed.equals("Primary thread", ignoreCase = true) ||
            trimmed.contains("Region Scheduler Thread", ignoreCase = true) ||
            trimmed.contains("TickRegionThread", ignoreCase = true) ||
            trimmed.contains("RegionizedServer", ignoreCase = true) ||
            (trimmed.contains("Folia", ignoreCase = true) && !trimmed.contains("Async", ignoreCase = true) && !trimmed.contains("Watchdog", ignoreCase = true))
    }

    private fun isAsyncWorkerThreadName(name: String): Boolean {
        val trimmed = name.trim()
        return trimmed.contains("Craft Scheduler Thread", ignoreCase = true) ||
            trimmed.contains("Paper Async", ignoreCase = true) ||
            trimmed.contains("Folia Async Scheduler", ignoreCase = true) ||
            trimmed.contains("ForkJoinPool.commonPool-worker", ignoreCase = true)
    }

    private fun normalizeFrame(
        raw: String,
        mappings: SparkMappingDictionary = SparkMappingDictionary.EMPTY,
        stats: DeobfStats? = null,
    ): String {
        val d = mappings.deobfuscateFrame(raw)
        if (d.wasRemapped) stats?.let { it.remappedFrames++ }
        if (d.wasLambdaDemangled) stats?.let { it.demangledLambdas++ }
        if (d.className.isNotEmpty()) return d.qualifiedFrame
        val withoutModule = raw.trim().substringAfterLast('/')
        return withoutModule.substringBefore('(').trim().replace('#', '.')
    }

    private fun extractClassName(normalizedFrame: String): String =
        normalizedFrame.substringBeforeLast('.', normalizedFrame)

    private fun isIdleBranch(branchFrames: List<String>): Boolean =
        branchFrames.any { frame -> IDLE_WAIT_TOKENS.any { idle -> frame.contains(idle, ignoreCase = true) } }

    private fun classifyFrame(normalizedFrame: String, plugins: PluginIndex): HotspotCategory? {
        val f = normalizedFrame
        when {
            f.startsWith("java.sql.") ||
                f.startsWith("javax.sql.") ||
                f.startsWith("com.mysql.") ||
                f.startsWith("org.mariadb.") ||
                f.startsWith("org.postgresql.") ||
                f.startsWith("org.sqlite.") ||
                f.startsWith("org.h2.") ||
                f.startsWith("com.zaxxer.hikari.") ||
                f.startsWith("org.hibernate.") ||
                f.startsWith("redis.clients.") ||
                f.startsWith("io.lettuce.") ||
                f.startsWith("com.mongodb.") ||
                f.contains("SocketInputStream.") ||
                f.contains("SocketOutputStream.") ||
                f.contains("NioSocketImpl.") ||
                f.contains("SocketChannelImpl.") ||
                f.startsWith("java.net.http.") ||
                f.startsWith("okhttp3.") ||
                f.startsWith("org.apache.hc.") -> return HotspotCategory.JDBC_OR_NETWORK_IO

            f.contains("FileInputStream.") ||
                f.contains("FileOutputStream.") ||
                f.contains("RandomAccessFile.") ||
                f.startsWith("sun.nio.fs.") ||
                f.startsWith("java.util.zip.") ||
                f.startsWith("org.yaml.snakeyaml.") ||
                f.contains("NbtIo.") -> return HotspotCategory.DISK_OR_CONFIG_IO

            f.contains("CompletableFuture.waitingGet") ||
                f.contains("CompletableFuture.timedGet") ||
                f.contains("CompletableFuture.join") ||
                f.contains("CompletableFuture.get") ||
                f.contains("FutureTask.get") ||
                f.contains("CountDownLatch.await") ||
                f.contains("ReentrantLock.") ||
                f.contains("StampedLock.") ||
                f.contains("Semaphore.acquire") ||
                f.contains("Unsafe.park") ||
                f.contains("LockSupport.park") ||
                f.contains("Object.wait") -> return HotspotCategory.LOCK_OR_FUTURE_WAIT

            f.contains("PathNavigation.") ||
                f.contains("PathFinder.") ||
                f.contains("WalkNodeEvaluator.") ||
                f.contains("SwimNodeEvaluator.") ||
                f.contains("Brain.tick") ||
                f.contains("GoalSelector.") ||
                f.contains("SecondaryPoiSensor.") ||
                f.contains("NearestLivingEntitySensor.") ||
                f.contains("AcquirePoi.") ||
                f.contains("PoiManager.") ||
                f.contains("VoxelShapes.") ||
                f.contains("Entity.collide") -> return HotspotCategory.ENTITY_AI_AND_COLLISIONS

            f.contains("HopperBlockEntity.") ||
                f.contains("BoundTickingBlockEntity.") ||
                f.contains("SculkCatalystBlockEntity.") ||
                f.contains("FurnaceBlockEntity.") -> return HotspotCategory.HOPPER_AND_BLOCK_ENTITIES

            f.contains("ServerChunkCache.getChunk") ||
                f.contains("SyncLoadFinder.") ||
                f.contains("Starlight") ||
                f.contains("StructureCheck.") ||
                f.contains("ChunkGenerator.") -> return HotspotCategory.SYNC_CHUNK_AND_WORLDGEN
        }

        val cls = extractClassName(f)
        if (cls.contains('.') && !ServerPackages.isServerOwned(cls) &&
            INFRA_LIBRARY_PREFIXES.none { cls.startsWith(it) }
        ) {
            if (plugins.owningPlugin(cls) != null || !cls.startsWith("org.slf4j.")) {
                return HotspotCategory.PLUGIN_CPU_HOTSPOT
            }
        }
        return null
    }

    internal fun attributeBranch(branchFrames: List<String>, plugins: PluginIndex): String? {
        val classes = branchFrames.map { extractClassName(it) }.filter { it.contains('.') }
        // 1. Exact match against installed plugin JARs (from leaf-most plugin frame first).
        for (cls in classes.asReversed()) {
            plugins.owningPlugin(cls)?.let { jar ->
                return jar.descriptor?.name ?: jar.fileName
            }
        }
        // 2. Prefer true foreign plugin package over generic JDBC/HTTP/YAML libraries.
        for (cls in classes.asReversed()) {
            if (!ServerPackages.isServerOwned(cls) && INFRA_LIBRARY_PREFIXES.none { cls.startsWith(it) }) {
                return cls.substringBeforeLast('.', cls)
            }
        }
        // 3. Fallback to non-Spark foreign library package if present.
        for (cls in classes.asReversed()) {
            if (!ServerPackages.isServerOwned(cls) && !cls.startsWith("me.lucko.spark.")) {
                return cls.substringBeforeLast('.', cls)
            }
        }
        return null
    }

    private fun buildHit(
        line: Int,
        threadName: String,
        category: HotspotCategory,
        sharePercent: Double,
        durationMs: Double?,
        hotFrame: String,
        branchFrames: List<String>,
        plugins: PluginIndex,
        evidenceLines: List<String>,
    ): SparkHotspotHit {
        val blame = attributeBranch(branchFrames, plugins)
        val pctFormatted = String.format(Locale.ROOT, "%.1f%%", sharePercent)
        val msPart = durationMs?.let { String.format(Locale.ROOT, " (%.1f ms)", it) } ?: ""
        val detail = buildString {
            append(category.label)
            append(" on ").append(threadName)
            append(": ").append(pctFormatted).append(msPart)
            append(" in ").append(hotFrame)
            if (blame != null) append(", attributed to ").append(blame)
            append('.')
        }
        val disc = "${category.slug}@${blame ?: hotFrame.take(48)}"
        return SparkHotspotHit(
            line = line,
            discriminator = disc,
            category = category,
            threadName = threadName,
            sharePercent = sharePercent,
            durationMs = durationMs,
            hotFrame = hotFrame,
            blamedPlugin = blame,
            detail = detail,
            evidence = evidenceLines.take(6),
        )
    }

    private fun parseTextCallTree(
        lines: List<Pair<Int, String>>,
        plugins: PluginIndex,
        mappings: SparkMappingDictionary = SparkMappingDictionary.EMPTY,
        stats: DeobfStats? = null,
    ): List<SparkHotspotHit> {
        val hits = mutableListOf<SparkHotspotHit>()
        var currentThread = "Server thread"
        var activeTickThread = true
        val stack = ArrayDeque<TreeFrame>()

        for ((lineNo, rawLine) in lines) {
            val strippedLog = stripLogEnvelope(rawLine)
            val withoutSpark = SPARK_PREFIX_STRIP.replace(strippedLog, "")
            if (withoutSpark.isBlank()) continue

            val headerMatch = THREAD_HEADER_RE.find(withoutSpark)
            if (headerMatch != null && (!headerMatch.groupValues[1].contains('.') || headerMatch.groupValues[1].contains("ForkJoinPool.commonPool-worker"))) {
                val candidate = headerMatch.groupValues[1].trim()
                currentThread = candidate
                activeTickThread = isTickThreadName(candidate)
                stack.clear()
                continue
            }

            val nodeMatch = TREE_NODE_RE.find(withoutSpark) ?: continue
            val prefix = nodeMatch.groupValues[1]
            val rawFrame = nodeMatch.groupValues[2].trim()
            val pct = nodeMatch.groupValues[3].toDoubleOrNull() ?: continue
            val ms = nodeMatch.groupValues[4].takeIf { it.isNotBlank() }?.toDoubleOrNull()
            val norm = normalizeFrame(rawFrame, mappings, stats)
            val depth = prefix.length

            while (stack.isNotEmpty() && stack.last().depth >= depth) {
                stack.removeLast()
            }

            if (stack.isEmpty()) {
                // If no explicit thread header preceded a root MinecraftServer/TickRegions frame, treat as tick thread.
                if (norm.contains("MinecraftServer.") || norm.contains("TickRegion") || norm.contains("RegionizedServer")) {
                    activeTickThread = true
                }
            }

            val node = TreeFrame(depth, lineNo, rawFrame, norm, pct, ms)
            stack.addLast(node)

            if (!activeTickThread) continue
            val branchNorm = stack.map { it.normalizedFrame }
            if (isIdleBranch(branchNorm)) continue

            val category = classifyFrame(norm, plugins) ?: continue
            if (pct < category.minSharePercent) continue

            // Prefer specific I/O, lock, or engine categories over generic PLUGIN_CPU_HOTSPOT on the same branch;
            // if a deeper frame on the same branch triggers a more specific category, the discriminator dedupes or upgrades.
            val evidence = stack.takeLast(4).map { "${"  ".repeat(minOf(it.depth / 2, 4))}${it.rawFrame} ${String.format(Locale.ROOT, "%.1f%%", it.percent)}" }
            hits += buildHit(
                line = lineNo,
                threadName = currentThread,
                category = category,
                sharePercent = pct,
                durationMs = ms,
                hotFrame = norm,
                branchFrames = branchNorm,
                plugins = plugins,
                evidenceLines = evidence,
            )
        }

        return pruneGenericPluginDuplicates(hits)
    }

    private fun parseCollapsedFlamegraph(
        lines: List<Pair<Int, String>>,
        plugins: PluginIndex,
        mappings: SparkMappingDictionary = SparkMappingDictionary.EMPTY,
        stats: DeobfStats? = null,
    ): List<SparkHotspotHit> {
        data class CollapsedSample(
            val line: Int,
            val thread: String,
            val frames: List<String>,
            val weight: Double,
            val raw: String,
        )

        val samples = mutableListOf<CollapsedSample>()
        val threadTotals = mutableMapOf<String, Double>()

        for ((lineNo, raw) in lines) {
            val m = COLLAPSED_STACK_RE.find(raw) ?: continue
            val parts = m.groupValues[1].split(';').map { it.trim() }.filter { it.isNotEmpty() }
            if (parts.size < 3) continue
            val weight = m.groupValues[2].toDoubleOrNull() ?: continue
            if (weight <= 0.0) continue

            val first = parts.first()
            val hasExplicitThread = !first.contains('.') || isTickThreadName(first) || isAsyncWorkerThreadName(first)
            val thread = if (hasExplicitThread) first else "Server thread"
            val stackFrames = if (hasExplicitThread) parts.drop(1) else parts
            if (hasExplicitThread && !isTickThreadName(thread)) continue

            val normalized = stackFrames.map { normalizeFrame(it, mappings, stats) }
            samples += CollapsedSample(lineNo, thread, normalized, weight, raw.trim())
            threadTotals[thread] = (threadTotals[thread] ?: 0.0) + weight
        }

        if (samples.isEmpty()) return emptyList()

        data class Bucket(
            var weight: Double = 0.0,
            var firstLine: Int = Int.MAX_VALUE,
            val thread: String,
            val category: HotspotCategory,
            val hotFrame: String,
            val sampleBranch: List<String>,
            val evidence: MutableList<String> = mutableListOf(),
        )

        val buckets = LinkedHashMap<String, Bucket>()
        for (sample in samples) {
            if (isIdleBranch(sample.frames)) continue
            // Pick the most specific (non-PLUGIN_CPU_HOTSPOT first, else deepest plugin frame) category in this stack.
            var chosenCat: HotspotCategory? = null
            var chosenFrame: String? = null
            for (frame in sample.frames.asReversed()) {
                val cat = classifyFrame(frame, plugins) ?: continue
                if (cat != HotspotCategory.PLUGIN_CPU_HOTSPOT) {
                    chosenCat = cat
                    chosenFrame = frame
                    break
                } else if (chosenCat == null) {
                    chosenCat = cat
                    chosenFrame = frame
                }
            }
            val category = chosenCat ?: continue
            val hotFrame = chosenFrame ?: continue
            val blame = attributeBranch(sample.frames, plugins)
            val key = "${sample.thread}::${category.slug}::${blame ?: hotFrame}"
            val bucket = buckets.getOrPut(key) {
                Bucket(
                    thread = sample.thread,
                    category = category,
                    hotFrame = hotFrame,
                    sampleBranch = sample.frames,
                )
            }
            bucket.weight += sample.weight
            if (sample.line < bucket.firstLine) bucket.firstLine = sample.line
            if (bucket.evidence.size < 3) bucket.evidence += sample.raw
        }

        val hits = mutableListOf<SparkHotspotHit>()
        for (bucket in buckets.values) {
            val total = threadTotals[bucket.thread] ?: continue
            if (total <= 0.0) continue
            val pct = (bucket.weight / total) * 100.0
            if (pct < bucket.category.minSharePercent) continue
            hits += buildHit(
                line = bucket.firstLine,
                threadName = bucket.thread,
                category = bucket.category,
                sharePercent = pct,
                durationMs = null,
                hotFrame = bucket.hotFrame,
                branchFrames = bucket.sampleBranch,
                plugins = plugins,
                evidenceLines = bucket.evidence,
            )
        }
        return pruneGenericPluginDuplicates(hits)
    }

    private fun parseJsonProfile(
        lines: List<Pair<Int, String>>,
        plugins: PluginIndex,
        mappings: SparkMappingDictionary = SparkMappingDictionary.EMPTY,
        stats: DeobfStats? = null,
    ): List<SparkHotspotHit> {
        val firstBraceIdx = lines.indexOfFirst { it.second.trimStart().startsWith("{") }
        if (firstBraceIdx < 0) return emptyList()
        val startLine = lines[firstBraceIdx].first
        val joined = lines.subList(firstBraceIdx, lines.size).joinToString("\n") { it.second }.trim()
        if (!joined.contains("\"threads\"") || !joined.endsWith("}")) return emptyList()

        val root = runCatching { Json.parseToJsonElement(joined).jsonObject }.getOrNull() ?: return emptyList()
        val threads = (root["threads"] as? JsonArray) ?: return emptyList()
        val hits = mutableListOf<SparkHotspotHit>()

        fun walkNode(
            threadName: String,
            totalThreadTime: Double,
            node: JsonObject,
            ancestors: List<String>,
        ) {
            val cls = node["className"]?.jsonPrimitive?.content
                ?: node["class"]?.jsonPrimitive?.content
            val method = node["methodName"]?.jsonPrimitive?.content
                ?: node["method"]?.jsonPrimitive?.content
            val rawName = node["name"]?.jsonPrimitive?.content
            val lineNum = node["lineNumber"]?.jsonPrimitive?.content
            val lineSuffix = if (!lineNum.isNullOrBlank()) "(SourceFile:$lineNum)" else ""
            val frame = when {
                !cls.isNullOrBlank() && !method.isNullOrBlank() -> normalizeFrame("$cls.$method$lineSuffix", mappings, stats)
                !rawName.isNullOrBlank() -> normalizeFrame("$rawName$lineSuffix", mappings, stats)
                else -> null
            }
            val time = node["time"]?.jsonPrimitive?.doubleOrNull
                ?: node["totalTime"]?.jsonPrimitive?.doubleOrNull
                ?: node["samples"]?.jsonPrimitive?.doubleOrNull
            val percent = node["percent"]?.jsonPrimitive?.doubleOrNull
                ?: if (time != null && totalThreadTime > 0.0) (time / totalThreadTime) * 100.0 else null

            val nextBranch = if (frame != null) ancestors + frame else ancestors
            if (frame != null && percent != null && !isIdleBranch(nextBranch)) {
                val category = classifyFrame(frame, plugins)
                if (category != null && percent >= category.minSharePercent) {
                    val ev = nextBranch.takeLast(4).map { "at $it" }
                    hits += buildHit(
                        line = startLine,
                        threadName = threadName,
                        category = category,
                        sharePercent = percent,
                        durationMs = time,
                        hotFrame = frame,
                        branchFrames = nextBranch,
                        plugins = plugins,
                        evidenceLines = ev,
                    )
                }
            }

            val children: List<JsonElement> = (node["children"] as? JsonArray) ?: emptyList()
            for (child in children) {
                (child as? JsonObject)?.let { walkNode(threadName, totalThreadTime, it, nextBranch) }
            }
        }

        for (el in threads) {
            val tObj = el as? JsonObject ?: continue
            val tName = tObj["name"]?.jsonPrimitive?.content ?: "Server thread"
            if (!isTickThreadName(tName)) continue
            val totalTime = tObj["time"]?.jsonPrimitive?.doubleOrNull
                ?: tObj["totalTime"]?.jsonPrimitive?.doubleOrNull
                ?: tObj["samples"]?.jsonPrimitive?.doubleOrNull
                ?: 100.0
            val children = (tObj["children"] as? JsonArray) ?: continue
            for (child in children) {
                (child as? JsonObject)?.let { walkNode(tName, totalTime, it, emptyList()) }
            }
        }

        return pruneGenericPluginDuplicates(hits)
    }

    /**
     * Analyzes async scheduler and ForkJoinPool worker stacks for connection-pool starvation
     * (such as HikariPool.getConnection waits), un-timed network sockets, contended monitor locks,
     * or runaway background CPU loops (`L032`).
     */
    fun detectAsyncPoolSaturationFromLines(
        lines: List<Pair<Int, String>>,
        plugins: PluginIndex = PluginIndex.EMPTY,
        mappings: SparkMappingDictionary = SparkMappingDictionary.EMPTY,
    ): List<AsyncPoolSaturationHit> {
        if (lines.isEmpty()) return emptyList()
        val out = LinkedHashMap<String, AsyncPoolSaturationHit>()

        fun emitCandidate(
            line: Int,
            threadName: String,
            category: HotspotCategory,
            pct: Double,
            hotFrame: String,
            branchFrames: List<String>,
            evidence: List<String>,
        ) {
            val minPct = if (category == HotspotCategory.PLUGIN_CPU_HOTSPOT) 50.0 else 35.0
            if (pct < minPct) return
            if (category != HotspotCategory.JDBC_OR_NETWORK_IO &&
                category != HotspotCategory.LOCK_OR_FUTURE_WAIT &&
                category != HotspotCategory.DISK_OR_CONFIG_IO &&
                category != HotspotCategory.PLUGIN_CPU_HOTSPOT
            ) {
                return
            }
            val blame = attributeBranch(branchFrames, plugins)
            val pctFmt = String.format(Locale.ROOT, "%.1f%%", pct)
            val symptom = when {
                hotFrame.contains("HikariPool.") -> "JDBC connection-pool starvation ($hotFrame)"
                category == HotspotCategory.JDBC_OR_NETWORK_IO -> "blocking socket or database wait ($hotFrame)"
                category == HotspotCategory.LOCK_OR_FUTURE_WAIT -> "lock or future convoy ($hotFrame)"
                category == HotspotCategory.DISK_OR_CONFIG_IO -> "blocking filesystem I/O ($hotFrame)"
                else -> "sustained async CPU saturation ($hotFrame)"
            }
            val detail = buildString {
                append("Async worker pool saturation on ").append(threadName)
                append(": ").append(pctFmt).append(" spent in ").append(symptom)
                if (blame != null) append(", attributed to ").append(blame)
                append('.')
            }
            val disc = "async-${category.slug}@${blame ?: hotFrame.take(40)}"
            val prev = out[disc]
            if (prev == null || pct > prev.sharePercent) {
                out[disc] = AsyncPoolSaturationHit(
                    line = line,
                    discriminator = disc,
                    category = category,
                    threadName = threadName,
                    sharePercent = pct,
                    hotFrame = hotFrame,
                    blamedPlugin = blame,
                    detail = detail,
                    evidence = evidence.take(5),
                )
            }
        }

        // 1. Text call-trees for async worker pools
        var currentThread = ""
        var activeAsync = false
        val stack = ArrayDeque<TreeFrame>()
        for ((lineNo, rawLine) in lines) {
            val withoutSpark = SPARK_PREFIX_STRIP.replace(stripLogEnvelope(rawLine), "")
            if (withoutSpark.isBlank()) continue
            val headerMatch = THREAD_HEADER_RE.find(withoutSpark)
            if (headerMatch != null && (!headerMatch.groupValues[1].contains('.') || headerMatch.groupValues[1].contains("ForkJoinPool.commonPool-worker"))) {
                currentThread = headerMatch.groupValues[1].trim()
                activeAsync = isAsyncWorkerThreadName(currentThread)
                stack.clear()
                continue
            }
            val nodeMatch = TREE_NODE_RE.find(withoutSpark) ?: continue
            val depth = nodeMatch.groupValues[1].length
            val rawFrame = nodeMatch.groupValues[2].trim()
            val pct = nodeMatch.groupValues[3].toDoubleOrNull() ?: continue
            val ms = nodeMatch.groupValues[4].takeIf { it.isNotBlank() }?.toDoubleOrNull()
            val norm = normalizeFrame(rawFrame, mappings)
            while (stack.isNotEmpty() && stack.last().depth >= depth) stack.removeLast()
            stack.addLast(TreeFrame(depth, lineNo, rawFrame, norm, pct, ms))
            if (!activeAsync) continue
            val branchNorm = stack.map { it.normalizedFrame }
            if (isIdleBranch(branchNorm)) continue
            val cat = classifyFrame(norm, plugins) ?: continue
            if (cat == HotspotCategory.PLUGIN_CPU_HOTSPOT) continue // check leaf/specific first; CPU loop handled if no specific child
            val ev = stack.takeLast(4).map { "${it.rawFrame} ${String.format(Locale.ROOT, "%.1f%%", it.percent)}" }
            emitCandidate(lineNo, currentThread, cat, pct, norm, branchNorm, ev)
        }

        // 2. Collapsed flamegraphs for async worker pools
        var asyncTotalWeight = 0.0
        data class AsyncBucket(
            var weight: Double = 0.0,
            var firstLine: Int = Int.MAX_VALUE,
            val thread: String,
            val category: HotspotCategory,
            val hotFrame: String,
            val branch: List<String>,
            val evidence: MutableList<String> = mutableListOf(),
        )
        val asyncBuckets = LinkedHashMap<String, AsyncBucket>()
        for ((lineNo, raw) in lines) {
            val m = COLLAPSED_STACK_RE.find(raw) ?: continue
            val parts = m.groupValues[1].split(';').map { it.trim() }.filter { it.isNotEmpty() }
            if (parts.size < 3) continue
            val weight = m.groupValues[2].toDoubleOrNull() ?: continue
            if (weight <= 0.0) continue
            val first = parts.first()
            if (!isAsyncWorkerThreadName(first)) continue
            asyncTotalWeight += weight
            val normFrames = parts.drop(1).map { normalizeFrame(it, mappings) }
            if (isIdleBranch(normFrames)) continue
            var chosenCat: HotspotCategory? = null
            var chosenFrame: String? = null
            for (f in normFrames.asReversed()) {
                val c = classifyFrame(f, plugins) ?: continue
                if (c != HotspotCategory.PLUGIN_CPU_HOTSPOT) {
                    chosenCat = c
                    chosenFrame = f
                    break
                } else if (chosenCat == null) {
                    chosenCat = c
                    chosenFrame = f
                }
            }
            val cat = chosenCat ?: continue
            val hf = chosenFrame ?: continue
            val blame = attributeBranch(normFrames, plugins)
            val key = "${cat.slug}::${blame ?: hf}"
            val b = asyncBuckets.getOrPut(key) { AsyncBucket(thread = first, category = cat, hotFrame = hf, branch = normFrames) }
            b.weight += weight
            if (lineNo < b.firstLine) b.firstLine = lineNo
            if (b.evidence.size < 3) b.evidence += raw.trim()
        }
        if (asyncTotalWeight > 0.0) {
            for (b in asyncBuckets.values) {
                val pct = (b.weight / asyncTotalWeight) * 100.0
                emitCandidate(b.firstLine, b.thread, b.category, pct, b.hotFrame, b.branch, b.evidence)
            }
        }

        return out.values.sortedByDescending { it.sharePercent }
    }

    /**
     * When a branch contains both a specific subsystem hotspot (e.g. JDBC_OR_NETWORK_IO attributed
     * to `com.example.economy`) and a generic PLUGIN_CPU_HOTSPOT for the same `com.example.economy`
     * caller frame above it, keep the specific subsystem diagnosis rather than reporting both.
     */
    private fun pruneGenericPluginDuplicates(hits: List<SparkHotspotHit>): List<SparkHotspotHit> {
        val specificPlugins = hits
            .filter { it.category != HotspotCategory.PLUGIN_CPU_HOTSPOT && it.blamedPlugin != null }
            .map { it.blamedPlugin!! }
            .toSet()
        return hits.filterNot {
            it.category == HotspotCategory.PLUGIN_CPU_HOTSPOT &&
                it.blamedPlugin != null &&
                it.blamedPlugin in specificPlugins
        }
    }

    private val LOG_ENVELOPE_RE = Regex("""^\[[^\]]+]\s+\[[^\]]+]:\s*""")

    private fun stripLogEnvelope(raw: String): String = LOG_ENVELOPE_RE.replace(raw, "")

    const val MAX_SPARK_LINES = 25_000
}

/**
 * Classifies Folia region thread stalls and deadlocks from FoliaWatchdogThread dumps and
 * TickRegionThread / Region Scheduler Thread stack traces.
 */
object FoliaStallTriager {

    enum class StallKind(val slug: String, val summary: String) {
        CROSS_REGION_FUTURE_DEADLOCK(
            slug = "cross-region-future-deadlock",
            summary = "Cross-region CompletableFuture/Future blocking wait on a Folia region thread",
        ),
        CROSS_REGION_LOCK_CONTENTION(
            slug = "cross-region-lock-contention",
            summary = "Cross-region monitor or lock contention stalling a Folia region thread",
        ),
        REGION_BLOCKING_NETWORK_JDBC(
            slug = "region-blocking-network-jdbc",
            summary = "Synchronous JDBC/SQL or network socket I/O blocking a Folia region thread",
        ),
        REGION_BLOCKING_DISK_IO(
            slug = "region-blocking-disk-io",
            summary = "Synchronous filesystem, YAML, or NBT disk I/O blocking a Folia region thread",
        ),
        REGIONIZER_BARRIER_STALL(
            slug = "regionizer-barrier-stall",
            summary = "ThreadedRegionizer merge/split barrier or task-queue contention",
        ),
    }

    data class StallTriageHit(
        val line: Int,
        val discriminator: String,
        val detail: String,
        val evidence: List<String>,
    )

    private val REGION_COORDS_RE = Regex("""\((-?\d+,\s*-?\d+)\)""")
    private val STALL_SECONDS_RE = Regex("""(\d+(?:\.\d+)?)\s*seconds""", RegexOption.IGNORE_CASE)
    private val LOCK_OWNER_RE = Regex("""owned by "([^"]+)"""")
    private val WAITING_LOCK_RE = Regex(
        """(?:-\s*(?:waiting to lock|parking to wait for|locked)\s+<[^>]+>[^\n]*|Thread state:\s*BLOCKED[^\n]*|java\.lang\.Thread\.State:\s*BLOCKED[^\n]*)""",
        RegexOption.IGNORE_CASE,
    )

    fun isFoliaRegionOrWatchdogThread(thread: String?): Boolean {
        if (thread == null) return false
        return thread.contains("Folia", ignoreCase = true) ||
            thread.contains("Region Watchdog", ignoreCase = true) ||
            thread.contains("Region Scheduler Thread", ignoreCase = true) ||
            thread.contains("TickRegionThread", ignoreCase = true)
    }

    private val STALL_SIGNAL_RE = Regex(
        """(?:stalled|deadlock|has not responded|stopped responding|timed out|Thread\.State:|Thread state:|waiting to lock|parking to wait for)""",
        RegexOption.IGNORE_CASE,
    )

    fun triageDump(
        startLine: Int,
        rawLines: List<String>,
        plugins: PluginIndex = PluginIndex.EMPTY,
        isWatchdogDump: Boolean = false,
    ): StallTriageHit? {
        if (rawLines.isEmpty()) return null
        val joined = rawLines.joinToString("\n")
        val hasStallSignal = isWatchdogDump || STALL_SIGNAL_RE.containsMatchIn(joined)
        val frames = rawLines.mapNotNull { line ->
            val atIdx = line.indexOf("at ")
            if (atIdx >= 0) StackFrame.parse(line.substring(atIdx)) else StackFrame.parse(line)
        }
        val frameNames = frames.map { "${it.className}.${it.method}" }
        val topFrames = frameNames.take(5)

        val futureFrame = frameNames.firstOrNull {
            it.contains("CompletableFuture.join") ||
                it.contains("CompletableFuture.get") ||
                it.contains("CompletableFuture.waitingGet") ||
                it.contains("CompletableFuture.timedGet") ||
                it.contains("FutureTask.get") ||
                it.contains("CountDownLatch.await")
        }
        val lockOwner = LOCK_OWNER_RE.find(joined)?.groupValues?.get(1)
        val hasMonitorBlock = lockOwner != null || WAITING_LOCK_RE.containsMatchIn(joined)
        val lockFrame = topFrames.firstOrNull {
            it.contains("ReentrantLock.") ||
                it.contains("StampedLock.") ||
                it.contains("Semaphore.acquire") ||
                (hasMonitorBlock && (it.contains("Unsafe.park") || it.contains("LockSupport.park")))
        }
        val netJdbcFrame = if (hasStallSignal) {
            frameNames.firstOrNull {
                it.startsWith("java.sql.") ||
                    it.startsWith("com.mysql.") ||
                    it.startsWith("org.mariadb.") ||
                    it.startsWith("org.postgresql.") ||
                    it.startsWith("org.sqlite.") ||
                    it.startsWith("com.zaxxer.hikari.") ||
                    it.startsWith("redis.clients.") ||
                    it.startsWith("io.lettuce.") ||
                    it.contains("SocketInputStream.") ||
                    it.contains("SocketOutputStream.") ||
                    it.contains("NioSocketImpl.") ||
                    it.contains("SocketChannelImpl.") ||
                    it.startsWith("java.net.http.") ||
                    it.startsWith("okhttp3.")
            }
        } else {
            null
        }
        val diskFrame = if (hasStallSignal) {
            frameNames.firstOrNull {
                it.contains("FileInputStream.") ||
                    it.contains("FileOutputStream.") ||
                    it.contains("RandomAccessFile.") ||
                    it.startsWith("sun.nio.fs.") ||
                    it.startsWith("org.yaml.snakeyaml.") ||
                    it.contains("NbtIo.")
            }
        } else {
            null
        }
        val regionizerTopFrame = topFrames.firstOrNull {
            it.contains("ThreadedRegionizer.") ||
                it.contains("RegionizedTaskQueue.")
        }
        val explicitRegionizerMsg = (joined.contains("ThreadedRegionizer") || joined.contains("RegionizedTaskQueue")) &&
            (joined.contains("deadlock", ignoreCase = true) ||
                joined.contains("merge", ignoreCase = true) ||
                joined.contains("split", ignoreCase = true) ||
                joined.contains("stalled", ignoreCase = true))

        val (kind, triggerFrame) = when {
            hasStallSignal && futureFrame != null ->
                StallKind.CROSS_REGION_FUTURE_DEADLOCK to futureFrame
            hasMonitorBlock || (hasStallSignal && lockFrame != null) ->
                StallKind.CROSS_REGION_LOCK_CONTENTION to (lockFrame ?: "object monitor")
            netJdbcFrame != null -> StallKind.REGION_BLOCKING_NETWORK_JDBC to netJdbcFrame
            diskFrame != null -> StallKind.REGION_BLOCKING_DISK_IO to diskFrame
            hasStallSignal && regionizerTopFrame != null ->
                StallKind.REGIONIZER_BARRIER_STALL to regionizerTopFrame
            explicitRegionizerMsg -> StallKind.REGIONIZER_BARRIER_STALL to (regionizerTopFrame ?: "ThreadedRegionizer")
            else -> return null
        }

        val coords = REGION_COORDS_RE.find(joined)?.groupValues?.get(1)
        val seconds = STALL_SECONDS_RE.find(joined)?.groupValues?.get(1)
        val blame = SparkFlamegraphAnalyzer.attributeBranch(frameNames.asReversed(), plugins)

        val detail = buildString {
            append(kind.summary)
            if (coords != null) append(" in region ($coords)")
            if (seconds != null) append(" (${seconds}s stall)")
            append(" via ").append(triggerFrame)
            if (lockOwner != null) append(" (lock held by \"$lockOwner\")")
            if (blame != null) append(", triggered by ").append(blame)
            append('.')
        }

        val lockLines = rawLines.map { it.trim() }.filter { WAITING_LOCK_RE.containsMatchIn(it) || LOCK_OWNER_RE.containsMatchIn(it) }
        val evidence = (lockLines + frames.take(4).map { it.raw }).distinct().take(6)
            .ifEmpty { rawLines.take(3).map { it.trim() } }

        return StallTriageHit(
            line = startLine,
            discriminator = "${kind.slug}@${blame ?: triggerFrame.take(40)}",
            detail = detail,
            evidence = evidence,
        )
    }
}
