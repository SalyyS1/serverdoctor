package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.plugins.PluginIndex

/**
 * Trace-level thread affinity analyzer for PaperMC/Folia's four scheduler domains:
 * - `GlobalRegionScheduler` (world time, weather, console, global rules; owns zero chunks/entities)
 * - `RegionScheduler` (chunk-coordinate island pinned at schedule time; does not follow moving entities)
 * - `EntityScheduler` (pinned to one entity's current owning TickRegionThread; retires on entity removal)
 * - `FoliaAsyncScheduler` (off-tick worker pool; owns zero world, chunk, entity, or global state)
 */
object FoliaAffinityAnalyzer {

    enum class SchedulerDomain(val label: String, val slug: String) {
        GLOBAL_REGION("GlobalRegionScheduler", "global-region"),
        CHUNK_REGION("RegionScheduler", "chunk-region"),
        ENTITY_SCHEDULER("EntityScheduler", "entity-scheduler"),
        FOLIA_ASYNC("FoliaAsyncScheduler", "folia-async"),
    }

    enum class TargetStateKind(val label: String, val prescribedScheduler: String) {
        CHUNK_OR_BLOCK("chunk/block world state", "RegionScheduler.execute(plugin, location, ...)"),
        ENTITY_MUTATION("entity/player regional state", "entity.getScheduler().run(plugin, task, retired)"),
        WORLD_OR_REGISTRY("regionized world/server state", "RegionScheduler, EntityScheduler, or GlobalRegionScheduler"),
    }

    data class AffinityMismatchHit(
        val discriminator: String,
        val domain: SchedulerDomain,
        val targetKind: TargetStateKind,
        val blamedPlugin: String?,
        val detail: String,
        val evidence: List<String>,
    )

    data class SchedulerFaultHit(
        val discriminator: String,
        val blamedPlugin: String?,
        val detail: String,
        val evidence: List<String>,
    )

    private val ENTITY_SINKS = listOf(
        "CraftEntity.",
        "CraftLivingEntity.",
        "CraftPlayer.",
        "CraftMob.",
        "ServerPlayer.",
        "LivingEntity.",
        "Entity.set",
        "Entity.teleport",
        "Entity.remove",
        "Entity.addPassenger",
        "ServerLevel.addFreshEntity",
    )

    private val CHUNK_BLOCK_SINKS = listOf(
        "ServerLevel.getBlockState",
        "ServerLevel.setBlock",
        "ServerLevel.getChunk",
        "ServerLevel.removeBlock",
        "CraftBlock.",
        "CraftChunk.",
        "CraftWorld.getBlockAt",
        "CraftWorld.getChunkAt",
        "LevelChunk.",
        "RegionizedWorldData.",
    )

    private val MERGE_THRASH_RE = Regex(
        """(?:ThreadedRegionizer[^\n]*(?:merge|split)[^\n]*(\d+)\s*(?:chunks|sections|regions)|Region\s+merge[^\n]*exceeded|RegionizedTaskQueue[^\n]*(?:backlog|overflow|saturated|dropped)|retired\s+entity\s+scheduler\s+task)""",
        RegexOption.IGNORE_CASE,
    )

    private val TASK_EXCEPTION_MSG_RE = Regex(
        """(?:Task\s+#?\S*\s+for\s+([^\n]+?)\s+generated an exception|Unhandled exception[^\n]*(?:EntityScheduler|RegionScheduler|GlobalRegionScheduler|FoliaAsyncScheduler|RegionizedTaskQueue)|Exception in thread\s+"Folia\s+[^\"]+")""",
        RegexOption.IGNORE_CASE,
    )

    fun inferSchedulerDomain(event: LogEvent): SchedulerDomain? {
        // 1. Prefer explicit Folia scheduler dispatch frames on the call stack (strongest evidence).
        for (frame in event.frames) {
            val cls = frame.className
            when {
                cls.contains("FoliaGlobalRegionScheduler") ||
                    cls.contains("GlobalRegionScheduler") -> return SchedulerDomain.GLOBAL_REGION

                cls.contains("FoliaAsyncScheduler") -> return SchedulerDomain.FOLIA_ASYNC

                cls.contains("EntityScheduler") -> return SchedulerDomain.ENTITY_SCHEDULER

                cls.contains("FoliaRegionScheduler") ||
                    cls.contains("RegionizedTaskQueue\$RegionTaskQueueData") -> return SchedulerDomain.CHUNK_REGION
            }
        }

        // 2. Fallback to explicit Folia Global or Folia Async thread names.
        val thread = event.thread ?: return null
        return when {
            thread.contains("Global Region Scheduler", ignoreCase = true) ||
                thread.contains("GlobalRegionScheduler", ignoreCase = true) -> SchedulerDomain.GLOBAL_REGION

            thread.contains("Folia Async Scheduler", ignoreCase = true) ||
                thread.contains("FoliaAsyncScheduler", ignoreCase = true) -> SchedulerDomain.FOLIA_ASYNC

            else -> null
        }
    }

    /**
     * Detects cross-context Folia scheduler affinity violations (`L033`) where the executing Folia
     * scheduler domain (`GlobalRegionScheduler`, `RegionScheduler`, `EntityScheduler`, or
     * `FoliaAsyncScheduler`) conflicts with the state owner of the target Bukkit/NMS operation.
     */
    fun analyzeAffinityMismatch(event: LogEvent, plugins: PluginIndex = PluginIndex.EMPTY): AffinityMismatchHit? {
        val domain = inferSchedulerDomain(event) ?: return null
        val text = event.fullText
        val frameSigs = event.frames.map { "${it.className}.${it.method}" }

        val hasTickThreadCheck = text.contains("TickThread") ||
            text.contains("failed main thread check", ignoreCase = true) ||
            text.contains("failed region thread check", ignoreCase = true) ||
            text.contains("off-owning region", ignoreCase = true) ||
            text.contains("not owned by current region", ignoreCase = true) ||
            text.contains("Cannot read world asynchronously", ignoreCase = true) ||
            text.contains("Cannot modify world asynchronously", ignoreCase = true) ||
            text.contains("Cannot access entity", ignoreCase = true) ||
            text.contains("Must use teleportAsync", ignoreCase = true)

        val entitySink = frameSigs.firstOrNull { sig -> ENTITY_SINKS.any { tok -> sig.contains(tok) } }
        val chunkSink = frameSigs.firstOrNull { sig -> CHUNK_BLOCK_SINKS.any { tok -> sig.contains(tok) } }

        val targetKind: TargetStateKind = when (domain) {
            SchedulerDomain.GLOBAL_REGION -> when {
                entitySink != null || text.contains("entity", ignoreCase = true) && hasTickThreadCheck ->
                    TargetStateKind.ENTITY_MUTATION
                chunkSink != null || hasTickThreadCheck ->
                    TargetStateKind.CHUNK_OR_BLOCK
                else -> return null
            }

            SchedulerDomain.FOLIA_ASYNC -> when {
                entitySink != null -> TargetStateKind.ENTITY_MUTATION
                chunkSink != null -> TargetStateKind.CHUNK_OR_BLOCK
                hasTickThreadCheck -> TargetStateKind.WORLD_OR_REGISTRY
                else -> return null
            }

            SchedulerDomain.CHUNK_REGION -> {
                // Fixed-coordinate RegionScheduler touching an entity that drifted to another region,
                // or touching an adjacent unowned chunk outside the scheduled region island.
                if (!hasTickThreadCheck) return null
                when {
                    entitySink != null || text.contains("entity", ignoreCase = true) -> TargetStateKind.ENTITY_MUTATION
                    chunkSink != null || text.contains("chunk", ignoreCase = true) || text.contains("block", ignoreCase = true) ->
                        TargetStateKind.CHUNK_OR_BLOCK
                    else -> return null
                }
            }

            SchedulerDomain.ENTITY_SCHEDULER -> {
                // EntityScheduler callback mutating distant/unloaded chunk coordinates outside the entity's region.
                if (!hasTickThreadCheck) return null
                if (chunkSink != null || text.contains("block", ignoreCase = true) || text.contains("chunk", ignoreCase = true)) {
                    TargetStateKind.CHUNK_OR_BLOCK
                } else {
                    TargetStateKind.ENTITY_MUTATION
                }
            }
        }

        val blame = LogTriage.attribute(event, plugins)
        val sinkFrame = entitySink ?: chunkSink ?: frameSigs.firstOrNull { !it.contains("TickThread.") } ?: "world access"
        val schedulerFrame = frameSigs.firstOrNull {
            it.contains("FoliaGlobalRegionScheduler") ||
                it.contains("GlobalRegionScheduler") ||
                it.contains("FoliaRegionScheduler") ||
                it.contains("EntityScheduler") ||
                it.contains("FoliaAsyncScheduler")
        }

        val detail = buildString {
            append(domain.label)
            append(" task touched ")
            append(targetKind.label)
            append(" (").append(sinkFrame.substringAfterLast('/', sinkFrame)).append(')')
            if (blame != null) append(" via $blame")
            append("; dispatch on ").append(targetKind.prescribedScheduler).append(" instead.")
        }

        val evidence = buildList {
            if (schedulerFrame != null) add("scheduler: $schedulerFrame")
            for (f in event.frames.take(4)) add(f.raw)
            if (isEmpty()) add(event.message.trim())
        }

        return AffinityMismatchHit(
            discriminator = "${domain.slug}->${targetKind.name.lowercase()}@${blame ?: "unknown"}",
            domain = domain,
            targetKind = targetKind,
            blamedPlugin = blame,
            detail = detail,
            evidence = evidence,
        )
    }

    /**
     * Detects uncaught Folia scheduler task exceptions and `RegionizedTaskQueue` / `ThreadedRegionizer`
     * task backlog or super-region merge thrashing (`L034`), excluding Paper `CraftScheduler` and
     * events already classified as TickThread ownership violations (`L017` / `L033`).
     */
    fun analyzeSchedulerFaultOrBacklog(event: LogEvent, plugins: PluginIndex = PluginIndex.EMPTY): SchedulerFaultHit? {
        val text = event.fullText
        if (text.contains("AsyncCatcher") || text.contains("TickThread.ensureTickThread") ||
            text.contains("Must use teleportAsync") || text.contains("CraftScheduler is not supported")
        ) {
            return null
        }

        MERGE_THRASH_RE.find(text)?.let { match ->
            val count = match.groupValues.getOrNull(1)?.toIntOrNull()
            if (count != null && count < 128 && text.contains("ThreadedRegionizer", ignoreCase = true) && !event.isProblem) {
                return null
            }
            val blame = LogTriage.attribute(event, plugins)
            return SchedulerFaultHit(
                discriminator = "folia-queue-or-merge@${blame ?: "regionizer"}",
                blamedPlugin = blame,
                detail = buildString {
                    append("Folia scheduler queue or ThreadedRegionizer merge pressure: ")
                    append(event.message.trim().take(150))
                    if (blame != null) append(" (involving $blame)")
                    append('.')
                },
                evidence = event.frames.take(3).map { it.raw }.ifEmpty { listOf(event.message.trim()) },
            )
        }

        val domain = inferSchedulerDomain(event)
        val isFoliaThread = event.thread?.let {
            it.contains("Folia", ignoreCase = true) ||
                it.contains("Region Scheduler Thread", ignoreCase = true) ||
                it.contains("Global Region Scheduler", ignoreCase = true) ||
                it.contains("TickRegionThread", ignoreCase = true)
        } == true

        if (domain == null && !isFoliaThread) return null
        if (event.message.contains("Could not pass event ")) return null
        if (event.message.contains("DO NOT REPORT THIS TO FOLIA")) return null

        val taskMatch = TASK_EXCEPTION_MSG_RE.find(text)
        val hasSchedulerException = event.isProblem && event.exceptions.isNotEmpty() && domain != null
        if (taskMatch == null && !hasSchedulerException) return null

        val namedPlugin = taskMatch?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
        val blame = namedPlugin ?: LogTriage.attribute(event, plugins)
        val exception = event.exceptions.firstOrNull()
        val ctxName = domain?.label ?: (event.thread ?: "Folia scheduler")

        return SchedulerFaultHit(
            discriminator = "folia-task-exc@${blame ?: ctxName}:${exception ?: "error"}",
            blamedPlugin = blame,
            detail = buildString {
                append("Uncaught exception in ").append(ctxName).append(" task")
                if (blame != null) append(" for $blame")
                if (exception != null) append(": $exception")
                append('.')
            },
            evidence = event.frames.take(4).map { it.raw }.ifEmpty { listOf(event.message.trim()) },
        )
    }
}
