package com.salyvn.serverdoctor.config

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.core.Severity
import com.salyvn.serverdoctor.input.YamlSource
import java.nio.file.Files

/**
 * Audits a server's configuration.
 *
 * The checks worth having are the ones that need more than one file. Offline mode is fine behind a
 * proxy and dangerous without one, and neither `server.properties` nor `paper-global.yml` knows the
 * other exists. So the audit reads them together and reports the combination, which is the thing that
 * actually decides whether a server is exposed.
 */
class ConfigAudit {

    fun analyse(configs: ServerConfigSet): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()

        configs.forkName?.let { facts["server"] = it }
        facts["files"] = buildList {
            configs.serverProperties?.let { add("server.properties") }
            configs.bukkit?.let { add("bukkit.yml") }
            configs.spigot?.let { add("spigot.yml") }
            configs.paperGlobal?.let { add("paper-global.yml") }
            configs.paperWorldDefaults?.let { add("paper-world-defaults.yml") }
            configs.extras.forEach { add(it.label.substringAfterLast('\\').substringAfterLast('/')) }
        }.joinToString(", ").ifEmpty { "none found" }

        checkParseable(configs, sink)
        checkDuplicateKeys(configs, sink)
        checkProxyAndOnlineMode(configs, sink, facts)
        checkUnsupportedSettings(configs, sink)
        checkConsoleAndProfiler(configs, sink)
        checkRcon(configs, sink)
        checkDistances(configs, sink, facts)
        checkWatchdog(configs, sink)
        checkPaperLayout(configs, sink)
        checkSecureProfile(configs, sink)
        checkEula(configs, sink)
        checkWorldDirectory(configs, sink, facts)
        checkAntiXray(configs, sink)
        checkChunkSystem(configs, sink)
        checkPaper26Schema(configs, sink)
        checkNetworkCompression(configs, sink)
        checkNettyThreads(configs, sink)
        checkItemComponentValidation(configs, sink)

        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = configs.describedSubject,
            subjectKind = if (configs.root != null) "server" else "config",
            findings = sink.findings(),
            facts = facts,
        )
    }

    private fun checkParseable(configs: ServerConfigSet, sink: FindingSink) {
        for (file in configs.yamlFiles) {
            val error = file.parseError ?: continue
            sink.add(
                rule = ConfigRules.CONFIG_NOT_PARSEABLE,
                location = file.label,
                detail = "The parser stopped: ${error.lineSequence().first().take(200)}",
            )
        }
    }

    private fun checkDuplicateKeys(configs: ServerConfigSet, sink: FindingSink) {
        for (file in configs.yamlFiles) {
            for (duplicate in file.duplicatePaths) {
                sink.add(
                    rule = ConfigRules.DUPLICATE_KEY,
                    location = "${file.label}:${duplicate.line}",
                    detail = "${duplicate.path} is defined more than once; the later one wins.",
                )
            }
        }
        configs.serverProperties?.duplicates()?.forEach { (key, entries) ->
            sink.add(
                rule = ConfigRules.DUPLICATE_KEY,
                location = "${configs.serverProperties.path}:${entries.last().line}",
                detail = "$key appears ${entries.size} times; the server uses \"${entries.last().value}\".",
                evidence = entries.map { "line ${it.line}: $key=${it.value}" },
            )
        }
    }

    private fun checkProxyAndOnlineMode(
        configs: ServerConfigSet,
        sink: FindingSink,
        facts: MutableMap<String, String>,
    ) {
        val onlineMode = configs.serverProperties?.bool("online-mode")
        val velocityEnabled = configs.paperGlobal?.bool("proxies.velocity.enabled") ?: false
        val velocitySecret = configs.paperGlobal?.text("proxies.velocity.secret")
        val bungeeEnabled = configs.spigot?.bool("settings.bungeecord") ?: false

        onlineMode?.let { facts["online-mode"] = it.toString() }
        if (velocityEnabled || bungeeEnabled) {
            facts["forwarding"] = listOfNotNull(
                "velocity".takeIf { velocityEnabled },
                "bungeecord".takeIf { bungeeEnabled },
            ).joinToString(" + ")
        }

        if (onlineMode == false && !velocityEnabled && !bungeeEnabled) {
            sink.add(
                rule = ConfigRules.OFFLINE_MODE_NO_PROXY,
                location = "${configs.serverProperties.path}:${configs.serverProperties.get("online-mode")?.line}",
                detail = "online-mode=false, and neither proxies.velocity.enabled nor " +
                    "settings.bungeecord is on. Any client can claim any username.",
            )
        }

        if (velocityEnabled && velocitySecret.isNullOrEmpty()) {
            sink.add(
                rule = ConfigRules.VELOCITY_SECRET_EMPTY,
                location = "${configs.paperGlobal.label}:${configs.paperGlobal.get("proxies.velocity.enabled")?.line}",
                detail = "proxies.velocity.enabled is true and proxies.velocity.secret is empty.",
            )
        }

        if (velocityEnabled && bungeeEnabled) {
            sink.add(
                rule = ConfigRules.TWO_FORWARDING_SCHEMES,
                location = "${configs.paperGlobal.label} + ${configs.spigot.label}",
                detail = "Velocity modern forwarding and BungeeCord forwarding are both enabled.",
            )
        }
    }

    /**
     * Every switch in this section ships off except the two that ship on, so the check is "does the
     * file disagree with the shipped default", not a hand-maintained list of dangerous keys.
     */
    private fun checkUnsupportedSettings(configs: ServerConfigSet, sink: FindingSink) {
        val global = configs.paperGlobal ?: return
        val entries = global.under("unsupported-settings")
        for (entry in entries) {
            val key = entry.path.removePrefix("unsupported-settings.")
            val value = entry.value.lowercase()
            val enabled = value == "true"
            val expected = key in DEFAULT_ON_UNSUPPORTED
            if (enabled == expected) continue
            sink.add(
                rule = ConfigRules.UNSUPPORTED_SETTING_ENABLED,
                location = "${global.label}:${entry.line}",
                detail = "unsupported-settings.$key is ${entry.value}, and it ships as $expected.",
                severityOverride = if (key in MILD_UNSUPPORTED) Severity.WARNING else null,
            )
        }
    }

    private fun checkConsoleAndProfiler(configs: ServerConfigSet, sink: FindingSink) {
        val global = configs.paperGlobal ?: return
        if (global.bool("console.has-all-permissions") == true) {
            sink.add(
                rule = ConfigRules.CONSOLE_ALL_PERMISSIONS,
                location = "${global.label}:${global["console.has-all-permissions"]?.line}",
                detail = "console.has-all-permissions is true.",
            )
        }
        if (global.bool("spark.enabled") == false) {
            sink.add(
                rule = ConfigRules.SPARK_DISABLED,
                location = "${global.label}:${global["spark.enabled"]?.line}",
                detail = "spark.enabled is false, so the bundled profiler is not available.",
            )
        }
    }

    private fun checkRcon(configs: ServerConfigSet, sink: FindingSink) {
        val properties = configs.serverProperties ?: return
        if (properties.bool("enable-rcon") != true) return
        val password = properties["rcon.password"]?.value
        if (password.isNullOrBlank()) {
            sink.add(
                rule = ConfigRules.RCON_WITHOUT_PASSWORD,
                location = "${properties.path}:${properties["enable-rcon"]?.line}",
                detail = "enable-rcon=true with an empty rcon.password on port " +
                    "${properties["rcon.port"]?.value ?: "25575"}.",
            )
        }
    }

    private fun checkDistances(
        configs: ServerConfigSet,
        sink: FindingSink,
        facts: MutableMap<String, String>,
    ) {
        val properties = configs.serverProperties ?: return
        val view = properties.int("view-distance")
        val simulation = properties.int("simulation-distance")
        if (view != null && simulation != null) {
            facts["distances"] = "view $view, simulation $simulation"
            if (simulation > view) {
                sink.add(
                    rule = ConfigRules.SIMULATION_OVER_VIEW,
                    location = "${properties.path}:${properties["simulation-distance"]?.line}",
                    detail = "simulation-distance=$simulation is larger than view-distance=$view.",
                )
            }
        }
    }

    private fun checkWatchdog(configs: ServerConfigSet, sink: FindingSink) {
        val spigot = configs.spigot ?: return
        val entry = spigot["settings.timeout-time"] ?: return
        val timeout = entry.value.toIntOrNull() ?: return
        when {
            timeout >= WATCHDOG_TIMEOUT_SUSPICIOUS -> sink.add(
                rule = ConfigRules.WATCHDOG_TIMEOUT_HIGH,
                location = "${spigot.label}:${entry.line}",
                detail = "settings.timeout-time is $timeout seconds; the default is 60.",
            )

            timeout <= 0 -> sink.add(
                rule = ConfigRules.WATCHDOG_TIMEOUT_HIGH,
                location = "${spigot.label}:${entry.line}",
                detail = "settings.timeout-time is $timeout, which does not disable the watchdog: " +
                    "Paper substitutes 300 seconds.",
                severityOverride = Severity.INFO,
            )
        }
    }

    private fun checkPaperLayout(configs: ServerConfigSet, sink: FindingSink) {
        val legacy = configs.legacyPaperYml
        if (legacy != null && configs.paperGlobal != null) {
            sink.add(
                rule = ConfigRules.LEGACY_PAPER_YML,
                location = legacy.toString(),
                detail = "config/paper-global.yml is what the server reads; this file is not.",
            )
        }
        for (file in listOfNotNull(configs.paperGlobal, configs.paperWorldDefaults)) {
            if (!file.ok) continue
            if (file["version"] == null) {
                sink.add(
                    rule = ConfigRules.NO_CONFIG_VERSION,
                    location = file.label,
                    detail = "No version key, so Paper cannot tell which migrations this file has had.",
                )
            }
        }
    }

    private fun checkSecureProfile(configs: ServerConfigSet, sink: FindingSink) {
        val properties = configs.serverProperties ?: return
        if (properties.bool("enforce-secure-profile") == false) {
            sink.add(
                rule = ConfigRules.SECURE_PROFILE_DISABLED,
                location = "${properties.path}:${properties["enforce-secure-profile"]?.line}",
                detail = "enforce-secure-profile=false, so unsigned chat is accepted.",
            )
        }
    }

    private fun checkEula(configs: ServerConfigSet, sink: FindingSink) {
        val root = configs.root ?: return
        val eula = configs.eula
        if (eula == null) {
            // Only reportable for a directory that looks like a server; an arbitrary folder is not
            // missing an eula.txt.
            if (configs.serverProperties != null) {
                sink.add(
                    rule = ConfigRules.EULA_NOT_ACCEPTED,
                    location = root.resolve("eula.txt").toString(),
                    detail = "No eula.txt next to server.properties.",
                )
            }
            return
        }
        val accepted = runCatching { Files.readAllLines(eula) }.getOrDefault(emptyList())
            .any { it.replace(" ", "").lowercase().startsWith("eula=true") }
        if (!accepted) {
            sink.add(
                rule = ConfigRules.EULA_NOT_ACCEPTED,
                location = eula.toString(),
                detail = "eula.txt does not contain eula=true.",
            )
        }
    }

    private fun checkWorldDirectory(
        configs: ServerConfigSet,
        sink: FindingSink,
        facts: MutableMap<String, String>,
    ) {
        val root = configs.root ?: return
        val level = configs.serverProperties?.get("level-name")?.value ?: return
        facts["level-name"] = level
        val world = root.resolve(level)
        if (!Files.isDirectory(world)) {
            sink.add(
                rule = ConfigRules.WORLD_DIRECTORY_MISSING,
                location = "${configs.serverProperties.path}:${configs.serverProperties["level-name"]?.line}",
                detail = "level-name=$level, but $world does not exist. The server would generate a " +
                    "new world under that name.",
            )
        }
    }

    private fun checkAntiXray(configs: ServerConfigSet, sink: FindingSink) {
        val candidates = listOfNotNull(configs.paperWorldDefaults) + configs.extras
        for (file in candidates) {
            if (file.bool("anticheat.anti-xray.enabled") != true) continue
            val mode = file.text("anticheat.anti-xray.engine-mode") ?: "1"
            sink.add(
                rule = ConfigRules.ANTI_XRAY_ENABLED,
                location = "${file.label}:${file["anticheat.anti-xray.enabled"]?.line}",
                detail = "anti-xray is enabled with engine-mode $mode.",
            )
        }
    }

    private fun checkChunkSystem(configs: ServerConfigSet, sink: FindingSink) {
        val global = configs.paperGlobal ?: return
        global["chunk-system.io-threads"]?.let { entry ->
            val ioThreads = entry.value.toIntOrNull()
            if (ioThreads != null && (ioThreads == 0 || ioThreads < -1)) {
                sink.add(
                    rule = ConfigRules.CHUNK_SYSTEM_BOTTLENECK,
                    location = "${global.label}:${entry.line}",
                    detail = "chunk-system.io-threads is $ioThreads (default is -1); 0 disables dedicated async region I/O.",
                )
            }
        }
        global["chunk-system.worker-threads"]?.let { entry ->
            val workers = entry.value.toIntOrNull()
            if (workers != null && (workers == 0 || workers == 1 || workers < -1)) {
                sink.add(
                    rule = ConfigRules.CHUNK_SYSTEM_BOTTLENECK,
                    location = "${global.label}:${entry.line}",
                    detail = "chunk-system.worker-threads is $workers (default is -1), serialising Moonrise chunk generation and lighting.",
                )
            }
        }
    }

    private fun checkPaper26Schema(configs: ServerConfigSet, sink: FindingSink) {
        val candidates = listOfNotNull(configs.paperGlobal, configs.paperWorldDefaults)
        val legacyRoots = listOf("timings", "chunk-loading", "messages")
        for (file in candidates) {
            if (!file.ok) continue
            val ver = file.int("version") ?: file.int("_version")
            if (ver != null && ver < 30) {
                sink.add(
                    rule = ConfigRules.PAPER_26_CONFIG_SCHEMA_VERSION,
                    location = "${file.label}:${file["version"]?.line ?: file["_version"]?.line ?: 1}",
                    detail = "Configuration schema version is $ver (Paper 26.3 expects version 30 or higher); older schemas risk unmigrated config defaults.",
                )
            }
            for (rootKey in legacyRoots) {
                if (file.has(rootKey)) {
                    val entry = file.under(rootKey).firstOrNull() ?: file[rootKey]
                    sink.add(
                        rule = ConfigRules.PAPER_26_CONFIG_SCHEMA_VERSION,
                        location = "${file.label}:${entry?.line ?: 1}",
                        detail = "Legacy root section '$rootKey' is deprecated in Paper 26.3; use 'chunk-system' and bundled Spark instead.",
                    )
                }
            }
        }
    }

    private fun checkNetworkCompression(configs: ServerConfigSet, sink: FindingSink) {
        val props = configs.serverProperties ?: return
        val entry = props["network-compression-threshold"] ?: return
        val threshold = entry.value.toIntOrNull() ?: return
        val online = configs.serverProperties.bool("online-mode") != false
        if (threshold in 0..64) {
            sink.add(
                rule = ConfigRules.NETWORK_COMPRESSION_HAZARD,
                location = "${props.path}:${entry.line}",
                detail = "network-compression-threshold is $threshold. Compressing packets <= 64 bytes wastes CPU on small packets with negligible compression gains.",
            )
        } else if (threshold == -1 && online) {
            sink.add(
                rule = ConfigRules.NETWORK_COMPRESSION_HAZARD,
                location = "${props.path}:${entry.line}",
                detail = "network-compression-threshold is -1 (compression disabled) on an online-mode server. Chunk and entity bursts may saturate network bandwidth.",
            )
        } else if (threshold > 1024) {
            sink.add(
                rule = ConfigRules.NETWORK_COMPRESSION_HAZARD,
                location = "${props.path}:${entry.line}",
                detail = "network-compression-threshold is $threshold (> 1024). Packets up to ${threshold} bytes are sent uncompressed, increasing socket buffer strain.",
            )
        }
    }

    private fun checkNettyThreads(configs: ServerConfigSet, sink: FindingSink) {
        val spigot = configs.spigot ?: return
        val entry = spigot["settings.netty-threads"] ?: return
        val threads = entry.value.toIntOrNull() ?: return
        if (threads <= 1) {
            sink.add(
                rule = ConfigRules.NETTY_THREADS_BOTTLENECK,
                location = "${spigot.label}:${entry.line}",
                detail = "settings.netty-threads is $threads. Pinning Netty to 1 thread serialises packet encode/decode and socket flushes across all connected players.",
            )
        }
    }

    private fun checkItemComponentValidation(configs: ServerConfigSet, sink: FindingSink) {
        val global = configs.paperGlobal ?: return
        val bookSelectors = global.bool("item-validation.resolve-selectors-in-books")
        if (bookSelectors == true) {
            sink.add(
                rule = ConfigRules.PAPER_26_ITEM_COMPONENT_VALIDATION,
                location = "${global.label}:${global["item-validation.resolve-selectors-in-books"]?.line ?: 1}",
                detail = "item-validation.resolve-selectors-in-books is set to true. Resolving target selectors in books enables malicious book NBT payloads to stall tick threads.",
            )
        }
        val maxComponentSize = global.int("item-validation.max-component-size")
        if (maxComponentSize != null && (maxComponentSize <= 0 || maxComponentSize > 67108864)) {
            sink.add(
                rule = ConfigRules.PAPER_26_ITEM_COMPONENT_VALIDATION,
                location = "${global.label}:${global["item-validation.max-component-size"]?.line ?: 1}",
                detail = "item-validation.max-component-size is $maxComponentSize. Disabling or over-allocating component validation exposes memory to oversized component payload exploits.",
            )
        }
    }

    private companion object {
        /**
         * The switches in unsupported-settings that ship on. Everything else in the section ships
         * off, so the check compares against this set instead of listing every dangerous key.
         */
        val DEFAULT_ON_UNSUPPORTED = setOf(
            "perform-username-validation",
            "update-equipment-on-player-actions",
        )

        /** Enabled by choice on plenty of servers and not an exploit, so reported one tier down. */
        val MILD_UNSUPPORTED = setOf(
            "skip-vanilla-damage-tick-when-shield-blocked",
            "skip-tripwire-hook-placement-validation",
        )

        const val WATCHDOG_TIMEOUT_SUSPICIOUS = 300
    }

    /** Convenience for [YamlSource] lookups that need a nullable receiver in the checks above. */
    private operator fun YamlSource?.get(path: String) = this?.get(path)
}
