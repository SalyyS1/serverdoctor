package com.salyvn.serverdoctor.config

import com.salyvn.serverdoctor.input.PropertiesSource
import com.salyvn.serverdoctor.input.YamlSource
import java.nio.file.Files
import java.nio.file.Path

/**
 * The configuration files a server actually has, gathered from one directory.
 *
 * Which files exist is itself information: `config/paper-global.yml` present means a modern Paper;
 * `paper.yml` in the root means a migration that was never finished; `purpur.yml` means a fork whose
 * defaults differ from the ones every guide quotes. Nothing is invented when a file is absent - the
 * audit simply has less to say.
 */
class ServerConfigSet(
    val root: Path?,
    val serverProperties: PropertiesSource? = null,
    val bukkit: YamlSource? = null,
    val spigot: YamlSource? = null,
    val paperGlobal: YamlSource? = null,
    val paperWorldDefaults: YamlSource? = null,
    /** purpur.yml, pufferfish.yml, commands.yml, permissions.yml and any per-world paper config. */
    val extras: List<YamlSource> = emptyList(),
    /** A pre-split paper.yml in the server root, which modern Paper does not read. */
    val legacyPaperYml: Path? = null,
    val eula: Path? = null,
    val forkName: String? = null,
) {

    val yamlFiles: List<YamlSource>
        get() = listOfNotNull(bukkit, spigot, paperGlobal, paperWorldDefaults) + extras

    val isEmpty: Boolean get() = serverProperties == null && yamlFiles.isEmpty()

    val describedSubject: String get() = root?.toString() ?: (serverProperties?.path?.toString() ?: "configuration")

    companion object {

        private val EXTRA_NAMES = listOf(
            "purpur.yml",
            "pufferfish.yml",
            "commands.yml",
            "permissions.yml",
            "help.yml",
        )

        fun read(root: Path): ServerConfigSet {
            fun yaml(relative: String): YamlSource? {
                val path = root.resolve(relative)
                return if (Files.isRegularFile(path)) YamlSource.read(path) else null
            }

            val properties = root.resolve("server.properties")
                .takeIf { Files.isRegularFile(it) }
                ?.let { PropertiesSource.read(it) }

            val extras = mutableListOf<YamlSource>()
            for (name in EXTRA_NAMES) yaml(name)?.let { extras += it }

            // A world's own overrides sit next to its data, so the world name has to come from
            // server.properties rather than from a fixed path.
            properties?.get("level-name")?.value?.let { world ->
                yaml("$world/paper-world.yml")?.let { extras += it }
            }

            val fork = when {
                Files.isRegularFile(root.resolve("purpur.yml")) -> "purpur.yml present"
                Files.isRegularFile(root.resolve("pufferfish.yml")) -> "pufferfish.yml present"
                Files.isRegularFile(root.resolve("config/paper-global.yml")) -> "paper"
                Files.isRegularFile(root.resolve("spigot.yml")) -> "spigot"
                else -> null
            }

            return ServerConfigSet(
                root = root,
                serverProperties = properties,
                bukkit = yaml("bukkit.yml"),
                spigot = yaml("spigot.yml"),
                paperGlobal = yaml("config/paper-global.yml"),
                paperWorldDefaults = yaml("config/paper-world-defaults.yml"),
                extras = extras,
                legacyPaperYml = root.resolve("paper.yml").takeIf { Files.isRegularFile(it) },
                eula = root.resolve("eula.txt").takeIf { Files.isRegularFile(it) },
                forkName = fork,
            )
        }

        /** For `--file` use: audit whatever was handed over, matched by file name. */
        fun of(paths: List<Path>): ServerConfigSet {
            var properties: PropertiesSource? = null
            var bukkit: YamlSource? = null
            var spigot: YamlSource? = null
            var global: YamlSource? = null
            var worldDefaults: YamlSource? = null
            val extras = mutableListOf<YamlSource>()

            for (path in paths) {
                when (path.fileName.toString().lowercase()) {
                    "server.properties" -> properties = PropertiesSource.read(path)
                    "bukkit.yml" -> bukkit = YamlSource.read(path)
                    "spigot.yml" -> spigot = YamlSource.read(path)
                    "paper-global.yml" -> global = YamlSource.read(path)
                    "paper-world-defaults.yml" -> worldDefaults = YamlSource.read(path)
                    else -> if (path.fileName.toString().endsWith(".yml")) extras += YamlSource.read(path)
                }
            }

            return ServerConfigSet(
                root = null,
                serverProperties = properties,
                bukkit = bukkit,
                spigot = spigot,
                paperGlobal = global,
                paperWorldDefaults = worldDefaults,
                extras = extras,
            )
        }
    }
}
