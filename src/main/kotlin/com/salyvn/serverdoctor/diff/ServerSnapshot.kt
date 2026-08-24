package com.salyvn.serverdoctor.diff

import com.salyvn.serverdoctor.config.ServerConfigSet
import com.salyvn.serverdoctor.flags.JvmCommandLine
import com.salyvn.serverdoctor.flags.StartScriptReader
import com.salyvn.serverdoctor.plugins.PluginIndex
import com.salyvn.serverdoctor.plugins.PluginJar
import java.nio.file.Files
import java.nio.file.Path

/**
 * One server reduced to the things worth comparing against another: its configuration values, the jars
 * it has, and the command line it starts with.
 *
 * Deliberately flat. A diff is only useful if both sides are read the same way, so everything is
 * normalised to `name -> value` here and no side keeps a structure the other might not have.
 */
class ServerSnapshot(
    val root: Path,
    /** `server.properties` as key to value. */
    val properties: Map<String, String>,
    /** File name to its flattened `dotted.path` to value. */
    val configFiles: Map<String, Map<String, String>>,
    val plugins: List<PluginJar>,
    val flags: JvmCommandLine?,
    val flagsSource: String?,
) {

    val label: String get() = root.fileName?.toString() ?: root.toString()

    /** Plugins keyed on the name they declare, falling back to the file name. */
    val pluginsByName: Map<String, PluginJar> = plugins.associateBy { it.displayName.lowercase() }

    companion object {

        fun read(root: Path): ServerSnapshot {
            val configs = ServerConfigSet.read(root)

            val properties = configs.serverProperties
                ?.entries
                ?.associate { it.key to it.value }
                ?: emptyMap()

            val files = configs.yamlFiles.associate { source ->
                Path.of(source.label).fileName.toString() to source.entries.associate { it.path to it.value }
            }

            val pluginsDirectory = root.resolve("plugins")
            val plugins = if (Files.isDirectory(pluginsDirectory)) PluginIndex.read(pluginsDirectory).jars else emptyList()

            val script = StartScriptReader.findScript(root)
            val command = script?.let { StartScriptReader.readCommand(it) }

            return ServerSnapshot(
                root = root,
                properties = properties,
                configFiles = files,
                plugins = plugins,
                flags = command?.let { JvmCommandLine.parse(it) },
                flagsSource = script?.fileName?.toString(),
            )
        }
    }
}
