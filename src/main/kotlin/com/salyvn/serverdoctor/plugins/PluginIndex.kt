package com.salyvn.serverdoctor.plugins

import java.nio.file.Files
import java.nio.file.Path

/**
 * The plugins a server has installed, indexed the three ways a log line can be traced back to one:
 * by declared name, by the bracketed label the server logs under, and by the package a stack frame
 * lives in.
 *
 * All three are best-effort and the reasons are worth stating, because a confident wrong attribution
 * is worse than none:
 *
 * - the bracketed label is `plugin.yml: prefix` when set, which need not resemble the plugin name;
 * - a shaded plugin's frames may sit under a library's package, or a library's frames under the
 *   plugin's, depending on how it was relocated;
 * - two plugins can share a package prefix, in which case the longest match wins and may still be
 *   the wrong one.
 */
class PluginIndex(val jars: List<PluginJar>) {

    private val byName: Map<String, PluginJar> = jars
        .mapNotNull { jar -> jar.descriptor?.name?.let { it.lowercase() to jar } }
        .toMap()

    private val byLabel: Map<String, PluginJar> = buildMap {
        for (jar in jars) {
            val descriptor = jar.descriptor ?: continue
            descriptor.name?.let { put(it.lowercase(), jar) }
            descriptor.prefix?.let { put(it.lowercase(), jar) }
        }
    }

    /** Longest package first, so `com.foo.plugin.extra` is preferred over `com.foo`. */
    private val byPackage: List<Pair<String, PluginJar>> = jars
        .mapNotNull { jar -> jar.descriptor?.mainPackage?.let { it to jar } }
        .sortedByDescending { it.first.length }

    val isEmpty: Boolean get() = jars.isEmpty()

    fun plugin(name: String): PluginJar? = byName[name.lowercase()]

    /** Resolves the `[Something]` a log line was written under. */
    fun byLoggerLabel(label: String): PluginJar? = byLabel[label.lowercase()]

    /** Resolves the owner of a stack frame's class, when one package matches. */
    fun owningPlugin(className: String): PluginJar? =
        byPackage.firstOrNull { (prefix, _) -> className == prefix || className.startsWith("$prefix.") }?.second

    /** Names declared by one plugin as hard dependencies but absent from this directory. */
    fun missingDependencies(): Map<PluginJar, List<String>> = jars.mapNotNull { jar ->
        val descriptor = jar.descriptor ?: return@mapNotNull null
        val missing = descriptor.depend.filter { plugin(it) == null }
        if (missing.isEmpty()) null else jar to missing
    }.toMap()

    /** Plugin names claimed by more than one jar, which the server refuses to disambiguate. */
    fun duplicateNames(): Map<String, List<PluginJar>> = jars
        .filter { it.descriptor?.name != null }
        .groupBy { it.descriptor!!.name!! }
        .filterValues { it.size > 1 }

    companion object {

        /** Reads every `*.jar` directly inside [directory]. Subdirectories are the server's own. */
        fun read(directory: Path): PluginIndex {
            if (!Files.isDirectory(directory)) return PluginIndex(emptyList())
            val jars = Files.list(directory).use { stream ->
                stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".jar", ignoreCase = true) }
                    .sorted()
                    .toList()
            }
            return PluginIndex(jars.map { PluginJar.read(it) })
        }

        val EMPTY = PluginIndex(emptyList())
    }
}
