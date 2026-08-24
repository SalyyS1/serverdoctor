package com.salyvn.serverdoctor.input

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/** A key/value pair from a `.properties` file, with the 1-based line it was read from. */
data class PropertyEntry(val key: String, val value: String, val line: Int)

/**
 * `server.properties`, parsed the way a diagnostician needs it rather than the way
 * [java.util.Properties] does it: line numbers are kept, and a key that appears twice is preserved
 * twice so the duplicate can be reported. The JVM loader silently keeps the last one, which is
 * exactly the behaviour that makes a duplicated `online-mode` hard to spot by eye.
 */
class PropertiesSource(val path: Path, val entries: List<PropertyEntry>) {

    private val byKey: Map<String, List<PropertyEntry>> = entries.groupBy { it.key }

    /** The value the server would use: the last occurrence wins. */
    operator fun get(key: String): PropertyEntry? = byKey[key]?.last()

    fun duplicates(): Map<String, List<PropertyEntry>> = byKey.filterValues { it.size > 1 }

    fun bool(key: String): Boolean? = get(key)?.value?.trim()?.lowercase()?.let {
        when (it) {
            "true" -> true
            "false" -> false
            else -> null
        }
    }

    fun int(key: String): Int? = get(key)?.value?.trim()?.toIntOrNull()

    companion object {
        fun read(path: Path): PropertiesSource {
            val entries = mutableListOf<PropertyEntry>()
            Files.newBufferedReader(path, StandardCharsets.UTF_8).useLines { lines ->
                lines.forEachIndexed { index, raw ->
                    val trimmed = raw.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("!")) return@forEachIndexed
                    val split = trimmed.indexOf('=')
                    if (split <= 0) return@forEachIndexed
                    entries += PropertyEntry(
                        key = trimmed.substring(0, split).trim(),
                        // Values are taken verbatim after the first '='. Minecraft writes
                        // motd and level-seed here, both of which can contain '='.
                        value = trimmed.substring(split + 1).trim(),
                        line = index + 1,
                    )
                }
            }
            return PropertiesSource(path, entries)
        }
    }
}
