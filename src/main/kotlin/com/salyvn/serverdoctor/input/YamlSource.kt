package com.salyvn.serverdoctor.input

import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import org.yaml.snakeyaml.nodes.MappingNode
import org.yaml.snakeyaml.nodes.Node
import org.yaml.snakeyaml.nodes.ScalarNode
import org.yaml.snakeyaml.nodes.SequenceNode
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/** A scalar read from a YAML document, addressed by its dotted path, with the 1-based line. */
data class YamlEntry(val path: String, val value: String, val line: Int)

/**
 * A YAML document, flattened to dotted paths with line numbers. Used for server configs on disk and
 * for plugin descriptors inside jars.
 *
 * It is composed, not loaded: SnakeYAML builds the node tree and this class walks it. Nothing in the
 * document is turned into an object and no tag is resolved to a class, because these files come from
 * machines that are already behaving strangely, and from jars the person running this tool did not
 * compile.
 *
 * Composing also keeps the two things a linter needs and a loader throws away: the line each value
 * came from, and duplicate keys, which a loader silently collapses to the last one.
 */
class YamlSource(
    /** How this document should be named in a finding: a file path, or `Foo.jar!/plugin.yml`. */
    val label: String,
    val entries: List<YamlEntry>,
    /** Keys that appeared more than once under the same parent, in file order. */
    val duplicatePaths: List<YamlEntry>,
    /** Set when the document could not be parsed; the server would not read it either. */
    val parseError: String? = null,
) {

    private val byPath: Map<String, YamlEntry> = entries.associateBy { it.path }

    operator fun get(path: String): YamlEntry? = byPath[path]

    fun text(path: String): String? = byPath[path]?.value

    fun bool(path: String): Boolean? = text(path)?.lowercase()?.let {
        when (it) {
            "true", "yes", "on" -> true
            "false", "no", "off" -> false
            else -> null
        }
    }

    fun int(path: String): Int? = text(path)?.toIntOrNull()

    fun double(path: String): Double? = text(path)?.toDoubleOrNull()

    /** Every entry whose dotted path sits under [prefix]. */
    fun under(prefix: String): List<YamlEntry> = entries.filter { it.path.startsWith("$prefix.") }

    /** The immediate child names of [prefix]: world names, alias names, plugin names. */
    fun childrenOf(prefix: String): Set<String> = under(prefix)
        .mapNotNull {
            it.path.removePrefix("$prefix.").substringBefore('.').substringBefore('[')
                .takeIf(String::isNotEmpty)
        }
        .toSet()

    /**
     * A YAML list of scalars at [path], in order. Lists are flattened as `path[0]`, `path[1]`, so
     * this rebuilds them.
     */
    fun list(path: String): List<String> = entries
        .filter { it.path.startsWith("$path[") }
        .sortedBy { it.path.substringAfter('[').substringBefore(']').toIntOrNull() ?: 0 }
        .map { it.value }

    fun has(path: String): Boolean = byPath.containsKey(path) || entries.any { it.path.startsWith("$path.") || it.path.startsWith("$path[") }

    val ok: Boolean get() = parseError == null

    companion object {

        fun read(path: Path): YamlSource {
            val text = runCatching { Files.readString(path, StandardCharsets.UTF_8) }
                .getOrElse { return YamlSource(path.toString(), emptyList(), emptyList(), it.message ?: "unreadable") }
            return compose(path.toString(), text)
        }

        fun compose(label: String, text: String): YamlSource {
            val options = LoaderOptions().apply {
                // Duplicates are the point of the exercise, so parsing must not throw on them; they
                // are collected below and reported as findings instead.
                isAllowDuplicateKeys = true
                maxAliasesForCollections = 50
                isProcessComments = false
            }
            val entries = mutableListOf<YamlEntry>()
            val duplicates = mutableListOf<YamlEntry>()
            return try {
                val root = Yaml(SafeConstructor(options)).compose(text.reader())
                if (root != null) walk(root, "", entries, duplicates)
                YamlSource(label, entries, duplicates)
            } catch (failure: Exception) {
                // SnakeYAML's message names the line and the construct, which is more useful to the
                // reader than anything this tool would add. It arrives as several lines with a caret
                // diagram, and a finding is one line, so it is folded rather than trimmed.
                YamlSource(label, emptyList(), emptyList(), oneLine(failure.message ?: failure.toString()))
            }
        }

        /** SnakeYAML points at the column with a line of carets, which carries nothing on its own. */
        private fun oneLine(message: String): String = message
            .lineSequence()
            .map { it.trim() }
            .filter { line -> line.isNotEmpty() && line.any { it != '^' } }
            .joinToString("; ")

        private fun walk(
            node: Node,
            prefix: String,
            into: MutableList<YamlEntry>,
            duplicates: MutableList<YamlEntry>,
        ) {
            when (node) {
                is MappingNode -> {
                    val seen = mutableSetOf<String>()
                    for (tuple in node.value) {
                        val key = (tuple.keyNode as? ScalarNode)?.value ?: continue
                        val childPath = if (prefix.isEmpty()) key else "$prefix.$key"
                        if (!seen.add(key)) {
                            duplicates += YamlEntry(childPath, "", tuple.keyNode.startMark.line + 1)
                        }
                        walk(tuple.valueNode, childPath, into, duplicates)
                    }
                }

                is SequenceNode -> node.value.forEachIndexed { index, item ->
                    walk(item, "$prefix[$index]", into, duplicates)
                }

                is ScalarNode -> into += YamlEntry(prefix, node.value, node.startMark.line + 1)
            }
        }
    }
}
