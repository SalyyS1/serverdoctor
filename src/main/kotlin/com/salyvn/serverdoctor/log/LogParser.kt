package com.salyvn.serverdoctor.log

import com.salyvn.serverdoctor.input.LogSource

/** What the parser saw, reported so the audit can say how much of the file it actually read. */
data class LogParseStats(
    val lines: Int,
    val events: Int,
    val truncated: Boolean,
    /** Which header shape matched most often: `paper`, `legacy`, `dated`, or null for none. */
    val dominantFormat: String?,
    /** Header shapes that matched at least once, with counts. Panels mix formats. */
    val formatCounts: Map<String, Int>,
)

/**
 * Turns log lines into [LogEvent]s.
 *
 * Three things make real logs harder than the format suggests, and all three are handled here:
 *
 * 1. Hosting panels wrap server output. Pterodactyl and friends inject ANSI colour and their own
 *    daemon lines, and Docker prefixes an ISO timestamp and a stream name. A parser that assumes
 *    the vanilla shape sees none of the content.
 * 2. There is more than one header shape in the wild - the modern `[time] [thread/LEVEL]:`, the
 *    older `[time LEVEL]:`, and dated variants that hosts configure.
 * 3. An exception is one event across many lines, so anything that does not look like a header
 *    belongs to the event above it.
 *
 * Events are handed to a callback rather than collected, because a crash-looping server produces
 * logs far larger than the analysis of them.
 */
class LogParser {

    fun parse(source: LogSource, onEvent: (LogEvent) -> Unit): LogParseStats {
        var events = 0
        val formats = mutableMapOf<String, Int>()

        var pendingHeader: Header? = null
        var pendingStart = 0
        val continuation = mutableListOf<String>()

        fun flush() {
            val header = pendingHeader ?: return
            // Trailing blank lines carry nothing and make the evidence block look broken.
            while (continuation.isNotEmpty() && continuation.last().isBlank()) continuation.removeAt(continuation.size - 1)
            events++
            onEvent(header.toEvent(pendingStart, continuation.toList()))
            continuation.clear()
        }

        val lines = source.forEachLine { line ->
            val clean = clean(line.text)
            val header = Header.parse(clean)
            if (header != null) {
                flush()
                pendingHeader = header
                pendingStart = line.number
                formats[header.format] = (formats[header.format] ?: 0) + 1
            } else if (pendingHeader != null) {
                if (continuation.size < MAX_CONTINUATION) continuation += clean
            } else if (clean.isNotBlank()) {
                // Lines before the first header: a crash report, a thread dump, a stray paste.
                // They become one event so their content is still searchable.
                pendingHeader = Header(null, null, null, clean, null, "headerless")
                pendingStart = line.number
                formats["headerless"] = (formats["headerless"] ?: 0) + 1
            }
        }
        flush()

        return LogParseStats(
            lines = lines,
            events = events,
            truncated = source.truncated,
            dominantFormat = formats.maxByOrNull { it.value }?.key,
            formatCounts = formats.toMap(),
        )
    }

    /** Strips what the transport added: ANSI colour, a Docker/panel timestamp, a stream name. */
    private fun clean(raw: String): String {
        var text = ANSI.replace(raw, "")
        text = DOCKER_PREFIX.replace(text, "")
        return text
    }

    private data class Header(
        val timestamp: String?,
        val thread: String?,
        val level: String?,
        val message: String,
        val loggerPlugin: String?,
        val format: String,
    ) {
        fun toEvent(startLine: Int, continuation: List<String>) = LogEvent(
            startLine = startLine,
            timestamp = timestamp,
            thread = thread,
            level = level,
            message = message,
            loggerPlugin = loggerPlugin,
            continuation = continuation,
        )

        companion object {
            fun parse(line: String): Header? {
                PAPER.find(line)?.let { match ->
                    val (time, threadAndLevel, rest) = match.destructured
                    val split = threadAndLevel.lastIndexOf('/')
                    val thread = if (split > 0) threadAndLevel.take(split) else threadAndLevel
                    val level = if (split > 0) threadAndLevel.substring(split + 1) else null
                    val (plugin, message) = splitPluginPrefix(rest)
                    return Header(time, thread, level?.uppercase(), message, plugin, "paper")
                }
                LEGACY.find(line)?.let { match ->
                    val (time, level, rest) = match.destructured
                    val (plugin, message) = splitPluginPrefix(rest)
                    return Header(time, null, level.uppercase(), message, plugin, "legacy")
                }
                DATED.find(line)?.let { match ->
                    val (stamp, threadAndLevel, rest) = match.destructured
                    val split = threadAndLevel.lastIndexOf('/')
                    val thread = if (split > 0) threadAndLevel.take(split) else threadAndLevel
                    val level = if (split > 0) threadAndLevel.substring(split + 1) else null
                    val (plugin, message) = splitPluginPrefix(rest)
                    return Header(stamp, thread, level?.uppercase(), message, plugin, "dated")
                }
                JVM_UNIFIED.find(line)?.let { match ->
                    val (stamp, rawLevel, rawTags, rest) = match.destructured
                    val level = when (rawLevel.uppercase()) {
                        "WARNING" -> "WARN"
                        else -> rawLevel.uppercase()
                    }
                    val tags = rawTags.replace(" ", "")
                    return Header(stamp, "jvm:$tags", level, rest, null, "jvm-unified")
                }
                return null
            }

            /**
             * Bukkit's plugin logger prefixes `[PluginName] ` to every line a plugin logs, which is
             * the cheapest and most reliable attribution available. The pattern matches the plugin
             * name characters the server itself accepts, so arbitrary bracketed text in a message
             * is not mistaken for a plugin.
             */
            private fun splitPluginPrefix(rest: String): Pair<String?, String> {
                val match = PLUGIN_PREFIX.find(rest) ?: return null to rest
                return match.groupValues[1] to match.groupValues[2]
            }
        }
    }

    private companion object {
        /** `[22:31:04] [Server thread/INFO]: message` */
        val PAPER = Regex("""^\[(\d{1,2}:\d{2}:\d{2})]\s\[([^]]+)]:\s?(.*)$""")

        /** `[22:31:04 INFO]: message` - Bukkit and CraftBukkit era, still emitted by some forks. */
        val LEGACY = Regex("""^\[(\d{1,2}:\d{2}:\d{2})\s(INFO|WARN|WARNING|ERROR|SEVERE|FATAL|DEBUG|TRACE)]:?\s?(.*)$""")

        /** `[2026-08-24 22:31:04] [Server thread/INFO]: message` - panels and custom log4j configs. */
        val DATED = Regex("""^\[?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?Z?)]?\s\[([^]]+)]:\s?(.*)$""")

        /** `[142.810s][info][gc] GC(14) Pause Young ...` - OpenJDK JEP 158 Unified JVM Logging. */
        val JVM_UNIFIED = Regex(
            """^\[([^\]]+)]\[(trace|debug|info|warning|error)]\[([a-zA-Z0-9_,\s]+)]\s*(.*)$""",
            RegexOption.IGNORE_CASE,
        )

        /** Only the characters Bukkit allows in a plugin name, so prose in brackets is not matched. */
        val PLUGIN_PREFIX = Regex("""^\[([A-Za-z0-9_.\- ]{1,48})]\s(.*)$""")

        /** CSI sequences, built from the code point so this file stays pure ASCII. */
        val ANSI = Regex(Char(27).toString() + """\[[0-9;?]*[ -/]*[@-~]""")

        /** `2026-08-24T22:31:04.123456789Z stdout F ` as written by container runtimes. */
        val DOCKER_PREFIX = Regex("""^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+(?:stdout|stderr)\s+[FP]\s""")

        /** A single event past this many lines is a thread dump; the rest changes no conclusion. */
        const val MAX_CONTINUATION = 400
    }
}
