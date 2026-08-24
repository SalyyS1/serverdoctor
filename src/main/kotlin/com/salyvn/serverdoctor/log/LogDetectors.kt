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

    /** Class file major 52 is Java 8, and each release adds one, so the release is major - 44. */
    private const val JAVA_CLASS_FILE_OFFSET = 44

    val all: List<LogDetector> = listOf(

        Signature(LogRules.WATCHDOG_FIRED) { event, _ ->
            if (!event.message.contains("The server has stopped responding")) return@Signature null
            DetectorMatch(
                discriminator = "watchdog",
                detail = "A tick did not finish before the watchdog timeout, so the server was " +
                    "considered hung. The thread dump that follows names what was running.",
            )
        },

        Signature(LogRules.ASYNC_API_MISUSE) { event, plugins ->
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
    )
}
