package com.salyvn.serverdoctor.flags

/**
 * A parsed `java ...` command line.
 *
 * The point of separating parsing from judgement is that the input is unreliable: it arrives as a
 * start script written by a hosting panel, a line pasted from a crash report, or something a user
 * typed into Discord. Everything that could not be understood is kept in [unrecognised] rather than
 * dropped, so a rule can say "this flag was not read" instead of pretending it was absent.
 */
data class JvmCommandLine(
    val javaBinary: String?,
    /** `-Xms` in bytes, or null when not set. */
    val initialHeapBytes: Long?,
    /** `-Xmx` (or `-XX:MaxRAMPercentage`, which is reported separately) in bytes. */
    val maxHeapBytes: Long?,
    /** The garbage collector the flags select, as the flag that selected it. */
    val collectorFlag: String?,
    /** `-XX:Key=value` and `-XX:+/-Key`, in order of appearance. A repeated key keeps the last. */
    val tuningFlags: Map<String, String?>,
    /** `-Dkey=value`. */
    val systemProperties: Map<String, String>,
    /** The jar the command runs, when it is a `-jar` invocation. */
    val jarPath: String?,
    /** Arguments after the jar or main class: `--nogui`, `--world-dir`, and so on. */
    val applicationArguments: List<String>,
    /** Tokens this parser did not classify, kept verbatim. */
    val unrecognised: List<String>,
    /** The tokens as parsed, for evidence lines. */
    val tokens: List<String>,
) {

    fun flag(name: String): String? = tuningFlags[name]

    fun hasFlag(name: String): Boolean = tuningFlags.containsKey(name)

    /** True for `-XX:+Name`, false for `-XX:-Name`, null when the flag is absent. */
    fun toggle(name: String): Boolean? = when (tuningFlags[name]) {
        "true" -> true
        "false" -> false
        else -> null
    }

    companion object {

        /** Characters a backslash may legitimately escape; anything else stays a literal backslash. */
        private val ESCAPABLE = setOf('"', '\'', ' ', '\\')

        private val COLLECTOR_FLAGS = setOf(
            "UseG1GC",
            "UseZGC",
            "UseShenandoahGC",
            "UseParallelGC",
            "UseSerialGC",
            "UseConcMarkSweepGC",
            "UseParNewGC",
        )

        /**
         * Splits a command line the way the two shells that write these files do.
         *
         * A backslash is only an escape when it precedes a quote, a space or another backslash. That
         * exception matters more than it looks: `start.bat` is as common as `start.sh` in this
         * domain, and treating every backslash as an escape turns
         * `"C:\Program Files\Java\bin\java.exe"` into a path that exists nowhere.
         */
        fun tokenize(command: String): List<String> {
            val tokens = mutableListOf<String>()
            val current = StringBuilder()
            var quote: Char? = null
            var started = false
            var index = 0

            while (index < command.length) {
                val character = command[index]
                val next = command.getOrNull(index + 1)
                when {
                    character == '\\' && quote != '\'' && next != null && next in ESCAPABLE -> {
                        current.append(next)
                        started = true
                        index++
                    }

                    quote != null -> {
                        if (character == quote) quote = null else current.append(character)
                        started = true
                    }

                    character == '"' || character == '\'' -> {
                        quote = character
                        started = true
                    }

                    character.isWhitespace() -> {
                        if (started) {
                            tokens += current.toString()
                            current.setLength(0)
                            started = false
                        }
                    }

                    else -> {
                        current.append(character)
                        started = true
                    }
                }
                index++
            }
            if (started) tokens += current.toString()
            return tokens
        }

        fun parse(command: String): JvmCommandLine = parseTokens(tokenize(command))

        fun parseTokens(tokens: List<String>): JvmCommandLine {
            var javaBinary: String? = null
            var xms: Long? = null
            var xmx: Long? = null
            var collector: String? = null
            val tuning = LinkedHashMap<String, String?>()
            val properties = LinkedHashMap<String, String>()
            var jar: String? = null
            val appArgs = mutableListOf<String>()
            val unrecognised = mutableListOf<String>()

            var index = 0
            var afterMainArtifact = false

            while (index < tokens.size) {
                val token = tokens[index]
                index++
                when {
                    afterMainArtifact -> appArgs += token

                    javaBinary == null && !token.startsWith("-") && looksLikeJava(token) -> javaBinary = token

                    token == "-jar" -> {
                        jar = tokens.getOrNull(index)
                        index++
                        afterMainArtifact = true
                    }

                    token.startsWith("-Xms") -> xms = parseSize(token.removePrefix("-Xms"))
                    token.startsWith("-Xmx") -> xmx = parseSize(token.removePrefix("-Xmx"))

                    token.startsWith("-XX:+") || token.startsWith("-XX:-") -> {
                        val enabled = token[4] == '+'
                        val name = token.substring(5)
                        tuning[name] = enabled.toString()
                        if (enabled && name in COLLECTOR_FLAGS) collector = token
                    }

                    token.startsWith("-XX:") -> {
                        val body = token.removePrefix("-XX:")
                        val name = body.substringBefore('=')
                        tuning[name] = body.substringAfter('=', "").takeIf { it.isNotEmpty() }
                    }

                    token.startsWith("-D") -> {
                        val body = token.removePrefix("-D")
                        properties[body.substringBefore('=')] = body.substringAfter('=', "")
                    }

                    // A bare class name ends the JVM options and starts the application's own.
                    !token.startsWith("-") && javaBinary != null && token.contains('.') && !token.endsWith(".jar") -> {
                        afterMainArtifact = true
                    }

                    else -> unrecognised += token
                }
            }

            return JvmCommandLine(
                javaBinary = javaBinary,
                initialHeapBytes = xms,
                maxHeapBytes = xmx,
                collectorFlag = collector,
                tuningFlags = tuning,
                systemProperties = properties,
                jarPath = jar,
                applicationArguments = appArgs,
                unrecognised = unrecognised,
                tokens = tokens,
            )
        }

        private fun looksLikeJava(token: String): Boolean {
            val leaf = token.substringAfterLast('/').substringAfterLast('\\').lowercase()
            return leaf == "java" || leaf == "java.exe" || leaf.endsWith("javaw.exe")
        }

        /** `4G`, `4096m`, `8388608k`, or a plain byte count. Returns null when unparseable. */
        fun parseSize(raw: String): Long? {
            if (raw.isEmpty()) return null
            val digits = raw.takeWhile { it.isDigit() }
            if (digits.isEmpty()) return null
            val amount = digits.toLongOrNull() ?: return null
            return when (raw.drop(digits.length).lowercase()) {
                "", "b" -> amount
                "k", "kb" -> amount * 1024
                "m", "mb" -> amount * 1024 * 1024
                "g", "gb" -> amount * 1024 * 1024 * 1024
                "t", "tb" -> amount * 1024 * 1024 * 1024 * 1024
                else -> null
            }
        }

        /**
         * Formatted with [java.util.Locale.ROOT]: the default locale would render 2.0 as "2,0" on a
         * machine configured for most of Europe, and this text is compared in tests and pasted into
         * bug reports.
         */
        fun humanSize(bytes: Long): String = when {
            bytes >= 1L shl 30 -> String.format(java.util.Locale.ROOT, "%.1f GiB", bytes.toDouble() / (1L shl 30))
            bytes >= 1L shl 20 -> String.format(java.util.Locale.ROOT, "%.0f MiB", bytes.toDouble() / (1L shl 20))
            else -> "$bytes B"
        }
    }
}
