package com.salyvn.serverdoctor.log

/**
 * One logical entry in a server log: the header line, plus every line that belongs to it. A Java
 * exception is dozens of physical lines and one event, and triage only makes sense at that grain.
 */
data class LogEvent(
    /** 1-based line where the header was. */
    val startLine: Int,
    /** Raw timestamp text as written, or null in a crash report or a thread dump. */
    val timestamp: String?,
    /** Thread name where known: `Server thread`, `main`, a Folia region thread, a plugin's pool. */
    val thread: String?,
    /** INFO / WARN / ERROR / FATAL, uppercased, or null when the line carried no level. */
    val level: String?,
    /** The message with the `[PluginName]` prefix removed. */
    val message: String,
    /** The plugin that owns the logger, when the line carried a prefix. */
    val loggerPlugin: String?,
    /** The lines that followed and belonged to this event: stack frames, `Caused by:`, dumps. */
    val continuation: List<String> = emptyList(),
) {
    /** Header plus continuation, for signature matching that spans a stack trace. */
    val fullText: String by lazy {
        if (continuation.isEmpty()) message else (listOf(message) + continuation).joinToString("\n")
    }

    val isProblem: Boolean get() = level == "WARN" || level == "WARNING" || level == "ERROR" || level == "FATAL" || level == "SEVERE"

    /** Stack frames in order, outermost first, as `package.Class.method(File.java:12)`. */
    val frames: List<StackFrame> by lazy { StackFrame.parseAll(continuation) }

    /** Every exception class named by this event, in the order they appear. */
    val exceptions: List<String> by lazy {
        val fromHeader = EXCEPTION_IN_TEXT.findAll(message).map { it.value }
        val fromBody = continuation.asSequence()
            .filter { it.trimStart().startsWith("Caused by:") || it.trimStart().startsWith("Suppressed:") || EXCEPTION_LINE.containsMatchIn(it) }
            .flatMap { EXCEPTION_IN_TEXT.findAll(it).map { match -> match.value } }
        (fromHeader + fromBody).distinct().toList()
    }

    private companion object {
        /**
         * A fully qualified name ending in Exception, Error or Throwable. Deliberately not a list of
         * known JDK types: the interesting ones come from plugins.
         */
        val EXCEPTION_IN_TEXT = Regex("""[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)*\.(?:[A-Z]\w*)?(?:Exception|Error|Throwable)""")
        val EXCEPTION_LINE = Regex("""^\s*[a-zA-Z_$][\w$.]*(?:Exception|Error|Throwable)""")
    }
}

/** One `at ...` line of a stack trace. */
data class StackFrame(val raw: String, val className: String, val method: String, val source: String?) {

    /** `com.example.plugin` for `com.example.plugin.Listener` - empty for a default-package class. */
    val packageName: String get() = className.substringBeforeLast('.', "")

    companion object {
        /**
         * `at com.example.Foo.bar(Foo.java:12)`, and the same line with the module or class-loader
         * prefix a modern JVM writes: `java.base/java.util.Arrays.copyOf(...)`, `app//com.example.Foo`.
         * The prefix is skipped rather than kept, so a JDK frame is still recognised as one.
         */
        private val FRAME = Regex("""^\s*at\s+(?:[\w.$@-]*/)*([\w$.]+)\.([\w$<>]+)\(([^)]*)\)""")

        fun parse(line: String): StackFrame? {
            val match = FRAME.find(line) ?: return null
            return StackFrame(
                raw = line.trim(),
                className = match.groupValues[1],
                method = match.groupValues[2],
                source = match.groupValues[3].takeIf { it.isNotBlank() },
            )
        }

        fun parseAll(lines: List<String>): List<StackFrame> = lines.mapNotNull { parse(it) }
    }
}
