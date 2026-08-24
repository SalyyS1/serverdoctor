package com.salyvn.serverdoctor.crash

import com.salyvn.serverdoctor.log.StackFrame
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/**
 * A parsed `crash-reports/crash-*.txt`.
 *
 * The layout was taken from real reports rather than from documentation: a header, a witty comment, a
 * `Time:` and `Description:`, the exception with its stack, then sections introduced by `-- Name --`
 * whose bodies are `Details:` blocks of tab-indented `Key: value` lines. `-- System Details --` is the
 * useful one; it carries the Minecraft and Java versions, the memory figures and, on a server, the
 * `JVM Flags: N total; ...` line that lets the flag audit run over a server nobody can reach any more.
 */
class CrashReportFile(
    val path: Path,
    val description: String?,
    val time: String?,
    val exception: String?,
    val headFrames: List<StackFrame>,
    /** Section name to its raw lines, in file order. */
    val sections: Map<String, List<String>>,
    /** Key/value pairs from `-- System Details --`. */
    val details: Map<String, String>,
    /** True when an OutOfMemoryError is named anywhere in the file, not only in the top trace. */
    val outOfMemory: Boolean = false,
    val parseError: String? = null,
) {

    val minecraftVersion: String? get() = details["Minecraft Version"]
    val javaVersion: String? get() = details["Java Version"]
    val memory: String? get() = details["Memory"]
    val serverBrand: String? get() = details["Server Brand"]
    val isModded: String? get() = details["Is Modded"]
    val playerCount: String? get() = details["Player Count"]

    /**
     * The flags as one command-line fragment, or null when the report has none. The value is written
     * as `N total; -Xmx... -XX:...`, so the count is dropped and the rest handed to the flags audit.
     */
    val jvmFlags: String?
        get() = details["JVM Flags"]
            ?.substringAfter(';', "")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }

    val plugins: List<String>
        get() = details["Plugins"]?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()

    /** Sections whose name says the server was ticking something when it stopped. */
    val tickingSections: Map<String, List<String>>
        get() = sections.filterKeys { it.contains("being ticked", ignoreCase = true) }

    val name: String get() = path.fileName.toString()

    val ok: Boolean get() = parseError == null

    companion object {

        /**
         * `-- Name --`. The report's own banner is written with four dashes, so it is not a section and
         * the trace under it stays attributed to the crash itself.
         */
        private val SECTION = Regex("""^--\s(.+?)\s--$""")
        private val DETAIL = Regex("""^\t([A-Z][A-Za-z0-9 ()/.'-]*):\s?(.*)$""")
        private val EXCEPTION_LINE = Regex("""^[\w.$]+(?:Exception|Error|Throwable)[:\s]""")

        /** Crash reports are named `crash-<date>-<kind>.txt`, so the name sorts by time. */
        fun sortedByName(reports: List<CrashReportFile>): List<CrashReportFile> = reports.sortedBy { it.name }

        /** Recognises a crash report without reading all of it. */
        fun looksLikeCrashReport(file: Path): Boolean = runCatching {
            Files.newBufferedReader(file, StandardCharsets.UTF_8).use { reader ->
                val first = reader.readLine() ?: return false
                first.contains("Minecraft Crash Report")
            }
        }.getOrDefault(false)

        /**
         * The reports under [target], which may be one report, a `crash-reports` directory, or a server
         * directory that has one. Text files that are not crash reports are left alone.
         */
        fun discover(target: Path): List<Path> {
            if (Files.isRegularFile(target)) return listOf(target)
            val nested = target.resolve("crash-reports")
            val directory = if (Files.isDirectory(nested)) nested else target
            if (!Files.isDirectory(directory)) return emptyList()
            return Files.list(directory).use { stream ->
                stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".txt", ignoreCase = true) }
                    .sorted()
                    .toList()
            }.filter { looksLikeCrashReport(it) }
        }

        fun read(file: Path): CrashReportFile {
            val lines = runCatching { Files.readAllLines(file, StandardCharsets.UTF_8) }
                .getOrElse {
                    return CrashReportFile(
                        path = file,
                        description = null,
                        time = null,
                        exception = null,
                        headFrames = emptyList(),
                        sections = emptyMap(),
                        details = emptyMap(),
                        parseError = it.message ?: it::class.simpleName ?: "unreadable",
                    )
                }

            var description: String? = null
            var time: String? = null
            var exception: String? = null
            var outOfMemory = false
            val headFrames = mutableListOf<StackFrame>()
            val sections = LinkedHashMap<String, MutableList<String>>()
            val details = LinkedHashMap<String, String>()

            var section: String? = null
            var inSystemDetails = false

            for (line in lines) {
                if (!outOfMemory && line.contains("OutOfMemoryError")) outOfMemory = true

                val header = SECTION.find(line.trim())
                if (header != null) {
                    val name = header.groupValues[1].trim()
                    section = name
                    inSystemDetails = name.equals("System Details", ignoreCase = true)
                    sections.getOrPut(name) { mutableListOf() }
                    continue
                }

                section?.let { sections.getValue(it) += line }

                when {
                    description == null && line.startsWith("Description:") ->
                        description = line.removePrefix("Description:").trim()

                    time == null && line.startsWith("Time:") ->
                        time = line.removePrefix("Time:").trim()

                    exception == null && EXCEPTION_LINE.containsMatchIn(line.trim()) ->
                        exception = line.trim()
                }

                // Frames before the first section are the crash's own trace; those inside `-- Head --`
                // are the same trace repeated, so both are collected and de-duplicated.
                if (section == null || section.equals("Head", ignoreCase = true)) {
                    StackFrame.parse(line)?.let { frame ->
                        if (headFrames.none { it.raw == frame.raw }) headFrames += frame
                    }
                }

                if (inSystemDetails) {
                    DETAIL.find(line)?.let { match ->
                        details[match.groupValues[1].trim()] = match.groupValues[2].trim()
                    }
                }
            }

            return CrashReportFile(
                path = file,
                description = description,
                time = time,
                exception = exception,
                headFrames = headFrames,
                sections = sections,
                details = details,
                outOfMemory = outOfMemory,
            )
        }
    }
}
