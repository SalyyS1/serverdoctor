package com.salyvn.serverdoctor.input

import java.io.BufferedReader
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream

/** One physical line of a log, with the 1-based number so a finding can point back at it. */
data class LogLine(val number: Int, val text: String)

/**
 * A log file, read as text. Handles the two shapes a server actually produces: the live
 * `latest.log`, and the rolled `logs/2026-08-24-1.log.gz` that a host hands you after the crash.
 *
 * Reading is streaming and capped. A server that crash-loops for a week produces logs in the
 * hundreds of megabytes, and the tool has to stay usable on the box that produced them.
 */
class LogSource private constructor(
    val path: Path,
    val compressed: Boolean,
    private val open: () -> BufferedReader,
) {

    /**
     * Applies [action] to every line, in order. Returns the number of lines read, which is not the
     * number of lines in the file when the cap is hit - [truncated] says which happened.
     */
    fun forEachLine(limit: Int = MAX_LINES, action: (LogLine) -> Unit): Int {
        var count = 0
        open().use { reader ->
            while (true) {
                val text = reader.readLine() ?: break
                count++
                action(LogLine(count, text))
                if (count >= limit) {
                    truncated = true
                    break
                }
            }
        }
        return count
    }

    /** True when the last read stopped at the cap rather than at the end of the file. */
    var truncated: Boolean = false
        private set

    val sizeBytes: Long get() = runCatching { Files.size(path) }.getOrDefault(-1L)

    companion object {
        /**
         * Two million lines is about 200 MB of Paper log. Past that a crash loop is repeating
         * itself and reading more changes no conclusion.
         */
        const val MAX_LINES = 2_000_000

        fun of(path: Path): LogSource {
            val gz = path.fileName.toString().endsWith(".gz", ignoreCase = true)
            return LogSource(path, gz) {
                val stream = Files.newInputStream(path)
                val decoded = if (gz) GZIPInputStream(stream) else stream
                // Server logs are UTF-8 in practice but carry player-supplied text, so decoding
                // has to replace bad bytes rather than throw halfway through a triage run.
                decoded.bufferedReader(StandardCharsets.UTF_8)
            }
        }
    }
}
