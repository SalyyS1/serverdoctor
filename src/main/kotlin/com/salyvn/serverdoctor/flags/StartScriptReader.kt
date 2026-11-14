package com.salyvn.serverdoctor.flags

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/**
 * Pulls the java invocation out of a start script.
 *
 * Start scripts are not programs anybody reviews. They carry comments, `screen` and `tmux` wrappers,
 * restart loops, and variables holding the java path. This reader does the small amount of work that
 * covers the shapes actually in use and then stops: line continuations are joined, comments dropped,
 * and the last line that looks like a java invocation wins, because a script that defines several
 * usually runs the last one.
 *
 * What it deliberately does not do is follow `@argfile` references or expand variables. Guessing at
 * either would produce a flag list that is not the one the server runs, and a wrong flag report is
 * worse than none - rule F012 says so out loud instead.
 */
object StartScriptReader {

    private val SCRIPT_NAMES = listOf(
        "start.sh",
        "start.bat",
        "start.cmd",
        "run.sh",
        "run.bat",
        "launch.sh",
        "startserver.sh",
        "server.sh",
    )

    /** Looks for a start script in a server directory. */
    fun findScript(directory: Path): Path? = SCRIPT_NAMES
        .map { directory.resolve(it) }
        .firstOrNull { Files.isRegularFile(it) }

    fun readCommand(script: Path): String? {
        val text = runCatching { Files.readString(script, StandardCharsets.UTF_8) }.getOrNull() ?: return null
        return extract(text)
    }

    /** @return the java command line found in [text], or null when there is none. */
    fun extract(text: String): String? {
        val joined = text
            .replace("\\\r\n", " ")
            .replace("\\\n", " ")
            .replace("^\r\n", " ")
            .replace("^\n", " ")

        val candidates = joined.lineSequence()
            .map { it.trim() }
            .filterNot { it.isEmpty() || it.startsWith("#") || it.startsWith("::") || it.startsWith("rem ", ignoreCase = true) }
            .filter { looksLikeJavaCommand(it) }
            .toList()

        val chosen = candidates.lastOrNull() ?: return null
        // Strip a wrapper that precedes the java call, e.g. `screen -S mc java -Xmx...` or `exec java`.
        val index = JAVA_TOKEN.find(chosen)?.range?.first ?: return chosen
        return chosen.substring(index).trim()
    }

    private fun looksLikeJavaCommand(line: String): Boolean {
        if (!JAVA_TOKEN.containsMatchIn(line)) return false
        return line.contains("-jar") || line.contains("-Xm") || line.contains("-XX:") || line.contains("--nogui")
    }

    /** `java`, `java.exe`, a path ending in either, or a variable that resolves to one. */
    private val JAVA_TOKEN = Regex("""(?:^|[\s"'=/\\])((?:[\w.:/\\$%{}()-]*)java(?:\.exe|w\.exe)?)(?=[\s"']|$)""")
}
