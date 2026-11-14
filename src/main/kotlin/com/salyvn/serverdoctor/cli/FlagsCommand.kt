package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.optional
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.flags.FlagsAudit
import com.salyvn.serverdoctor.flags.JvmCommandLine
import com.salyvn.serverdoctor.flags.StartScriptReader
import java.nio.file.Files

/**
 * `serverdoctor flags <script>` or `--command "java -Xmx..."` - audit the JVM command line.
 */
class FlagsCommand : ReportCommand("flags") {

    override fun help(context: Context) =
        "Audit the JVM flags a server starts with, from its start script or from a pasted command."

    private val target by argument(
        name = "target",
        help = "A start script, or a server directory containing one",
    ).path(mustExist = true).optional()

    private val command by option(
        "--command",
        help = "The java command line itself, quoted",
    )

    private val hostMemory by option(
        "--host-memory",
        help = "How much memory the machine has (e.g. 8G), to check the heap leaves room for the OS",
    )

    override fun run() {
        if (target == null && command == null) {
            echo("Give a start script, a server directory, or --command \"java ...\".", err = true)
            throw ProgramResult(2)
        }

        val hostBytes = hostMemory?.let {
            JvmCommandLine.parseSize(it) ?: run {
                echo("Could not read --host-memory $it; use a form like 8G or 8192M.", err = true)
                throw ProgramResult(2)
            }
        }

        val audit = FlagsAudit(hostBytes)
        val reports = mutableListOf<ScanReport>()

        command?.let { literal ->
            reports += audit.analyse("--command", JvmCommandLine.parse(literal))
        }

        target?.let { path ->
            val script = if (Files.isDirectory(path)) StartScriptReader.findScript(path) else path
            if (script == null) {
                reports += audit.analyse(path.toString(), null)
            } else {
                val extracted = StartScriptReader.readCommand(script)
                reports += audit.analyse(
                    script.toString(),
                    extracted?.let { JvmCommandLine.parse(it) },
                )
            }
        }

        emit(reports)
    }
}
