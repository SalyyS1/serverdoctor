package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.LogTriage
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.nio.file.Files
import java.nio.file.Path

/**
 * `serverdoctor log <file...>` - triage a server log, a rolled `*.log.gz`, or a pasted crash report.
 *
 * A directory is accepted too, because the thing an operator has to hand is usually the server folder
 * rather than a path to the log inside it.
 */
class LogCommand : ReportCommand("log") {

    override fun help(context: com.github.ajalt.clikt.core.Context) =
        "Triage a server log and report what went wrong, worst first."

    private val targets by argument(
        name = "target",
        help = "Log files, a logs/ directory, or a server directory",
    ).path(mustExist = true).multiple(required = true)

    private val pluginsDir by option(
        "--plugins",
        help = "Plugins directory, used to attribute stack frames and logger labels to real plugins",
    ).path(mustExist = true, canBeFile = false)

    override fun run() {
        val logs = targets.flatMap { resolveLogs(it) }
        if (logs.isEmpty()) {
            echo("No log files found. Point at latest.log, a *.log.gz, or a directory holding them.", err = true)
            throw ProgramResult(2)
        }

        val index = pluginsDir?.let { PluginIndex.read(it) } ?: PluginIndex.EMPTY
        val triage = LogTriage(index)
        val reports = mutableListOf<ScanReport>()
        for (log in logs) reports += triage.analyse(LogSource.of(log))
        emit(reports)
    }

    /**
     * Turns whatever was passed into a list of logs. A server directory resolves to `logs/latest.log`
     * only: rolling through every archived log by default would bury today's problem under last
     * month's.
     */
    private fun resolveLogs(target: Path): List<Path> {
        if (Files.isRegularFile(target)) return listOf(target)

        val latest = target.resolve("latest.log")
        if (Files.isRegularFile(latest)) return listOf(latest)

        val nested = target.resolve("logs").resolve("latest.log")
        if (Files.isRegularFile(nested)) return listOf(nested)

        return Files.list(target).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter {
                    val name = it.fileName.toString().lowercase()
                    name.endsWith(".log") || name.endsWith(".log.gz") || name.endsWith(".txt")
                }
                .sorted()
                .toList()
        }
    }
}
