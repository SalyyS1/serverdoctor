package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.crash.CrashAudit
import com.salyvn.serverdoctor.crash.CrashReportFile
import com.salyvn.serverdoctor.flags.FlagsAudit
import com.salyvn.serverdoctor.flags.JvmCommandLine
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.nio.file.Files

/**
 * `serverdoctor crash <report|crash-reports|server-dir>` - read what the server said as it stopped.
 *
 * A crash report carries its own `JVM Flags:` line, so the flags audit runs over it too and the run
 * prints two reports. That is the point of pointing this at a file somebody emailed: the server it came
 * from does not have to exist any more.
 */
class CrashCommand : ReportCommand("crash") {

    override fun help(context: Context) =
        "Read crash reports: what crashed, whose code was in the trace, and the flags it ran with."

    private val target by argument(
        name = "target",
        help = "A crash report, a crash-reports directory, or a server directory holding one",
    ).path(mustExist = true)

    private val noFlags by option(
        "--no-flags",
        help = "Skip the flags audit of the JVM flags recorded in the newest report",
    ).flag()

    override fun run() {
        val files = CrashReportFile.discover(target)
        if (files.isEmpty()) {
            echo(
                "No crash reports under $target. Point at crash-reports/, a server directory, or one " +
                    "crash-*.txt.",
                err = true,
            )
            throw ProgramResult(2)
        }

        val reports = files.map { CrashReportFile.read(it) }
        val pluginsDirectory = if (Files.isDirectory(target)) target.resolve("plugins") else null
        val index = pluginsDirectory
            ?.takeIf { Files.isDirectory(it) }
            ?.let { PluginIndex.read(it) }
            ?: PluginIndex.EMPTY

        val crash = CrashAudit(index).analyse(reports, target.toString())

        val withFlags = if (noFlags) null else reports.lastOrNull { it.jvmFlags != null }
        val flags = withFlags?.let { report ->
            FlagsAudit().analyse(
                source = "${report.name} (JVM Flags)",
                command = JvmCommandLine.parse(report.jvmFlags!!),
            )
        }

        emit(listOfNotNull(crash, flags))
    }
}
