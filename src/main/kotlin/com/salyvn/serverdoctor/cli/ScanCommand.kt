package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.config.ConfigAudit
import com.salyvn.serverdoctor.config.ServerConfigSet
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.crash.CrashAudit
import com.salyvn.serverdoctor.crash.CrashReportFile
import com.salyvn.serverdoctor.flags.FlagsAudit
import com.salyvn.serverdoctor.flags.JvmCommandLine
import com.salyvn.serverdoctor.flags.StartScriptReader
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.LogTriage
import com.salyvn.serverdoctor.perms.PermsAudit
import com.salyvn.serverdoctor.plugins.HangarClient
import com.salyvn.serverdoctor.plugins.ModrinthClient
import com.salyvn.serverdoctor.plugins.PluginIndex
import com.salyvn.serverdoctor.plugins.PluginsAudit
import com.salyvn.serverdoctor.world.WorldAudit
import com.salyvn.serverdoctor.world.WorldFolder
import java.nio.file.Files
import java.nio.file.Path

/**
 * `serverdoctor scan <server-dir>` - every audit that applies to one directory, in one pass.
 *
 * This is the command for the situation the tool was written for: something is wrong, the operator has
 * the server folder, and nobody yet knows whether the cause is in the log, the config, the flags, the
 * plugins, the worlds, a crash report or the access lists. Running them separately means deciding in
 * advance which one to suspect.
 *
 * The plugins index is read once and handed to the plugins audit, the log triage and the crash audit,
 * so stack frames anywhere can be attributed to jars that are really installed.
 */
class ScanCommand : ReportCommand("scan") {

    override fun help(context: Context) =
        "Run every applicable audit over one server directory: log, config, flags, plugins, worlds, " +
            "crash reports and access lists."

    private val target by argument(
        name = "server-dir",
        help = "The server directory",
    ).path(mustExist = true, canBeFile = false)

    private val online by option(
        "--online",
        help = "Also look plugin jars up by hash to report provenance and updates",
    ).flag()

    private val hostMemory by option(
        "--host-memory",
        help = "How much memory the machine has (e.g. 8G), for the heap checks",
    )

    override fun run() {
        val reports = mutableListOf<ScanReport>()
        val pluginsDir = target.resolve("plugins").takeIf { Files.isDirectory(it) }
        val index = pluginsDir?.let { PluginIndex.read(it) } ?: PluginIndex.EMPTY

        val configs = ServerConfigSet.read(target)
        if (!configs.isEmpty) reports += ConfigAudit().analyse(configs)

        StartScriptReader.findScript(target)?.let { script ->
            val hostBytes = hostMemory?.let { JvmCommandLine.parseSize(it) }
            val command = StartScriptReader.readCommand(script)?.let { JvmCommandLine.parse(it) }
            reports += FlagsAudit(hostBytes).analyse(script.toString(), command)
        }

        if (index.jars.isNotEmpty()) {
            val audit = if (online) PluginsAudit(ModrinthClient(), HangarClient()) else PluginsAudit()
            reports += audit.analyse(index, pluginsDir.toString())
        }

        latestLog(target)?.let { log ->
            reports += LogTriage(index).analyse(LogSource.of(log))
        }

        val worlds = WorldFolder.discover(target)
        if (worlds.isNotEmpty()) reports += WorldAudit().analyse(worlds, target.toString())

        val crashes = CrashReportFile.discover(target).map { CrashReportFile.read(it) }
        if (crashes.isNotEmpty()) reports += CrashAudit(index).analyse(crashes, target.toString())

        if (Files.isRegularFile(target.resolve("server.properties"))) {
            reports += PermsAudit().analyse(target, target.toString())
        }

        if (reports.isEmpty()) {
            echo(
                "Nothing to audit in $target. A server directory should hold server.properties, " +
                    "a plugins directory or a logs directory.",
                err = true,
            )
            throw ProgramResult(2)
        }

        emit(reports)
    }

    private fun latestLog(root: Path): Path? = listOf(
        root.resolve("logs").resolve("latest.log"),
        root.resolve("latest.log"),
    ).firstOrNull { Files.isRegularFile(it) }
}
