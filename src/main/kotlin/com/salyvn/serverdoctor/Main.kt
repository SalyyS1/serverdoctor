package com.salyvn.serverdoctor

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.options.versionOption
import com.salyvn.serverdoctor.cli.ConfigCommand
import com.salyvn.serverdoctor.cli.CrashCommand
import com.salyvn.serverdoctor.cli.DiffCommand
import com.salyvn.serverdoctor.cli.FlagsCommand
import com.salyvn.serverdoctor.cli.LogCommand
import com.salyvn.serverdoctor.cli.McpCommand
import com.salyvn.serverdoctor.cli.PermsCommand
import com.salyvn.serverdoctor.cli.PluginsCommand
import com.salyvn.serverdoctor.cli.RulesCommand
import com.salyvn.serverdoctor.cli.ScanCommand
import com.salyvn.serverdoctor.cli.WorldCommand
import com.salyvn.serverdoctor.core.BuildInfo

/**
 * Entry point.
 *
 * Everything here reads artifacts a server has already produced: its log, its configuration, its
 * start script, the jars in its plugins directory. The server is never started and no plugin code is
 * ever loaded, which is what makes it safe to run against somebody else's box, or against a paid
 * plugin nobody has the source to.
 */
class ServerDoctorCommand : CliktCommand(name = "serverdoctor") {

    override fun help(context: Context) =
        "Diagnose a Minecraft server from its own log, configuration, JVM flags and plugins."

    override fun run() = Unit
}

fun main(args: Array<String>) = ServerDoctorCommand()
    .versionOption(BuildInfo.version, names = setOf("--version"))
    .subcommands(
        ScanCommand(),
        LogCommand(),
        ConfigCommand(),
        FlagsCommand(),
        PluginsCommand(),
        WorldCommand(),
        CrashCommand(),
        PermsCommand(),
        DiffCommand(),
        McpCommand(),
        RulesCommand(),
    )
    .main(args)
