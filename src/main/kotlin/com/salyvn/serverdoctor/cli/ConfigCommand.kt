package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.multiple
import com.salyvn.serverdoctor.config.ConfigAudit
import com.salyvn.serverdoctor.config.ServerConfigSet
import com.github.ajalt.clikt.parameters.types.path
import java.nio.file.Files

/**
 * `serverdoctor config <server-dir>` - audit a server's own configuration.
 *
 * Individual files are accepted as well, but a directory is the useful form: the checks that matter
 * are the ones that compare `server.properties` against `paper-global.yml` against `spigot.yml`, and
 * none of those can be made from one file alone.
 */
class ConfigCommand : ReportCommand("config") {

    override fun help(context: Context) =
        "Audit server.properties and the Bukkit, Spigot and Paper configs together."

    private val targets by argument(
        name = "target",
        help = "A server directory, or individual config files",
    ).path(mustExist = true).multiple(required = true)

    override fun run() {
        val directories = targets.filter { Files.isDirectory(it) }
        val files = targets.filter { Files.isRegularFile(it) }

        val sets = buildList {
            for (directory in directories) add(ServerConfigSet.read(directory))
            if (files.isNotEmpty()) add(ServerConfigSet.of(files))
        }

        val usable = sets.filterNot { it.isEmpty }
        if (usable.isEmpty()) {
            echo(
                "Found no configuration to read. Point at a server directory holding " +
                    "server.properties, or at the config files themselves.",
                err = true,
            )
            throw ProgramResult(2)
        }

        val audit = ConfigAudit()
        emit(usable.map { audit.analyse(it) })
    }
}
