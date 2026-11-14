package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.plugins.HangarClient
import com.salyvn.serverdoctor.plugins.ModrinthClient
import com.salyvn.serverdoctor.plugins.PluginIndex
import com.salyvn.serverdoctor.plugins.PluginsAudit
import java.nio.file.Files

/**
 * `serverdoctor plugins <dir>` - inventory a plugins directory and check the set for the problems that
 * only exist between plugins: a missing dependency, two jars claiming one name, a library that is not
 * a plugin at all.
 *
 * `--online` additionally asks a public index what each file is, by hash.
 */
class PluginsCommand : ReportCommand("plugins") {

    override fun help(context: Context) =
        "Inventory a plugins directory and report what is broken about the set."

    private val target by argument(
        name = "target",
        help = "A plugins directory, or a server directory containing one",
    ).path(mustExist = true)

    private val online by option(
        "--online",
        help = "Look each jar up by hash on Modrinth, then by name on Hangar, to report provenance",
    ).flag()

    override fun run() {
        val directory = when {
            Files.isDirectory(target.resolve("plugins")) -> target.resolve("plugins")
            Files.isDirectory(target) -> target
            else -> {
                echo("Point at a plugins directory or a server directory.", err = true)
                throw ProgramResult(2)
            }
        }

        val index = PluginIndex.read(directory)
        if (index.jars.isEmpty()) {
            echo("No jars in $directory.", err = true)
            throw ProgramResult(2)
        }

        val audit = if (online) PluginsAudit(ModrinthClient(), HangarClient()) else PluginsAudit()
        emit(listOf(audit.analyse(index, directory.toString())))
    }
}
