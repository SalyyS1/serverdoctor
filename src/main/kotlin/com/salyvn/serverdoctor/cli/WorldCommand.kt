package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.world.WorldAudit
import com.salyvn.serverdoctor.world.WorldFolder

/**
 * `serverdoctor world <server-dir|world-dir>` - check the worlds on disk.
 */
class WorldCommand : ReportCommand("world") {

    override fun help(context: Context) =
        "Check worlds on disk: level.dat, region files, datapacks and version agreement."

    private val target by argument(
        name = "target",
        help = "A server directory, or a single world directory",
    ).path(mustExist = true, canBeFile = false)

    override fun run() {
        val worlds = WorldFolder.discover(target)
        if (worlds.isEmpty()) {
            echo("No worlds under $target. A world folder holds level.dat or region/.", err = true)
            throw ProgramResult(2)
        }
        emit(listOf(WorldAudit().analyse(worlds, target.toString())))
    }
}
