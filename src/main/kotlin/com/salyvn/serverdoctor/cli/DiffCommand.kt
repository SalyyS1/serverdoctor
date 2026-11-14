package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.diff.ServerDiff
import com.salyvn.serverdoctor.diff.ServerSnapshot

/**
 * `serverdoctor diff <server-a> <server-b>` - what is not the same about two servers.
 *
 * Written for the case that has no other tool: one node of a network behaves unlike its siblings, or a
 * staging box works and production does not, and the difference is in a file nobody remembers editing.
 */
class DiffCommand : ReportCommand("diff") {

    override fun help(context: Context) =
        "Compare two server directories: configuration, plugins and JVM flags."

    private val left by argument(
        name = "left",
        help = "The server directory to read first",
    ).path(mustExist = true, canBeFile = false)

    private val right by argument(
        name = "right",
        help = "The server directory to compare it against",
    ).path(mustExist = true, canBeFile = false)

    override fun run() {
        emit(listOf(ServerDiff().compare(ServerSnapshot.read(left), ServerSnapshot.read(right))))
    }
}
