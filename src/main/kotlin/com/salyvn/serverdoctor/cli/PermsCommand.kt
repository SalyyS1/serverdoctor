package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.perms.PermsAudit
import java.nio.file.Files

/**
 * `serverdoctor perms <server-dir>` - who can get in, and who is an operator once they are.
 */
class PermsCommand : ReportCommand("perms") {

    override fun help(context: Context) =
        "Check ops, whitelist, bans and permissions.yml against how the server verifies identity."

    private val target by argument(
        name = "target",
        help = "A server directory",
    ).path(mustExist = true, canBeFile = false)

    override fun run() {
        val looksLikeServer = ACCESS_FILES.any { Files.isRegularFile(target.resolve(it)) }
        if (!looksLikeServer) {
            echo(
                "Nothing to audit in $target: none of ${ACCESS_FILES.joinToString(", ")} is here.",
                err = true,
            )
            throw ProgramResult(2)
        }
        emit(listOf(PermsAudit().analyse(target, target.toString())))
    }

    private companion object {
        val ACCESS_FILES = listOf(
            "server.properties",
            "ops.json",
            "whitelist.json",
            "banned-players.json",
            "banned-ips.json",
        )
    }
}
