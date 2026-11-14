package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.mcp.McpServer
import com.salyvn.serverdoctor.mcp.ToolCatalog

/**
 * `serverdoctor mcp` - serve the audits to an AI coding agent over stdio.
 *
 * stdout carries protocol messages and nothing else, which is why there is no banner and no progress
 * output here: one stray line of human-readable text breaks the transport. Diagnostics go to stderr.
 */
class McpCommand : CliktCommand(name = "mcp") {

    override fun help(context: Context) =
        "Run as a Model Context Protocol server over stdio (one JSON message per line)."

    override fun run() {
        val server = McpServer(
            tools = ToolCatalog.tools(),
            serverName = BuildInfo.NAME,
            serverVersion = BuildInfo.version,
        )

        System.err.println("${BuildInfo.NAME} ${BuildInfo.version} MCP server ready on stdio")
        val output = System.out.bufferedWriter()
        System.`in`.bufferedReader().forEachLine { line ->
            val response = server.handle(line) ?: return@forEachLine
            output.write(response)
            output.newLine()
            // Flushed per message: the client is waiting on this line before it sends the next.
            output.flush()
        }
    }
}
