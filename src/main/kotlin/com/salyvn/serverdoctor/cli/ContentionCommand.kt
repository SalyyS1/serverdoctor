package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.NativeLeakTicketAndContentionAnalyzer
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.nio.file.Files

/**
 * `serverdoctor contention <target>` - diagnose Netty DirectByteBuffer off-heap leaks (L039),
 * Paper 26.3 Moonrise chunk ticket leaks (L040), and JFR / async-profiler lock contention (L041).
 */
class ContentionCommand : ReportCommand("contention") {

    override fun help(context: Context) =
        "Diagnose Netty DirectByteBuffer native leaks, Paper 26.3 chunk ticket leaks, and JFR or async-profiler lock contention."

    private val target by argument(
        name = "target",
        help = "Server log, Netty ResourceLeakDetector output, chunkinfo dump, JFR print text, or async-profiler lock profile",
    ).path(mustExist = true)

    private val pluginsDir by option(
        "--plugins",
        help = "Plugins directory, used to attribute native leaks, chunk tickets, and contended locks to installed plugins",
    ).path(mustExist = true, canBeFile = false)

    override fun run() {
        if (!Files.isRegularFile(target)) {
            echo("Target must be a regular file: $target", err = true)
            throw ProgramResult(2)
        }

        val index = pluginsDir?.let { PluginIndex.read(it) } ?: PluginIndex.EMPTY
        val report = NativeLeakTicketAndContentionAnalyzer.diagnose(
            source = LogSource.of(target),
            plugins = index,
        )
        emit(listOf(report))
    }
}
