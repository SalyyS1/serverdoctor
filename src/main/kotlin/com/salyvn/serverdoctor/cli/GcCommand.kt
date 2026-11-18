package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.JvmGcAndHeapAnalyzer
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.nio.file.Files
import java.nio.file.Path

/**
 * `serverdoctor gc <target>` - diagnose unified JVM GC logs and heap histograms.
 */
class GcCommand : ReportCommand("gc") {

    override fun help(context: Context) =
        "Diagnose unified JVM GC logs (-Xlog:gc*) and heap histograms (jmap -histo) for memory leaks and GC stalls."

    private val target by argument(
        name = "target",
        help = "GC log file (-Xlog:gc*), combined server log, or jmap -histo text file",
    ).path(mustExist = true)

    private val histoPath by option(
        "--histo",
        help = "Optional separate jmap -histo text file to cross-reference with GC pauses",
    ).path(mustExist = true, canBeDir = false)

    private val pluginsDir by option(
        "--plugins",
        help = "Plugins directory, used to attribute heap retention and allocations to installed plugins",
    ).path(mustExist = true, canBeFile = false)

    override fun run() {
        if (!Files.isRegularFile(target)) {
            echo("Target must be a regular file: $target", err = true)
            throw ProgramResult(2)
        }

        val index = pluginsDir?.let { PluginIndex.read(it) } ?: PluginIndex.EMPTY
        val histoSource = histoPath?.let { LogSource.of(it) }
        val report = JvmGcAndHeapAnalyzer.diagnose(
            source = LogSource.of(target),
            plugins = index,
            histoSource = histoSource,
        )
        emit(listOf(report))
    }
}
