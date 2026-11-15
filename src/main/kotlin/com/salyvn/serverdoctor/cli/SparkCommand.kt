package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.SparkFlamegraphAnalyzer
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.nio.file.Files
import java.nio.file.Path

/**
 * `serverdoctor spark <profile...>` - categorize Spark profiler text call-trees, collapsed
 * flamegraph stacks (`.folded` / `.txt`), JSON sampler trees, or server logs containing `[spark]`
 * sampler output.
 */
class SparkCommand : ReportCommand("spark") {

    override fun help(context: Context) =
        "Categorize Spark profiler flamegraph stacks, text call-trees, or JSON thread profiles."

    private val targets by argument(
        name = "target",
        help = "Spark call-tree text files, collapsed flamegraph files, JSON profiles, or server logs",
    ).path(mustExist = true).multiple(required = true)

    private val pluginsDir by option(
        "--plugins",
        help = "Plugins directory, used to attribute hotspot call branches to installed plugin jars",
    ).path(mustExist = true, canBeFile = false)

    override fun run() {
        val files = targets.flatMap { resolveInputs(it) }
        if (files.isEmpty()) {
            echo("No Spark profile or log files found under the given target.", err = true)
            throw ProgramResult(2)
        }

        val index = pluginsDir?.let { PluginIndex.read(it) } ?: PluginIndex.EMPTY
        val reports = mutableListOf<ScanReport>()
        for (file in files) {
            reports += SparkFlamegraphAnalyzer.analyseSource(LogSource.of(file), index)
        }
        emit(reports)
    }

    private fun resolveInputs(target: Path): List<Path> {
        if (Files.isRegularFile(target)) return listOf(target)
        return Files.list(target).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .filter {
                    val lower = it.fileName.toString().lowercase()
                    lower.endsWith(".txt") ||
                        lower.endsWith(".folded") ||
                        lower.endsWith(".collapsed") ||
                        lower.endsWith(".json") ||
                        lower.endsWith(".log") ||
                        lower.endsWith(".log.gz")
                }
                .sorted()
                .toList()
        }
    }
}
