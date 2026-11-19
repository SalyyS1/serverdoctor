package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.IncidentTimelineCorrelator
import com.salyvn.serverdoctor.plugins.PluginIndex
import java.nio.file.Files

/**
 * `serverdoctor diagnose-incident <target>` - diagnose virtual-thread carrier pinning (L042),
 * HikariCP/SQLite persistence starvation (L043), Linux cgroup/PSI/swap pressure (L044), and
 * correlate multi-signal timelines into root-cause causal chains (L045).
 */
class DiagnoseIncidentCommand : ReportCommand("diagnose-incident") {

    override fun help(context: Context) =
        "Diagnose Loom carrier pinning, DB pool starvation, Linux cgroup throttling, and correlate causal outage timelines."

    private val target by argument(
        name = "target",
        help = "Primary server log, crash log, or combined diagnostic capture",
    ).path(mustExist = true)

    private val gcLog by option(
        "--gc-log",
        help = "Optional companion Unified JVM GC log (-Xlog:gc*) for cross-log causal correlation",
    ).path(mustExist = true, canBeDir = false)

    private val jfrLog by option(
        "--jfr",
        help = "Optional companion JFR print output or host cgroup/PSI telemetry file",
    ).path(mustExist = true, canBeDir = false)

    private val pluginsDir by option(
        "--plugins",
        help = "Plugins directory used to attribute frames and pools to installed plugin jars",
    ).path(mustExist = true, canBeFile = false)

    override fun run() {
        if (!Files.isRegularFile(target)) {
            echo("Target must be a regular file: $target", err = true)
            throw ProgramResult(2)
        }
        val index = pluginsDir?.let { PluginIndex.read(it) } ?: PluginIndex.EMPTY
        val report = IncidentTimelineCorrelator.diagnose(
            primarySource = LogSource.of(target),
            plugins = index,
            gcSource = gcLog?.let { LogSource.of(it) },
            jfrSource = jfrLog?.let { LogSource.of(it) },
        )
        emit(listOf(report))
    }
}
