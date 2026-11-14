package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.choice
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.core.Severity
import com.salyvn.serverdoctor.report.ConsoleReporter
import com.salyvn.serverdoctor.report.JsonReporter
import com.salyvn.serverdoctor.report.SarifReporter
import java.nio.file.Files

/**
 * Shared plumbing for every audit: how a report is rendered, where it goes, and what the process
 * exit code becomes. Kept in one place so `log`, `config`, `flags`, `plugins` and `scan` behave
 * identically inside a shell script.
 */
abstract class ReportCommand(name: String) : CliktCommand(name = name) {

    protected val format by option("--format", help = "Output format")
        .choice("console", "json", "sarif").default("console")

    protected val jsonFlag by option("--json", help = "Shorthand for --format json").flag()

    protected val output by option("-o", "--output", help = "Write the report to this file").path()

    protected val sarifOutput by option("--sarif", help = "Also write a SARIF 2.1.0 report to this file").path()

    protected val failOn by option(
        "--fail-on",
        help = "Lowest severity that makes the run exit non-zero (default: critical)",
    ).choice("blocker", "critical", "warning", "info", "never").default("critical")

    protected val noColor by option("--no-color", help = "Disable ANSI colour").flag()

    protected val verbose by option("-v", "--verbose", help = "Show every hit and its source").flag()

    protected fun emit(reports: List<ScanReport>) {
        val effectiveFormat = if (jsonFlag && format == "console") "json" else format
        val text = when (effectiveFormat) {
            "json" -> JsonReporter.render(reports)
            "sarif" -> SarifReporter.render(reports)
            else -> {
                val reporter = ConsoleReporter(color = !noColor && output == null, verbose = verbose)
                reports.joinToString("\n" + "-".repeat(72) + "\n") { reporter.render(it) }
            }
        }

        output?.let { target ->
            target.parent?.let { Files.createDirectories(it) }
            Files.writeString(target, text)
            echo("Wrote $effectiveFormat report to $target")
        } ?: echo(text)

        sarifOutput?.let { target ->
            target.parent?.let { Files.createDirectories(it) }
            val sarifText = if (effectiveFormat == "sarif") text else SarifReporter.render(reports)
            Files.writeString(target, sarifText)
        }

        val threshold = Severity.parse(failOn) ?: return
        val worst = reports.mapNotNull { it.worst }.maxByOrNull { it.rank }
        if (worst != null && worst.rank >= threshold.rank) throw ProgramResult(1)
    }
}
