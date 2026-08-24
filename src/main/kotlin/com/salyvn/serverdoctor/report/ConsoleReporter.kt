package com.salyvn.serverdoctor.report

import com.salyvn.serverdoctor.core.Finding
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.core.Severity

/**
 * Plain-text output, grouped by rule so that a log with forty hits of one signature reads as one
 * problem rather than forty. ASCII only: this output ends up in CI logs, Windows consoles, forum
 * posts and Discord messages, and anything fancier survives none of those.
 */
class ConsoleReporter(private val color: Boolean, private val verbose: Boolean = false) {

    fun render(report: ScanReport): String = buildString {
        appendLine("${report.subjectKind}: ${report.subject}")
        if (report.facts.isNotEmpty()) {
            val width = report.facts.keys.maxOf { it.length }
            for ((key, value) in report.facts) {
                appendLine("  ${key.padEnd(width)}  $value")
            }
        }
        appendLine()

        if (report.findings.isEmpty()) {
            appendLine(paint("No findings.", Ansi.GREEN))
            return@buildString
        }

        val groups = report.findings.groupBy { it.ruleId }
            .entries
            .sortedWith(
                compareByDescending<Map.Entry<String, List<Finding>>> { it.value.first().severity.rank }
                    .thenBy { it.key }
            )

        for ((ruleId, findings) in groups) {
            val first = findings.first()
            appendLine(paint("[${first.severity.label}] $ruleId  ${first.title}", severityColor(first.severity)))
            val shown = if (verbose) findings else findings.take(MAX_PER_RULE)
            for (finding in shown) {
                appendLine("    ${finding.location}")
                appendLine("      ${finding.detail}")
                for (line in finding.evidence) appendLine("        $line")
            }
            if (shown.size < findings.size) {
                appendLine("    ... ${findings.size - shown.size} more (use --verbose to list every hit)")
            }
            first.fix?.let { appendLine("    fix: $it") }
            if (verbose) first.provenance?.let { appendLine("    source: $it") }
            appendLine()
        }

        appendLine(summaryLine(report))
    }

    fun summaryLine(report: ScanReport): String {
        val parts = Severity.entries
            .filter { report.count(it) > 0 }
            .map { severity ->
                val count = report.count(severity)
                // "1 warning" but "3 warnings": this line is read by people, not parsers.
                val label = if (count == 1) severity.label else "${severity.label}s"
                "$count $label"
            }
        return if (parts.isEmpty()) "clean" else parts.joinToString(", ", prefix = "Summary: ")
    }

    private fun severityColor(severity: Severity) = when (severity) {
        Severity.BLOCKER -> Ansi.MAGENTA
        Severity.CRITICAL -> Ansi.RED
        Severity.WARNING -> Ansi.YELLOW
        Severity.INFO -> Ansi.CYAN
    }

    private fun paint(text: String, code: String) = if (color) "$code$text${Ansi.RESET}" else text

    /** Escape sequences built from the code point, so this source file stays pure ASCII. */
    private object Ansi {
        private val CSI = Char(27).toString() + "["
        val RESET = CSI + "0m"
        val RED = CSI + "31m"
        val GREEN = CSI + "32m"
        val YELLOW = CSI + "33m"
        val MAGENTA = CSI + "35m"
        val CYAN = CSI + "36m"
    }

    private companion object {
        const val MAX_PER_RULE = 8
    }
}
