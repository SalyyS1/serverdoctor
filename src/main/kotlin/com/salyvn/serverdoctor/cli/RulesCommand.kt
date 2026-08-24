package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.RuleCatalog

/**
 * `serverdoctor rules` — the whole catalogue, with the source each rule's underlying fact came from.
 *
 * This exists so a claim can be argued with. A finding says "the watchdog fired"; this says which
 * file and line in Paper emits that message, so the reader can check rather than believe.
 */
class RulesCommand : CliktCommand(name = "rules") {

    override fun help(context: Context) = "List every rule, with its rationale and its source."

    private val area by option("--area", help = "Only one audit: log, config, flags or plugins")

    private val brief by option("--brief", help = "One line per rule").flag()

    private val markdown by option(
        "--markdown",
        help = "Emit the catalogue as markdown tables, which is how docs/rules.md is generated",
    ).flag()

    override fun run() {
        val selected = area?.let { requested ->
            RuleArea.entries.firstOrNull { it.label.equals(requested, ignoreCase = true) }
                ?: run {
                    echo("Unknown area: $requested. Known: ${RuleArea.entries.joinToString { it.label }}", err = true)
                    return
                }
        }

        val areas = selected?.let { listOf(it) } ?: RuleArea.entries.toList()
        if (markdown) {
            emitMarkdown(areas)
            return
        }

        for (ruleArea in areas) {
            val rules = RuleCatalog.byArea(ruleArea)
            if (rules.isEmpty()) continue
            echo("${ruleArea.label} (${rules.size} rules)")
            echo("")
            for (rule in rules) {
                if (brief) {
                    echo("  ${rule.id}  ${rule.severity.label.padEnd(8)} ${rule.title}")
                    continue
                }
                echo("  ${rule.id}  [${rule.severity.label}] ${rule.title}")
                echo("      why:    ${rule.rationale}")
                rule.fix?.let { echo("      fix:    $it") }
                echo("      source: ${rule.provenance}")
                echo("")
            }
        }
    }

    /**
     * The docs page is generated from the same objects the audits use, so a rule cannot be described
     * one way in the repository and behave another way in the jar.
     */
    private fun emitMarkdown(areas: List<RuleArea>) {
        echo("# Rule catalogue")
        echo("")
        echo("Generated with `serverdoctor rules --markdown`. Every source names a file and line, a")
        echo("specification, or an API response that was read rather than recalled.")
        echo("")
        for (ruleArea in areas) {
            val rules = RuleCatalog.byArea(ruleArea)
            if (rules.isEmpty()) continue
            echo("## ${ruleArea.label} (${rules.size} rules)")
            echo("")
            echo("| id | severity | what it means | source |")
            echo("| --- | --- | --- | --- |")
            for (rule in rules) {
                val why = escape(rule.rationale)
                val fix = rule.fix?.let { " **Fix:** ${escape(it)}" } ?: ""
                echo("| `${rule.id}` | ${rule.severity.label} | **${escape(rule.title)}** $why$fix | ${escape(rule.provenance)} |")
            }
            echo("")
        }
    }

    /** Pipes would end the table cell, and newlines would end the row. */
    private fun escape(text: String) = text.replace("|", "\\|").replace('\n', ' ')
}
