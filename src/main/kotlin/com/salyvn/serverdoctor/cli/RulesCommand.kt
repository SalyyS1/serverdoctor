package com.salyvn.serverdoctor.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.RuleCatalog
import java.nio.charset.StandardCharsets
import java.nio.file.Files

/**
 * `serverdoctor rules` - the whole catalogue, with the source each rule's underlying fact came from.
 *
 * This exists so a claim can be argued with. A finding says "the watchdog fired"; this says which
 * file and line in Paper emits that message, so the reader can check rather than believe.
 */
class RulesCommand : CliktCommand(name = "rules") {

    override fun help(context: Context) = "List every rule, with its rationale and its source."

    private val area by option(
        "--area",
        help = "Only one audit: log, config, flags, plugins, world, crash, perms or diff",
    )

    private val brief by option("--brief", help = "One line per rule").flag()

    private val markdown by option(
        "--markdown",
        help = "Emit the catalogue as markdown tables, which is how docs/rules.md is generated",
    ).flag()

    private val output by option(
        "-o",
        "--output",
        help = "Write to this file as UTF-8 rather than to the console, whose encoding is the shell's",
    ).path()

    override fun run() {
        val selected = area?.let { requested ->
            RuleArea.entries.firstOrNull { it.label.equals(requested, ignoreCase = true) }
                ?: run {
                    echo("Unknown area: $requested. Known: ${RuleArea.entries.joinToString { it.label }}", err = true)
                    return
                }
        }

        val areas = selected?.let { listOf(it) } ?: RuleArea.entries.toList()
        val text = if (markdown) markdown(areas) else listing(areas)
        write(text)
    }

    private fun write(text: String) {
        val target = output ?: run {
            echo(text)
            return
        }
        target.parent?.let { Files.createDirectories(it) }
        Files.writeString(target, text, StandardCharsets.UTF_8)
        echo("Wrote ${RuleCatalog.all.size} rules to $target")
    }

    private fun listing(areas: List<RuleArea>): String = buildString {
        for (ruleArea in areas) {
            val rules = RuleCatalog.byArea(ruleArea)
            if (rules.isEmpty()) continue
            appendLine("${ruleArea.label} (${rules.size} rules)")
            appendLine("")
            for (rule in rules) {
                if (brief) {
                    appendLine("  ${rule.id}  ${rule.severity.label.padEnd(8)} ${rule.title}")
                    continue
                }
                appendLine("  ${rule.id}  [${rule.severity.label}] ${rule.title}")
                appendLine("      why:    ${rule.rationale}")
                rule.fix?.let { appendLine("      fix:    $it") }
                appendLine("      source: ${rule.provenance}")
                appendLine("")
            }
        }
    }.trimEnd()

    /**
     * The docs page is generated from the same objects the audits use, so a rule cannot be described
     * one way in the repository and behave another way in the jar.
     */
    private fun markdown(areas: List<RuleArea>): String = buildString {
        appendLine("# Rule catalogue")
        appendLine("")
        appendLine("Generated with `serverdoctor rules --markdown -o docs/rules.md`. Every source names a")
        appendLine("file and line, a specification, or an API response that was read rather than recalled.")
        appendLine("")
        for (ruleArea in areas) {
            val rules = RuleCatalog.byArea(ruleArea)
            if (rules.isEmpty()) continue
            appendLine("## ${ruleArea.label} (${rules.size} rules)")
            appendLine("")
            appendLine("| id | severity | what it means | source |")
            appendLine("| --- | --- | --- | --- |")
            for (rule in rules) {
                val why = escape(rule.rationale)
                val fix = rule.fix?.let { " **Fix:** ${escape(it)}" } ?: ""
                appendLine(
                    "| `${rule.id}` | ${rule.severity.label} | **${escape(rule.title)}** $why$fix | " +
                        "${escape(rule.provenance)} |",
                )
            }
            appendLine("")
        }
    }

    /** Pipes would end the table cell, and newlines would end the row. */
    private fun escape(text: String) = text.replace("|", "\\|").replace('\n', ' ')
}
