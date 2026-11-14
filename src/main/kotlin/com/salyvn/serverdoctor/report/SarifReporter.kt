package com.salyvn.serverdoctor.report

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.Finding
import com.salyvn.serverdoctor.core.RuleCatalog
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.core.Severity
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.security.MessageDigest

/**
 * OASIS SARIF v2.1.0 output tailored for GitHub Actions `github/codeql-action/upload-sarif`
 * (Security -> Code scanning) as well as general SARIF 2.1.0 consumers.
 */
object SarifReporter {

    const val SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    const val VERSION = "2.1.0"
    const val INFO_URI = "https://github.com/SalyyS1/serverdoctor"
    private const val RULES_HELP_URI = "$INFO_URI/blob/main/docs/rules.md"

    private val LINE_ONLY = Regex("""^line\s+(\d+)""", RegexOption.IGNORE_CASE)
    private val FILE_AND_LINE = Regex("""^(.+):(\d+)(?:\s+\(x\d+\))?$""")
    private val WINDOWS_DRIVE = Regex("""^[A-Za-z]:/""")

    private val json = Json {
        prettyPrint = true
        prettyPrintIndent = "  "
    }

    fun render(reports: List<ScanReport>): String {
        val pairedFindings = reports.flatMap { report -> report.findings.map { report to it } }
        val usedRuleIds = pairedFindings.map { (_, finding) -> finding.ruleId }.distinct().sorted()
        val ruleIndices = usedRuleIds.withIndex().associate { (index, id) -> id to index }
        val toolVersion = reports.firstOrNull()?.toolVersion ?: BuildInfo.version

        val root = buildJsonObject {
            put("\$schema", SCHEMA)
            put("version", VERSION)
            putJsonArray("runs") {
                add(
                    buildJsonObject {
                        putJsonObject("tool") {
                            putJsonObject("driver") {
                                put("name", "ServerDoctor")
                                put("version", toolVersion)
                                put("informationUri", INFO_URI)
                                putJsonArray("rules") {
                                    usedRuleIds.forEach { add(ruleObject(it)) }
                                }
                            }
                        }
                        putJsonArray("results") {
                            pairedFindings.forEach { (report, finding) ->
                                add(resultObject(report, finding, ruleIndices[finding.ruleId] ?: 0))
                            }
                        }
                    },
                )
            }
        }
        return json.encodeToString(root)
    }

    private fun ruleObject(ruleId: String) = buildJsonObject {
        val rule = RuleCatalog.byId(ruleId)
        val title = rule?.title ?: ruleId
        val rationale = rule?.rationale ?: title
        val fixText = rule?.fix ?: "Inspect the referenced artifact and apply the documented fix."
        val provenance = rule?.provenance ?: ""

        put("id", ruleId)
        put("name", pascalIdentifier(title, fallback = ruleId))
        putJsonObject("shortDescription") { put("text", title) }
        putJsonObject("fullDescription") { put("text", rationale) }
        put("helpUri", RULES_HELP_URI)
        putJsonObject("help") {
            put("text", fixText)
            put(
                "markdown",
                buildString {
                    appendLine("**$title**")
                    appendLine()
                    appendLine(rationale)
                    if (rule?.fix != null) {
                        appendLine()
                        appendLine("**Fix:** ${rule.fix}")
                    }
                    if (provenance.isNotBlank()) {
                        appendLine()
                        appendLine("**Source:** $provenance")
                    }
                }.trimEnd(),
            )
        }
        putJsonObject("defaultConfiguration") {
            put("level", sarifLevel(rule?.severity))
        }
        putJsonObject("properties") {
            putJsonArray("tags") {
                add(kotlinx.serialization.json.JsonPrimitive("minecraft"))
                add(kotlinx.serialization.json.JsonPrimitive("paper"))
                add(kotlinx.serialization.json.JsonPrimitive("folia"))
                rule?.area?.label?.let { add(kotlinx.serialization.json.JsonPrimitive(it)) }
            }
        }
    }

    private fun resultObject(report: ScanReport, finding: Finding, ruleIndex: Int) = buildJsonObject {
        val (uri, startLine) = parseLocation(report.subject, finding.location)
        val messageText = buildString {
            append(finding.detail)
            if (finding.evidence.isNotEmpty()) {
                append(" Evidence: ")
                append(finding.evidence.take(3).joinToString(" | "))
            }
            finding.fix?.let { append(" Fix: ").append(it) }
        }

        put("ruleId", finding.ruleId)
        put("ruleIndex", ruleIndex)
        put("level", sarifLevel(finding.severity))
        putJsonObject("message") {
            put("text", messageText)
        }
        putJsonArray("locations") {
            add(
                buildJsonObject {
                    putJsonObject("physicalLocation") {
                        putJsonObject("artifactLocation") {
                            put("uri", uri)
                            put("uriBaseId", "%SRCROOT%")
                        }
                        putJsonObject("region") {
                            put("startLine", startLine)
                        }
                    }
                },
            )
        }
        putJsonObject("partialFingerprints") {
            put("primaryLocationLineHash", fingerprint("${finding.ruleId}|$uri|$startLine|${finding.detail}"))
        }
    }

    internal fun parseLocation(subject: String, rawLocation: String): Pair<String, Int> {
        val trimmed = rawLocation.trim()
        LINE_ONLY.find(trimmed)?.let { match ->
            val line = match.groupValues[1].toIntOrNull()?.coerceAtLeast(1) ?: 1
            return normalizeUri(subject) to line
        }
        FILE_AND_LINE.find(trimmed)?.let { match ->
            val pathPart = match.groupValues[1]
            val line = match.groupValues[2].toIntOrNull()?.coerceAtLeast(1) ?: 1
            return normalizeUri(pathPart) to line
        }
        val candidate = trimmed.substringBefore(" (x").ifBlank { subject }
        return normalizeUri(candidate) to 1
    }

    internal fun normalizeUri(raw: String): String {
        var cleaned = raw.trim().replace('\\', '/')
        cleaned = cleaned.substringBefore(" (")
        cleaned = WINDOWS_DRIVE.replace(cleaned, "")
        cleaned = cleaned.trimStart('/')
        while (cleaned.startsWith("./")) cleaned = cleaned.removePrefix("./")
        if (cleaned.isBlank() || cleaned.startsWith("-")) return "server-config"
        return cleaned
    }

    internal fun pascalIdentifier(title: String, fallback: String): String {
        val words = title.split(Regex("[^A-Za-z0-9]+")).filter { it.isNotBlank() }
        val joined = words.joinToString("") { word ->
            word.lowercase().replaceFirstChar { ch -> ch.uppercaseChar() }
        }
        return when {
            joined.isEmpty() -> fallback
            joined.first().isDigit() -> "Rule$joined"
            else -> joined
        }
    }

    private fun sarifLevel(severity: Severity?): String = when (severity) {
        Severity.BLOCKER, Severity.CRITICAL -> "error"
        Severity.WARNING -> "warning"
        Severity.INFO, null -> "note"
    }

    private fun fingerprint(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return digest.take(16).joinToString("") { "%02x".format(it) }
    }
}
