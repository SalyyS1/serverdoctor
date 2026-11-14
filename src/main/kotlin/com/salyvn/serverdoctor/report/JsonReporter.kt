package com.salyvn.serverdoctor.report

import com.salyvn.serverdoctor.core.Finding
import com.salyvn.serverdoctor.core.ScanReport
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Machine-readable output. The shape is deliberately flat and boring: a wrapper with a schema
 * version, then one entry per audit. Anything that consumes this - a CI step, a Discord bot, an
 * agent - should be able to read it without a client library.
 */
object JsonReporter {

    private const val SCHEMA = 1

    private val json = Json {
        prettyPrint = true
        prettyPrintIndent = "  "
        encodeDefaults = true
    }

    @Serializable
    private data class Summary(
        val blocker: Int,
        val critical: Int,
        val warning: Int,
        val info: Int,
        val worst: String?,
    )

    @Serializable
    private data class Audit(
        val subject: String,
        val subjectKind: String,
        val facts: Map<String, String>,
        val summary: Summary,
        val findings: List<Finding>,
    )

    @Serializable
    private data class Envelope(
        val schema: Int,
        val tool: String,
        val toolVersion: String,
        val summary: Summary,
        val audits: List<Audit>,
    )

    fun render(reports: List<ScanReport>): String {
        val audits = reports.map { report ->
            Audit(
                subject = report.subject,
                subjectKind = report.subjectKind,
                facts = report.facts,
                summary = summarise(report.findings),
                findings = report.findings,
            )
        }
        val envelope = Envelope(
            schema = SCHEMA,
            tool = reports.firstOrNull()?.tool ?: "serverdoctor",
            toolVersion = reports.firstOrNull()?.toolVersion ?: "unknown",
            summary = summarise(reports.flatMap { it.findings }),
            audits = audits,
        )
        return json.encodeToString(Envelope.serializer(), envelope)
    }

    private fun summarise(findings: List<Finding>) = Summary(
        blocker = findings.count { it.severity.label == "blocker" },
        critical = findings.count { it.severity.label == "critical" },
        warning = findings.count { it.severity.label == "warning" },
        info = findings.count { it.severity.label == "info" },
        worst = findings.maxByOrNull { it.severity.rank }?.severity?.label,
    )
}
