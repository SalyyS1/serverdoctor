package com.salyvn.serverdoctor.core

import kotlinx.serialization.Serializable

/**
 * How much a finding matters. The tiers are narrow on purpose, so that a severity means one
 * specific thing to the person reading the report:
 *
 * - [BLOCKER]  the server will not start, or is not starting right now.
 * - [CRITICAL] it runs, and something is actively wrong: data at risk, an open door, a crash loop.
 * - [WARNING]  it works today and depends on luck - one more plugin, one more player, one version.
 * - [INFO]     worth a human's attention. No defect claimed.
 */
@Serializable
enum class Severity(val label: String, val rank: Int) {
    BLOCKER("blocker", 4),
    CRITICAL("critical", 3),
    WARNING("warning", 2),
    INFO("info", 1);

    companion object {
        fun parse(raw: String): Severity? =
            entries.firstOrNull { it.label.equals(raw, ignoreCase = true) }
    }
}

/**
 * Which audit a rule belongs to. Used by `serverdoctor rules` to group the catalogue and by the
 * MCP surface to describe itself.
 */
enum class RuleArea(val label: String) {
    LOG("log"),
    CONFIG("config"),
    FLAGS("flags"),
    PLUGINS("plugins"),
    WORLD("world"),
    CRASH("crash"),
    PERMS("perms"),
    DIFF("diff"),
}

/**
 * A rule states one checkable fact about a server. [provenance] records where that fact was
 * established from - a source file in Paper, a JDK release note, an API response - so every claim
 * printed by this tool can be checked by the person it is being made to, instead of taken on trust.
 */
data class Rule(
    val id: String,
    val area: RuleArea,
    val severity: Severity,
    val title: String,
    val rationale: String,
    val provenance: String,
    val fix: String? = null,
)

/** One concrete hit of a [Rule] in one place. */
@Serializable
data class Finding(
    val ruleId: String,
    val severity: Severity,
    val title: String,
    /** Where it is: `server.properties:12`, `latest.log:8841`, a jar name, a config key. */
    val location: String,
    /** What was actually observed, in the reader's terms. */
    val detail: String,
    /** Raw observations backing [detail] - log lines, values, counts, class names. */
    val evidence: List<String> = emptyList(),
    val fix: String? = null,
    val provenance: String? = null,
)

/** Everything one audit produced, ready to hand to a reporter. */
@Serializable
data class ScanReport(
    val tool: String,
    val toolVersion: String,
    /** What was inspected: a log file, a server directory, a plugins folder, a command line. */
    val subject: String,
    val subjectKind: String,
    val findings: List<Finding>,
    /** Facts worth printing even when nothing is wrong: server brand, MC version, heap size. */
    val facts: Map<String, String> = emptyMap(),
) {
    fun count(severity: Severity): Int = findings.count { it.severity == severity }

    val worst: Severity?
        get() = findings.maxByOrNull { it.severity.rank }?.severity
}

/** Collects findings for one subject, keeping each hit attached to the rule that produced it. */
class FindingSink {
    private val collected = mutableListOf<Finding>()

    fun add(
        rule: Rule,
        location: String,
        detail: String,
        evidence: List<String> = emptyList(),
        severityOverride: Severity? = null,
        /** Set when one rule can be established from more than one source and this hit used one. */
        provenanceOverride: String? = null,
    ) {
        collected += Finding(
            ruleId = rule.id,
            severity = severityOverride ?: rule.severity,
            title = rule.title,
            location = location,
            detail = detail,
            evidence = evidence,
            fix = rule.fix,
            provenance = provenanceOverride ?: rule.provenance,
        )
    }

    /** Worst first, then rule id, then location, so console and JSON output are stable. */
    fun findings(): List<Finding> = collected.sortedWith(
        compareByDescending<Finding> { it.severity.rank }.thenBy { it.ruleId }.thenBy { it.location }
    )

    fun isEmpty(): Boolean = collected.isEmpty()
}
