package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.crash.CrashAudit
import com.salyvn.serverdoctor.crash.CrashReportFile
import com.salyvn.serverdoctor.flags.FlagsAudit
import com.salyvn.serverdoctor.flags.JvmCommandLine
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.io.path.createTempDirectory

class CrashAuditTest {

    private val directory = TestFixtures.path("/crash-reports/crash-2026-08-24_11.04.12-server.txt").parent

    private val reports by lazy { CrashReportFile.discover(directory).map { CrashReportFile.read(it) } }

    private val report by lazy { CrashAudit().analyse(reports, directory.toString()) }

    private fun ids() = report.findings.map { it.ruleId }.toSet()

    @Test
    fun `finds all three reports and what each one says`() {
        assertEquals(3, reports.size, "discovery should find the three crash reports")
        val expected = setOf(
            "X001", // the crash itself
            "X002", // a plugin frame in the trace
            "X003", // out of memory
            "X004", // something was being ticked
            "X005", // the same crash twice
        )
        assertTrue(ids().containsAll(expected), "missing ${expected - ids()} in ${ids()}")
        assertEquals(3, report.findings.count { it.ruleId == "X001" }, "one per report")
    }

    @Test
    fun `blames the plugin frame rather than the server frame under it`() {
        val blame = report.findings.first { it.ruleId == "X002" }
        assertTrue(blame.detail.contains("com.example.spawner"), blame.detail)
        assertTrue(
            blame.evidence.first().contains("SpawnerListener"),
            "the outermost foreign frame should lead the evidence: ${blame.evidence}",
        )
    }

    @Test
    fun `counts the repeated crash once and names both files`() {
        val repeat = report.findings.first { it.ruleId == "X005" }
        assertTrue(repeat.detail.startsWith("2 reports say: Ticking entity"), repeat.detail)
        assertEquals(2, repeat.evidence.size, repeat.evidence.toString())
    }

    @Test
    fun `names the object that was being ticked`() {
        val ticking = report.findings.first { it.ruleId == "X004" }
        assertTrue(ticking.detail.contains("Entity being ticked"), ticking.detail)
        assertTrue(
            ticking.evidence.any { it.contains("minecraft:zombie") },
            "the entity's own details should be the evidence: ${ticking.evidence}",
        )
    }

    @Test
    fun `reads the system details out of the newest report`() {
        assertEquals("3", report.facts["crash reports"])
        assertEquals("crash-2026-08-24_12.02.40-server.txt", report.facts["newest"])
        assertEquals("1.21.4", report.facts["minecraft"])
        assertEquals("Paper", report.facts["server brand"])
        assertEquals("3", report.facts["plugins listed"])
        assertTrue(report.facts.getValue("java").startsWith("21"), report.facts.getValue("java"))
    }

    @Test
    fun `recovers the flags the dead server ran with`() {
        val ticking = reports.first { it.name.contains("11.04.12") }
        assertEquals("-Xms1G -Xmx3G -XX:+UseConcMarkSweepGC -Ddisable.watchdog=true", ticking.jvmFlags)

        val flags = FlagsAudit().analyse("crash", JvmCommandLine.parse(ticking.jvmFlags!!))
        val found = flags.findings.map { it.ruleId }
        assertTrue("F003" in found, "the watchdog flag should be caught from the crash report: $found")
        assertTrue("F006" in found, "a removed collector should be caught from the crash report: $found")
    }

    @Test
    fun `keeps the jdk frames a modern jvm prefixes with its module`() {
        val oom = reports.first { it.outOfMemory }
        val top = oom.headFrames.first()
        assertEquals("java.util.Arrays", top.className, "the module prefix belongs to the JVM, not the class")
        assertTrue(top.raw.startsWith("at java.base/"), top.raw)
    }

    @Test
    fun `a file that is not a crash report is reported rather than parsed into nothing`() {
        val temporary = createTempDirectory("serverdoctor-crash")
        try {
            val file = temporary.resolve("crash-not-really.txt")
            file.toFile().writeText("this file was never written by a server\n")
            val audited = CrashAudit().analyse(listOf(CrashReportFile.read(file)), temporary.toString())
            assertEquals(listOf("X006"), audited.findings.map { it.ruleId })
        } finally {
            temporary.toFile().deleteRecursively()
        }
    }
}
