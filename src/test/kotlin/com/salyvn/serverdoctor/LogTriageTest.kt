package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.core.Severity
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.LogParser
import com.salyvn.serverdoctor.log.LogTriage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class LogTriageTest {

    private val report by lazy {
        LogTriage().analyse(LogSource.of(TestFixtures.path("/logs/broken-paper-server.log")))
    }

    private fun ids() = report.findings.map { it.ruleId }.toSet()

    @Test
    fun `finds the signatures the fixture contains`() {
        val expected = setOf(
            "L001", // watchdog
            "L002", // async catcher
            "L003", // event handler threw
            "L004", // plugin load failed
            "L005", // ambiguous plugin name
            "L006", // class file version
            "L009", // legacy plugin, no api-version
            "L010", // deprecated api nag
            "L012", // eula
            "L013", // out of memory
        )
        assertTrue(ids().containsAll(expected), "missing ${expected - ids()} in ${ids()}")
    }

    @Test
    fun `does not claim vanilla's overload warning on a paper log`() {
        assertFalse("L014" in ids(), "L014 should only fire when the line is actually present")
    }

    @Test
    fun `groups repeated occurrences instead of listing each one`() {
        val eventThrow = report.findings.first { it.ruleId == "L003" }
        assertTrue(eventThrow.location.contains("x2"), "expected a count in ${eventThrow.location}")
    }

    @Test
    fun `keeps the watchdog dump separate from later stack traces`() {
        val watchdog = report.findings.first { it.ruleId == "L001" }
        assertTrue(
            watchdog.evidence.any { it.contains("MySqlStore") },
            "watchdog evidence should carry the dump: ${watchdog.evidence}",
        )
        assertTrue(
            watchdog.evidence.none { it.contains("RegionReader") },
            "an unrelated later trace leaked into the dump: ${watchdog.evidence}",
        )
    }

    @Test
    fun `reports an error no rule explains rather than staying silent`() {
        val leftover = report.findings.firstOrNull { it.ruleId == "L016" }
        assertNotNull(leftover, "the corrupt-region exception has no signature and must still surface")
        assertTrue(leftover!!.detail.contains("IllegalStateException"))
    }

    @Test
    fun `reads the server facts out of the header lines`() {
        assertEquals("26.2", report.facts["minecraft"])
        assertTrue(report.facts["server"]!!.startsWith("Paper version"))
        assertEquals("paper", report.facts["line format"])
    }

    @Test
    fun `worst severity is a blocker because start-up failed`() {
        assertEquals(Severity.BLOCKER, report.worst)
    }

    @Test
    fun `parses the three header shapes and strips transport noise`() {
        val parser = LogParser()
        val cases = mapOf(
            "[22:31:04] [Server thread/INFO]: hello" to Triple("Server thread", "INFO", "hello"),
            "[22:31:04 WARN]: hello" to Triple(null, "WARN", "hello"),
            "[2026-08-24 22:31:04] [main/ERROR]: hello" to Triple("main", "ERROR", "hello"),
        )
        for ((line, expected) in cases) {
            val events = collect(parser, line)
            assertEquals(1, events.size, "one event for: $line")
            val event = events.single()
            assertEquals(expected.first, event.thread)
            assertEquals(expected.second, event.level)
            assertEquals(expected.third, event.message)
        }
    }

    @Test
    fun `takes the plugin name out of a bracketed logger prefix`() {
        val event = collect(LogParser(), "[22:31:04] [Server thread/INFO]: [WorldTools] loaded").single()
        assertEquals("WorldTools", event.loggerPlugin)
        assertEquals("loaded", event.message)
    }

    @Test
    fun `does not mistake bracketed prose for a plugin prefix`() {
        val event = collect(LogParser(), "[22:31:04] [Server thread/INFO]: [this is not a plugin!] x").single()
        assertNull(event.loggerPlugin)
    }

    private fun collect(parser: LogParser, text: String): List<com.salyvn.serverdoctor.log.LogEvent> {
        val file = kotlin.io.path.createTempFile(suffix = ".log")
        file.toFile().writeText(text + "\n")
        val events = mutableListOf<com.salyvn.serverdoctor.log.LogEvent>()
        parser.parse(LogSource.of(file)) { events += it }
        file.toFile().delete()
        return events
    }
}
