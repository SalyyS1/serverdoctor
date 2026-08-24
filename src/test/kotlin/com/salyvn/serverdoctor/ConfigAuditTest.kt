package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.config.ConfigAudit
import com.salyvn.serverdoctor.config.ServerConfigSet
import com.salyvn.serverdoctor.input.YamlSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ConfigAuditTest {

    private val report by lazy { ConfigAudit().analyse(ServerConfigSet.read(TestFixtures.serverDirectory())) }

    private fun ids() = report.findings.map { it.ruleId }.toSet()

    @Test
    fun `finds the problems planted in the fixture`() {
        val expected = setOf(
            "C002", // velocity enabled, empty secret
            "C004", // unsupported-settings toggle on
            "C005", // console has all permissions
            "C006", // rcon without password
            "C007", // simulation > view
            "C008", // watchdog timeout raised
            "C010", // duplicate key
            "C011", // legacy paper.yml
            "C012", // no version key
            "C013", // secure profile off
            "C014", // eula not accepted
        )
        assertTrue(ids().containsAll(expected), "missing ${expected - ids()} in ${ids()}")
    }

    @Test
    fun `does not report offline mode when forwarding is configured`() {
        // The fixture is offline-mode=false with Velocity forwarding on, which is the correct
        // configuration for a backend server. Reporting C001 here would be the classic false
        // positive this cross-file check exists to avoid.
        assertFalse("C001" in ids(), "C001 fired even though velocity forwarding is enabled")
    }

    @Test
    fun `reports offline mode when nothing forwards`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-offline")
        directory.resolve("server.properties").toFile().writeText("online-mode=false\nlevel-name=world\n")
        directory.resolve("eula.txt").toFile().writeText("eula=true\n")
        val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.map { it.ruleId }
        assertTrue("C001" in findings, "expected C001 in $findings")
        directory.toFile().deleteRecursively()
    }

    @Test
    fun `keeps the value the server would actually use for a duplicated key`() {
        val duplicate = report.findings.first { it.ruleId == "C010" }
        assertTrue(duplicate.detail.contains("appears 2 times"), duplicate.detail)
    }

    @Test
    fun `records the cross-file facts it based the checks on`() {
        assertEquals("false", report.facts["online-mode"])
        assertEquals("velocity", report.facts["forwarding"])
        assertEquals("view 10, simulation 12", report.facts["distances"])
    }

    @Test
    fun `composing yaml keeps line numbers and duplicate keys`() {
        val source = YamlSource.compose(
            "test.yml",
            """
            settings:
              a: 1
              b: 2
              a: 3
            list:
              - one
              - two
            """.trimIndent(),
        )
        assertTrue(source.ok)
        assertEquals("3", source.text("settings.a"), "the later value wins, as in the loader")
        assertEquals(1, source.duplicatePaths.size)
        assertEquals("settings.a", source.duplicatePaths.single().path)
        assertEquals(listOf("one", "two"), source.list("list"))
        assertEquals(3, source["settings.b"]!!.line)
    }

    @Test
    fun `an unparseable config is a blocker rather than an exception`() {
        val source = YamlSource.compose("broken.yml", "settings:\n\tindented-with-a-tab: true\n")
        assertFalse(source.ok)
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-broken")
        directory.resolve("server.properties").toFile().writeText("level-name=world\n")
        directory.resolve("spigot.yml").toFile().writeText("settings:\n\tbungeecord: true\n")
        directory.resolve("eula.txt").toFile().writeText("eula=true\n")
        val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings
        assertTrue(findings.any { it.ruleId == "C009" }, "expected C009 in ${findings.map { it.ruleId }}")
        directory.toFile().deleteRecursively()
    }
}
