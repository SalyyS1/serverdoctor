package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.plugins.PluginIndex
import com.salyvn.serverdoctor.plugins.PluginsAudit
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Path
import kotlin.io.path.createTempDirectory

class PluginsAuditTest {

    private lateinit var directory: Path

    @BeforeEach
    fun setUp() {
        directory = createTempDirectory("serverdoctor-plugins")
    }

    @AfterEach
    fun tearDown() {
        directory.toFile().deleteRecursively()
    }

    private fun ids(): List<String> = PluginsAudit()
        .analyse(PluginIndex.read(directory), directory.toString())
        .findings
        .map { it.ruleId }

    @Test
    fun `reports a hard dependency that is not installed`() {
        FixtureJars.plugin(directory, "Shop-1.0.jar", "Shop", "1.0", depend = listOf("Vault"))
        assertTrue("P001" in ids())
    }

    @Test
    fun `is quiet when the dependency is present`() {
        FixtureJars.plugin(directory, "Shop-1.0.jar", "Shop", "1.0", depend = listOf("Vault"))
        FixtureJars.plugin(directory, "Vault-1.7.jar", "Vault", "1.7")
        assertFalse("P001" in ids())
    }

    @Test
    fun `reports two jars claiming one name`() {
        FixtureJars.plugin(directory, "Shop-2.4.1.jar", "Shop", "2.4.1")
        FixtureJars.plugin(directory, "Shop-2.3.0.jar", "Shop", "2.3.0")
        assertTrue("P002" in ids())
    }

    @Test
    fun `identifies a library that is not a plugin`() {
        FixtureJars.library(directory, "gson-2.14.0.jar", "com.google.code.gson:gson:2.14.0")
        val report = PluginsAudit().analyse(PluginIndex.read(directory), directory.toString())
        val finding = report.findings.first { it.ruleId == "P003" }
        assertTrue(finding.detail.contains("com.google.code.gson:gson:2.14.0"), finding.detail)
        assertEquals("0", report.facts["plugins"])
    }

    @Test
    fun `reports a missing api-version and a declared folia claim`() {
        FixtureJars.plugin(directory, "Ancient-1.2.jar", "Ancient", "1.2", apiVersion = null)
        FixtureJars.plugin(directory, "Regions-3.0.jar", "Regions", "3.0", foliaSupported = true)
        val found = ids()
        assertTrue("P006" in found, "expected the legacy plugin to be flagged: $found")
        assertTrue("P007" in found, "expected the folia claim to be recorded: $found")
    }

    @Test
    fun `notices a file name that disagrees with the descriptor`() {
        FixtureJars.plugin(directory, "Shop-2.4.1.jar", "Shop", "2.5.0")
        assertTrue("P005" in ids())
    }

    @Test
    fun `reads the newer paper-plugin descriptor`() {
        FixtureJars.plugin(
            directory,
            "Modern-1.0.jar",
            "Modern",
            "1.0",
            descriptorName = "paper-plugin.yml",
        )
        val report = PluginsAudit().analyse(PluginIndex.read(directory), directory.toString())
        assertEquals("1", report.facts["plugins"])
        // A paper-plugin.yml has no api-version key at all, so the legacy rule must not fire on it.
        assertFalse("P006" in report.findings.map { it.ruleId })
    }

    @Test
    fun `treats a corrupt archive as critical`() {
        directory.resolve("Truncated.jar").toFile().writeText("PK and then nothing")
        assertTrue("P004" in ids())
    }
}
