package com.salyvn.serverdoctor

import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.core.parse
import com.github.ajalt.clikt.core.subcommands
import com.salyvn.serverdoctor.cli.ConfigCommand
import com.salyvn.serverdoctor.cli.LogCommand
import com.salyvn.serverdoctor.cli.ScanCommand
import com.salyvn.serverdoctor.config.ConfigAudit
import com.salyvn.serverdoctor.config.ServerConfigSet
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.LogTriage
import com.salyvn.serverdoctor.report.SarifReporter
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText

class SarifAndCliTest {

    @Test
    fun `renders valid sarif v2_1_0 with deduplicated rules and mapped line locations`() {
        val logReport = LogTriage().analyse(LogSource.of(TestFixtures.path("/logs/broken-paper-server.log")))
        val configReport = ConfigAudit().analyse(ServerConfigSet.read(TestFixtures.serverDirectory()))
        val raw = SarifReporter.render(listOf(logReport, configReport))
        val root = Json.parseToJsonElement(raw).jsonObject

        assertEquals("https://json.schemastore.org/sarif-2.1.0.json", root["\$schema"]!!.jsonPrimitive.content)
        assertEquals("2.1.0", root["version"]!!.jsonPrimitive.content)

        val run = root["runs"]!!.jsonArray.single().jsonObject
        val driver = run["tool"]!!.jsonObject["driver"]!!.jsonObject
        assertEquals("ServerDoctor", driver["name"]!!.jsonPrimitive.content)
        assertEquals("https://github.com/SalyyS1/serverdoctor", driver["informationUri"]!!.jsonPrimitive.content)

        val rules = driver["rules"]!!.jsonArray.map { it.jsonObject }
        val ruleIds = rules.map { it["id"]!!.jsonPrimitive.content }
        assertEquals(ruleIds.size, ruleIds.toSet().size, "driver.rules must be deduplicated")
        for (rule in rules) {
            val name = rule["name"]!!.jsonPrimitive.content
            assertFalse(name.contains(' '), "SARIF rule name must not contain spaces: $name")
        }

        val results = run["results"]!!.jsonArray.map { it.jsonObject }
        assertEquals(logReport.findings.size + configReport.findings.size, results.size)

        val watchdogResult = results.first { it["ruleId"]!!.jsonPrimitive.content == "L001" }
        assertEquals("error", watchdogResult["level"]!!.jsonPrimitive.content)
        val location = watchdogResult["locations"]!!.jsonArray.single().jsonObject["physicalLocation"]!!.jsonObject
        val uri = location["artifactLocation"]!!.jsonObject["uri"]!!.jsonPrimitive.content
        assertFalse(uri.startsWith("/"), "SARIF artifact URI must be relative: $uri")
        assertEquals(39, location["region"]!!.jsonObject["startLine"]!!.jsonPrimitive.int)

        for (result in results) {
            val idx = result["ruleIndex"]!!.jsonPrimitive.int
            assertEquals(result["ruleId"]!!.jsonPrimitive.content, ruleIds[idx])
        }
    }

    @Test
    fun `cli writes sarif and json files and enforces fail-on exit code`() {
        val outDir = createTempDirectory("serverdoctor-cli")
        try {
            val jsonOut = outDir.resolve("report.json")
            val sarifOut = outDir.resolve("report.sarif")
            val logPath = TestFixtures.path("/logs/broken-paper-server.log").toString()

            val cmd = ServerDoctorCommand().subcommands(LogCommand(), ConfigCommand(), ScanCommand())
            val thrown = assertThrows(ProgramResult::class.java) {
                cmd.parse(
                    listOf(
                        "log",
                        logPath,
                        "--json",
                        "-o",
                        jsonOut.toString(),
                        "--sarif",
                        sarifOut.toString(),
                        "--fail-on",
                        "critical",
                    ),
                )
            }
            assertEquals(1, thrown.statusCode)
            assertTrue(jsonOut.readText().contains("\"schema\": 1"))
            assertTrue(sarifOut.readText().contains("\"version\": \"2.1.0\""))

            val neverCmd = ServerDoctorCommand().subcommands(LogCommand())
            neverCmd.parse(listOf("log", logPath, "--format", "sarif", "-o", sarifOut.toString(), "--fail-on", "never"))
        } finally {
            outDir.toFile().deleteRecursively()
        }
    }
}
