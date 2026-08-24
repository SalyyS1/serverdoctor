package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.perms.PermsAudit
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Path
import kotlin.io.path.createTempDirectory

class PermsAuditTest {

    private val directory: Path = TestFixtures.path("/access/server.properties").parent

    private val report by lazy { PermsAudit().analyse(directory, directory.toString()) }

    private fun ids() = report.findings.map { it.ruleId }.toSet()

    @Test
    fun `finds the problems planted in the access lists`() {
        val expected = setOf(
            "S001", // offline mode, no forwarding, and four operators
            "S003", // an operator entry with no id
            "S004", // one name twice
            "S005", // an operator who is also banned
            "S006", // permissions.yml is not valid YAML
            "S008", // the whitelist is on and empty
            "S009", // an operator who bypasses the player limit
        )
        assertTrue(ids().containsAll(expected), "missing ${expected - ids()} in ${ids()}")
        assertFalse("S002" in ids(), "every JSON file in the fixture parses")
    }

    @Test
    fun `does not count a banned address as an entry with a missing id`() {
        val nameless = report.findings.filter { it.ruleId == "S003" }
        assertEquals(listOf("ops.json"), nameless.map { it.location })
        assertTrue(nameless.single().detail.contains("Bo"), nameless.single().detail)
    }

    @Test
    fun `names the operator who is banned and why`() {
        val conflict = report.findings.first { it.ruleId == "S005" }
        assertTrue(conflict.detail.contains("Cyd"), conflict.detail)
        assertTrue(conflict.detail.contains("griefing spawn"), conflict.detail)
    }

    @Test
    fun `records what it read the lists as`() {
        assertEquals("false", report.facts["online-mode"])
        assertEquals("true", report.facts["white-list"])
        assertEquals("false", report.facts["enforce-whitelist"])
        assertEquals("4 operators", report.facts["ops.json"])
        assertEquals("empty", report.facts["whitelist.json"])
        assertEquals("1 banned player", report.facts["banned-players.json"])
        assertEquals("1 banned address", report.facts["banned-ips.json"])
    }

    @Test
    fun `does not report operators in offline mode when a proxy forwards identity`() {
        // The mirror of the config audit's rule: a backend server behind Velocity is supposed to be
        // offline-mode=false, and reporting its operators would be the false positive that teaches
        // people to ignore the tool.
        withServer(
            properties = "online-mode=false\n",
            paperGlobal = "proxies:\n  velocity:\n    enabled: true\n    secret: abc\n",
        ) { root ->
            val found = PermsAudit().analyse(root, root.toString()).findings.map { it.ruleId }
            assertFalse("S001" in found, "S001 fired behind a proxy: $found")
        }
    }

    @Test
    fun `does not report operators on a server that verifies identity`() {
        withServer(properties = "online-mode=true\n") { root ->
            val found = PermsAudit().analyse(root, root.toString()).findings.map { it.ruleId }
            assertFalse("S001" in found, "S001 fired in online mode: $found")
        }
    }

    @Test
    fun `reports a permissions file that bukkit yml points at and is not there`() {
        withServer(
            properties = "online-mode=true\n",
            bukkit = "settings:\n  permissions-file: group-permissions.yml\n",
        ) { root ->
            val found = PermsAudit().analyse(root, root.toString()).findings
            assertTrue(found.any { it.ruleId == "S007" }, "expected S007 in ${found.map { it.ruleId }}")
            assertTrue(
                found.first { it.ruleId == "S007" }.detail.contains("group-permissions.yml"),
                "the finding should name the file that was configured",
            )
        }
    }

    @Test
    fun `an access list that is not json is reported rather than treated as empty`() {
        withServer(properties = "online-mode=true\n", ops = "{ this is not a list }") { root ->
            val found = PermsAudit().analyse(root, root.toString()).findings
            assertTrue(found.any { it.ruleId == "S002" }, "expected S002 in ${found.map { it.ruleId }}")
        }
    }

    private fun withServer(
        properties: String,
        paperGlobal: String? = null,
        bukkit: String? = null,
        ops: String = """[{"uuid":"4d1a2f60-9b3c-4e5a-8f21-0c7b6d5e4a31","name":"Ari","level":4}]""",
        block: (Path) -> Unit,
    ) {
        val root = createTempDirectory("serverdoctor-perms")
        try {
            root.resolve("server.properties").toFile().writeText(properties)
            root.resolve("ops.json").toFile().writeText(ops)
            paperGlobal?.let {
                val config = root.resolve("config")
                config.toFile().mkdirs()
                config.resolve("paper-global.yml").toFile().writeText(it)
            }
            bukkit?.let { root.resolve("bukkit.yml").toFile().writeText(it) }
            block(root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
