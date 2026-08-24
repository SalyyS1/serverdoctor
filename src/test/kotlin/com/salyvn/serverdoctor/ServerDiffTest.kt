package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.diff.ServerDiff
import com.salyvn.serverdoctor.diff.ServerSnapshot
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory

class ServerDiffTest {

    private val root: Path = createTempDirectory("serverdoctor-diff")
    private val left: Path = plantLeft(root.resolve("staging"))
    private val right: Path = plantRight(root.resolve("production"))

    @AfterEach
    fun removeFixture() {
        root.toFile().deleteRecursively()
    }

    private val report by lazy { ServerDiff().compare(ServerSnapshot.read(left), ServerSnapshot.read(right)) }

    private fun ids() = report.findings.map { it.ruleId }.toSet()

    private fun finding(id: String) = report.findings.first { it.ruleId == id }

    @Test
    fun `finds every kind of difference between the two servers`() {
        val expected = setOf(
            "D001", // view-distance differs
            "D002", // allow-flight only on one side
            "D003", // purpur.yml only on one side
            "D004", // LuckPerms on one side, WorldEdit on the other
            "D005", // ExampleSpawner is at two versions
            "D006", // Vault claims one version and is not the same file
            "D007", // the heap and the watchdog flag differ
        )
        assertTrue(ids().containsAll(expected), "missing ${expected - ids()} in ${ids()}")
    }

    @Test
    fun `does not report the values two machines are supposed to disagree on`() {
        val text = report.findings.joinToString("\n") { it.detail + it.evidence.joinToString() }
        assertFalse(text.contains("server-port"), "the port is not a finding")
        assertFalse(text.contains("motd"), "the motd is not a finding")
        assertFalse(text.contains("level-seed"), "the seed is not a finding")
    }

    @Test
    fun `words a value difference as both sides rather than as a verdict`() {
        val values = finding("D001")
        assertEquals("server.properties", values.location)
        assertTrue(
            values.evidence.any { it == "view-distance: 10 against 6" },
            "expected both values in ${values.evidence}",
        )
    }

    @Test
    fun `separates a version difference from one version with two different files`() {
        assertTrue(finding("D005").detail.contains("ExampleSpawner"), finding("D005").detail)
        val repacked = finding("D006")
        assertEquals("Vault", repacked.location)
        assertEquals(2, repacked.evidence.size)
        assertTrue(repacked.evidence.all { it.contains("sha1") }, repacked.evidence.toString())
    }

    @Test
    fun `names which side each plugin is missing from`() {
        val onlyOnOneSide = report.findings.filter { it.ruleId == "D004" }
        assertEquals(2, onlyOnOneSide.size, "one finding per side")
        assertTrue(onlyOnOneSide.any { it.evidence.any { line -> line.contains("LuckPerms") } })
        assertTrue(onlyOnOneSide.any { it.evidence.any { line -> line.contains("WorldEdit") } })
    }

    @Test
    fun `reports both heap and system property differences in the flags`() {
        val flags = finding("D007")
        assertTrue(flags.evidence.any { it.startsWith("-Xmx:") }, flags.evidence.toString())
        assertTrue(flags.evidence.any { it.contains("disable.watchdog") }, flags.evidence.toString())
    }

    @Test
    fun `says nothing about a directory compared with itself`() {
        val same = ServerDiff().compare(ServerSnapshot.read(left), ServerSnapshot.read(left))
        assertTrue(same.findings.isEmpty(), "expected silence, got ${same.findings.map { it.ruleId }}")
    }

    private fun plantLeft(root: Path): Path {
        val plugins = Files.createDirectories(root.resolve("plugins"))
        root.resolve("server.properties").toFile().writeText(
            """
            online-mode=true
            view-distance=10
            simulation-distance=10
            max-players=60
            server-port=25565
            motd=Staging
            level-seed=8675309
            """.trimIndent(),
        )
        root.resolve("spigot.yml").toFile().writeText(
            "settings:\n  bungeecord: false\n  save-user-cache-on-stop-only: false\n",
        )
        root.resolve("start.sh").toFile().writeText("#!/bin/sh\njava -Xms4G -Xmx4G -XX:+UseG1GC -jar paper.jar nogui\n")
        FixtureJars.plugin(plugins, "Vault.jar", "Vault", "1.7.3")
        FixtureJars.plugin(plugins, "ExampleSpawner.jar", "ExampleSpawner", "2.0.1")
        FixtureJars.plugin(plugins, "LuckPerms.jar", "LuckPerms", "5.4.0")
        return root
    }

    private fun plantRight(root: Path): Path {
        val plugins = Files.createDirectories(root.resolve("plugins"))
        root.resolve("server.properties").toFile().writeText(
            """
            online-mode=true
            view-distance=6
            simulation-distance=10
            max-players=60
            allow-flight=true
            server-port=25566
            motd=Production
            level-seed=112358
            """.trimIndent(),
        )
        root.resolve("spigot.yml").toFile().writeText("settings:\n  bungeecord: false\n")
        root.resolve("purpur.yml").toFile().writeText("settings:\n  use-alternate-keepalive: true\n")
        root.resolve("start.sh").toFile().writeText(
            "#!/bin/sh\njava -Xms6G -Xmx6G -XX:+UseG1GC -Ddisable.watchdog=true -jar paper.jar nogui\n",
        )
        // Same name and version, different bytes: a jar that was repacked somewhere along the way.
        FixtureJars.plugin(plugins, "Vault.jar", "Vault", "1.7.3", main = "com.example.vault.VaultRepacked")
        FixtureJars.plugin(plugins, "ExampleSpawner.jar", "ExampleSpawner", "2.1.0")
        FixtureJars.plugin(plugins, "WorldEdit.jar", "WorldEdit", "7.3.0")
        return root
    }
}
