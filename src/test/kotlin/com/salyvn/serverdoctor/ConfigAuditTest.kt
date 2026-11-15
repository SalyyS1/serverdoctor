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

    @Test
    fun `detects paper chunk-system io-threads and worker-threads bottlenecks`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-chunk-cfg")
        try {
            directory.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val configDir = java.nio.file.Files.createDirectories(directory.resolve("config"))
            configDir.resolve("paper-global.yml").toFile().writeText(
                """
                _version: 29
                version: 29
                chunk-system:
                  io-threads: 0
                  worker-threads: 1
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C018" }
            assertEquals(2, findings.size, "expected C018 for io-threads=0 and worker-threads=1: $findings")
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects paper 26_3 config schema version mismatch and deprecated root keys`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-schema-test")
        try {
            directory.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val configDir = java.nio.file.Files.createDirectories(directory.resolve("config"))
            configDir.resolve("paper-global.yml").toFile().writeText(
                """
                version: 28
                timings:
                  enabled: true
                messages:
                  kick:
                    flying: "Flying is not enabled on this server"
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C019" }
            assertTrue(findings.size >= 2, "expected C019 findings for old version and deprecated roots: $findings")
            assertTrue(findings.any { it.detail.contains("28") })
            assertTrue(findings.any { it.detail.contains("timings") })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects network compression tuning hazards`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-compression-test")
        try {
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            directory.resolve("server.properties").toFile().writeText(
                """
                online-mode=true
                level-name=world
                network-compression-threshold=32
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C020" }
            assertEquals(1, findings.size)
            assertTrue(findings.single().detail.contains("32"))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects netty threads bottleneck when pinned to 1`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-netty-test")
        try {
            directory.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            directory.resolve("spigot.yml").toFile().writeText(
                """
                settings:
                  netty-threads: 1
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C021" }
            assertEquals(1, findings.size)
            assertTrue(findings.single().detail.contains("settings.netty-threads is 1"))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects paper 26_3 item component validation hazards`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-item-comp-test")
        try {
            directory.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val configDir = java.nio.file.Files.createDirectories(directory.resolve("config"))
            configDir.resolve("paper-global.yml").toFile().writeText(
                """
                version: 30
                item-validation:
                  resolve-selectors-in-books: true
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C022" }
            assertEquals(1, findings.size)
            assertTrue(findings.single().detail.contains("resolve-selectors-in-books is set to true"))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects folia threaded-regions serialisation and chunk worker starvation`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-folia-threads")
        try {
            directory.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val configDir = java.nio.file.Files.createDirectories(directory.resolve("config"))
            configDir.resolve("paper-global.yml").toFile().writeText(
                """
                version: 30
                threaded-regions:
                  threads: 16
                chunk-system:
                  worker-threads: 2
                """.trimIndent() + "\n",
            )
            configDir.resolve("folia.yml").toFile().writeText(
                """
                threaded-regions:
                  threads: 1
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C023" }
            assertEquals(2, findings.size, "expected C023 for worker starvation and threads=1: $findings")
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects paper 26_3 world tick-rates villager poi hyper-polling and zeroed intervals`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-tick-rates")
        try {
            directory.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val configDir = java.nio.file.Files.createDirectories(directory.resolve("config"))
            configDir.resolve("paper-world-defaults.yml").toFile().writeText(
                """
                _version: 31
                version: 31
                tick-rates:
                  container-update: 0
                  grass-spread: 4
                  sensor:
                    villager:
                      secondarypoisensor: 2
                  behavior:
                    villager:
                      validatenearbypoi: -1
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C024" }
            assertEquals(2, findings.size, "expected C024 for container-update=0 and secondarypoisensor=2: $findings")
            assertTrue(findings.any { it.detail.contains("container-update is 0") })
            assertTrue(findings.any { it.detail.contains("secondarypoisensor is 2") })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects unbounded max-entity-collisions and entity-activation-range exceeding simulation distance`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-collisions-activation")
        try {
            directory.resolve("server.properties").toFile().writeText(
                "online-mode=true\nlevel-name=world\nview-distance=10\nsimulation-distance=6\n",
            )
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val configDir = java.nio.file.Files.createDirectories(directory.resolve("config"))
            configDir.resolve("paper-world-defaults.yml").toFile().writeText(
                """
                version: 31
                collisions:
                  max-entity-collisions: 0
                """.trimIndent() + "\n",
            )
            directory.resolve("spigot.yml").toFile().writeText(
                """
                world-settings:
                  default:
                    entity-activation-range:
                      animals: 32
                      monsters: 128
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C025" }
            assertEquals(2, findings.size, "expected C025 for max-entity-collisions=0 and monsters=128 > 96: $findings")
            assertTrue(findings.any { it.detail.contains("max-entity-collisions is 0") })
            assertTrue(findings.any { it.detail.contains("monsters is 128 blocks, exceeding simulation-distance=6 (96 blocks)") })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects paper 26_3 packet-limiter rate ceiling and interval hazards`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-packet-limiter")
        try {
            directory.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val configDir = java.nio.file.Files.createDirectories(directory.resolve("config"))
            configDir.resolve("paper-global.yml").toFile().writeText(
                """
                version: 30
                packet-limiter:
                  all-packets:
                    interval: 0.0
                    max-packet-rate: -1.0
                  overrides:
                    ServerboundPlaceRecipePacket:
                      interval: 4.0
                      max-packet-rate: 0.0
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C026" }
            assertEquals(3, findings.size, "expected 3 C026 packet-limiter findings: $findings")
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects paper 26_3 chunk-loading-basic and advanced misconfigurations without false positives`() {
        val healthyDir = kotlin.io.path.createTempDirectory("serverdoctor-chunk-healthy")
        try {
            healthyDir.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            healthyDir.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(healthyDir.resolve("world"))
            val cfg = java.nio.file.Files.createDirectories(healthyDir.resolve("config"))
            cfg.resolve("paper-global.yml").toFile().writeText(
                """
                version: 30
                chunk-loading-basic:
                  player-max-chunk-load-rate: 100.0
                  player-max-chunk-send-rate: -1.0
                chunk-loading-advanced:
                  player-max-concurrent-chunk-generates: 0
                """.trimIndent() + "\n",
            )
            val cleanFindings = ConfigAudit().analyse(ServerConfigSet.read(healthyDir)).findings.filter { it.ruleId == "C027" }
            assertTrue(cleanFindings.isEmpty(), "default Paper 26.3 chunk-loading limits must stay quiet: $cleanFindings")
        } finally {
            healthyDir.toFile().deleteRecursively()
        }

        val brokenDir = kotlin.io.path.createTempDirectory("serverdoctor-chunk-broken")
        try {
            brokenDir.resolve("server.properties").toFile().writeText("online-mode=true\nlevel-name=world\n")
            brokenDir.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(brokenDir.resolve("world"))
            val cfg = java.nio.file.Files.createDirectories(brokenDir.resolve("config"))
            cfg.resolve("paper-global.yml").toFile().writeText(
                """
                version: 30
                chunk-loading-basic:
                  player-max-chunk-load-rate: 0.0
                  player-max-chunk-send-rate: 0.0
                chunk-loading-advanced:
                  player-max-concurrent-chunk-generates: 128
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(brokenDir)).findings.filter { it.ruleId == "C027" }
            assertEquals(3, findings.size, "expected 3 C027 findings: $findings")
        } finally {
            brokenDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects paper 26_3 autosave persistence hazards and pause-when-empty on network servers`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-autosave-pause")
        try {
            directory.resolve("server.properties").toFile().writeText(
                """
                online-mode=false
                level-name=world
                enable-rcon=true
                rcon.password=s3cr3t-long-token
                pause-when-empty-seconds=60
                """.trimIndent() + "\n",
            )
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val cfg = java.nio.file.Files.createDirectories(directory.resolve("config"))
            cfg.resolve("paper-global.yml").toFile().writeText(
                """
                version: 30
                proxies:
                  velocity:
                    enabled: true
                    secret: "shared-secret"
                player-auto-save:
                  max-per-tick: 0
                """.trimIndent() + "\n",
            )
            cfg.resolve("paper-world-defaults.yml").toFile().writeText(
                """
                version: 31
                chunks:
                  auto-save-interval: 0
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C028" }
            assertEquals(3, findings.size, "expected C028 for max-per-tick=0, auto-save-interval=0, and pause-when-empty: $findings")
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun `detects paper 26_3 despawn-ranges ring inversion, border overflow, and unthrottled hoppers`() {
        val directory = kotlin.io.path.createTempDirectory("serverdoctor-despawn-hoppers")
        try {
            directory.resolve("server.properties").toFile().writeText(
                "online-mode=true\nlevel-name=world\nview-distance=8\nsimulation-distance=6\n",
            )
            directory.resolve("eula.txt").toFile().writeText("eula=true\n")
            java.nio.file.Files.createDirectories(directory.resolve("world"))
            val cfg = java.nio.file.Files.createDirectories(directory.resolve("config"))
            cfg.resolve("paper-world-defaults.yml").toFile().writeText(
                """
                version: 31
                entities:
                  spawning:
                    despawn-ranges:
                      monster:
                        horizontal:
                          soft: 96
                          hard: 64
                      creature:
                        soft: 32
                        hard: 224
                hopper:
                  cooldown-when-full: false
                  disable-move-event: false
                """.trimIndent() + "\n",
            )
            val findings = ConfigAudit().analyse(ServerConfigSet.read(directory)).findings.filter { it.ruleId == "C029" }
            assertEquals(3, findings.size, "expected 3 C029 findings for monster inversion, creature overflow, and hoppers: $findings")
        } finally {
            directory.toFile().deleteRecursively()
        }
    }
}
