package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.world.Nbt
import com.salyvn.serverdoctor.world.WorldAudit
import com.salyvn.serverdoctor.world.WorldFolder
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Path
import kotlin.io.path.createTempDirectory

class WorldAuditTest {

    private val root: Path = createTempDirectory("serverdoctor-worlds").also { plant(it) }

    @AfterEach
    fun removeFixture() {
        root.toFile().deleteRecursively()
    }

    private val report by lazy { WorldAudit().analyse(WorldFolder.discover(root), root.toString()) }

    private fun ids() = report.findings.map { it.ruleId }.toSet()

    @Test
    fun `finds every problem planted in the worlds`() {
        val expected = setOf(
            "W001", // the end has region data and no level.dat
            "W002", // a level.dat that stops mid-tag
            "W003", // only level.dat_old survived
            "W004", // the nether was last saved by an older version
            "W005", // a zero-byte region file
            "W006", // a datapack with no pack.mcmeta
            "W007", // DIM-1 inside world and world_nether beside it
            "W008", // hardcore
            "W009", // allowCommands
            "W010", // a region file shorter than its own header
            "W011", // a header pointing at sectors the file does not have
        )
        assertTrue(ids().containsAll(expected), "missing ${expected - ids()} in ${ids()}")
    }

    @Test
    fun `reads the region header without reporting an oversized chunk`() {
        val short = report.findings.first { it.ruleId == "W010" }
        assertTrue(short.location.endsWith("r.0.2.mca"), short.location)

        val outside = report.findings.first { it.ruleId == "W011" }
        assertTrue(outside.location.endsWith("r.0.3.mca"), outside.location)
        assertTrue(outside.detail.startsWith("2 of 3 locations"), outside.detail)
        assertTrue(outside.evidence.any { it.contains("inside the header") }, outside.evidence.toString())

        // 255 sectors is Spigot's oversized marker rather than a length, so the file that uses it is
        // healthy and must produce nothing at all.
        val about = report.findings.filter { it.location.endsWith("r.0.4.mca") }
        assertTrue(about.isEmpty(), "an oversized chunk was reported as damage: $about")
    }

    @Test
    fun `blames the world that is behind, not the one that is current`() {
        val mismatch = report.findings.first { it.ruleId == "W004" }
        assertEquals("world_nether", mismatch.location)
        assertTrue(mismatch.detail.contains("1.20.4"), mismatch.detail)
        assertTrue(mismatch.detail.contains("1.21.4"), mismatch.detail)
        assertEquals(2, mismatch.evidence.size, "both worlds should be listed: ${mismatch.evidence}")
    }

    @Test
    fun `reads the version and the name out of gzipped nbt`() {
        assertEquals("world, saved by 1.21.4 (data version 4189)", report.facts["world"])
        assertEquals("5", report.facts["worlds"])
        assertEquals("8", report.facts["region files"])
        assertEquals("15", report.facts["chunks stored"])
        assertEquals("3", report.facts["player data"])
    }

    @Test
    fun `names the datapack the server will ignore and not the one beside it`() {
        val finding = report.findings.first { it.ruleId == "W006" }
        assertTrue(finding.location.endsWith("extracted-too-deep"), finding.location)
    }

    @Test
    fun `says nothing about a world that is fine`() {
        val clean = createTempDirectory("serverdoctor-clean")
        try {
            FixtureWorlds.world(clean, "world")
            val findings = WorldAudit().analyse(WorldFolder.discover(clean), clean.toString()).findings
            assertTrue(findings.isEmpty(), "expected silence, got ${findings.map { it.ruleId }}")
        } finally {
            clean.toFile().deleteRecursively()
        }
    }

    @Test
    fun `a truncated level dat is an error message rather than an exception`() {
        val document = Nbt.read(root.resolve("world_backup").resolve("level.dat"))
        assertFalse(document.ok)
        assertTrue(document.error?.contains("truncated") == true, document.error ?: "no error given")
    }

    private fun plant(root: Path) {
        val world = FixtureWorlds.world(root, "world", hardcore = true)
        val region = world.resolve("region")
        FixtureWorlds.regionFile(region.resolve("r.0.1.mca"), 0)
        FixtureWorlds.regionFileTooShort(region.resolve("r.0.2.mca"))
        FixtureWorlds.regionFileWithBadHeader(region.resolve("r.0.3.mca"))
        FixtureWorlds.regionFileWithOversizedChunk(region.resolve("r.0.4.mca"))
        FixtureWorlds.regionFileWithChunks(world.resolve("DIM-1").resolve("region").resolve("r.0.0.mca"), 2)
        FixtureWorlds.datapack(world, "carpet-rules", withMetadata = true)
        FixtureWorlds.datapack(world, "extracted-too-deep", withMetadata = false)
        FixtureWorlds.playerData(world, 3)

        FixtureWorlds.world(
            root = root,
            name = "world_nether",
            dataVersion = 3953,
            versionName = "1.20.4",
            allowCommands = true,
        )

        FixtureWorlds.regionFileWithChunks(
            root.resolve("world_the_end").resolve("region").resolve("r.0.0.mca"),
            1,
        )
        FixtureWorlds.levelDat(root.resolve("world_old").resolve("level.dat_old"), "world_old", 4189, "1.21.4")
        FixtureWorlds.truncatedLevelDat(root.resolve("world_backup").resolve("level.dat"))
    }
}
