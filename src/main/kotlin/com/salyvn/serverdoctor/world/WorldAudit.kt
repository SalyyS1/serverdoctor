package com.salyvn.serverdoctor.world

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale

/**
 * Audits the worlds under a server directory.
 *
 * The cross-world check is the one worth having: a server whose worlds were written by different game
 * versions has one world that nobody has entered since the upgrade, and the conversion is still ahead
 * of it. Nothing else on the server says so.
 */
class WorldAudit {

    fun analyse(worlds: List<WorldFolder>, subject: String): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()

        facts["worlds"] = worlds.size.toString()
        if (worlds.isEmpty()) {
            return report(subject, sink, facts)
        }

        val versions = mutableMapOf<String, Pair<Int, String?>>()
        var totalRegions = 0
        var totalBytes = 0L
        var totalChunks = 0

        for (world in worlds) {
            val level = if (world.hasLevelDat) Nbt.read(world.levelDat) else null

            when {
                level == null && world.hasLevelDatOld -> sink.add(
                    rule = WorldRules.ONLY_BACKUP_LEVEL_DAT,
                    location = world.name,
                    detail = "level.dat_old is present and level.dat is not.",
                )

                level == null -> sink.add(
                    rule = WorldRules.LEVEL_DAT_MISSING,
                    location = world.name,
                    detail = "No level.dat, and the folder holds ${world.regionFiles().size} region files.",
                )

                !level.ok -> sink.add(
                    rule = WorldRules.LEVEL_DAT_UNREADABLE,
                    location = "${world.name}/level.dat",
                    detail = level.error ?: "unreadable",
                )
            }

            level?.takeIf { it.ok }?.let { document ->
                val dataVersion = document.int("Data.DataVersion")
                val versionName = document.string("Data.Version.Name")
                if (dataVersion != null) versions[world.name] = dataVersion to versionName

                if (document.boolean("Data.hardcore") == true) {
                    sink.add(WorldRules.HARDCORE, world.name, "level.dat has hardcore set.")
                }
                if (document.boolean("Data.allowCommands") == true) {
                    sink.add(
                        rule = WorldRules.CHEATS_ENABLED,
                        location = world.name,
                        detail = "level.dat has allowCommands set, which is how a single-player world " +
                            "with cheats is saved.",
                    )
                }

                val label = buildString {
                    append(document.string("Data.LevelName") ?: world.name)
                    versionName?.let { append(", saved by $it") }
                    dataVersion?.let { append(" (data version $it)") }
                }
                facts[world.name] = label
            }

            for (file in world.regionFiles()) {
                totalRegions++
                val size = runCatching { Files.size(file) }.getOrDefault(0L)
                totalBytes += size
                val where = "${world.name}/${file.parent.fileName}/${file.fileName}"

                if (size == 0L) {
                    sink.add(
                        rule = WorldRules.EMPTY_REGION_FILE,
                        location = where,
                        detail = "The file is zero bytes.",
                    )
                    continue
                }

                totalChunks += checkRegionHeader(file, where, sink)
            }

            for (pack in world.datapackFolders()) {
                if (!Files.isDirectory(pack)) continue
                if (!Files.isRegularFile(pack.resolve("pack.mcmeta"))) {
                    sink.add(
                        rule = WorldRules.DATAPACK_WITHOUT_METADATA,
                        location = "${world.name}/datapacks/${pack.fileName}",
                        detail = "No pack.mcmeta directly inside the folder, so the server ignores it.",
                        evidence = childNames(pack),
                    )
                }
            }

            if (world.hasSessionLock) facts["${world.name} session.lock"] = "present"
        }

        checkLayoutLeftovers(worlds, sink)
        checkVersionAgreement(versions, sink)

        facts["region files"] = totalRegions.toString()
        facts["region size"] = String.format(Locale.ROOT, "%.1f MiB", totalBytes.toDouble() / (1L shl 20))
        if (totalChunks > 0) facts["chunks stored"] = totalChunks.toString()
        val players = worlds.sumOf { it.playerDataCount() }
        if (players > 0) facts["player data"] = players.toString()

        return report(subject, sink, facts)
    }

    /**
     * Reads one region file's header and reports what it cannot be. Returns the number of chunks the
     * header names, which is a fact worth printing even when nothing is wrong with it.
     */
    private fun checkRegionHeader(file: Path, where: String, sink: FindingSink): Int {
        val header = RegionFileHeader.read(file)

        if (header.headerIncomplete) {
            sink.add(
                rule = WorldRules.REGION_HEADER_INCOMPLETE,
                location = where,
                detail = "The file is ${header.sizeBytes} bytes; the header alone is " +
                    "${RegionFileHeader.SECTOR_BYTES * RegionFileHeader.HEADER_SECTORS}.",
            )
            return 0
        }

        if (!header.ok) return 0

        if (header.problemCount > 0) {
            sink.add(
                rule = WorldRules.REGION_HEADER_POINTS_OUTSIDE,
                location = where,
                detail = "${header.problemCount} of ${header.chunkCount} locations in the header do not " +
                    "point at a sector this file has.",
                evidence = header.problems,
            )
        }

        return header.chunkCount
    }

    /**
     * Both layouts in one place means a migration left the other behind. Reported once for the world
     * that carries the vanilla dimensions, not once per sibling.
     */
    private fun checkLayoutLeftovers(worlds: List<WorldFolder>, sink: FindingSink) {
        val names = worlds.map { it.name }.toSet()
        for (world in worlds) {
            if (!world.hasVanillaDimensions) continue
            val siblings = listOf("${world.name}_nether", "${world.name}_the_end").filter { it in names }
            if (siblings.isEmpty()) continue
            sink.add(
                rule = WorldRules.BOTH_LEGACY_LAYOUTS,
                location = world.name,
                detail = "${world.name} holds DIM-1 or DIM1, and ${siblings.joinToString(" and ")} " +
                    "also exists.",
                evidence = siblings,
            )
        }
    }

    private fun checkVersionAgreement(
        versions: Map<String, Pair<Int, String?>>,
        sink: FindingSink,
    ) {
        if (versions.size < 2) return
        val distinct = versions.values.map { it.first }.distinct()
        if (distinct.size < 2) return
        val newest = versions.maxBy { it.value.first }
        val oldest = versions.minBy { it.value.first }
        sink.add(
            rule = WorldRules.VERSION_MISMATCH,
            location = oldest.key,
            detail = "${oldest.key} was last saved by ${oldest.value.second ?: "data version ${oldest.value.first}"} " +
                "while ${newest.key} is at ${newest.value.second ?: "data version ${newest.value.first}"}.",
            evidence = versions.entries.sortedBy { it.value.first }
                .map { "${it.key}: ${it.value.second ?: "?"} (${it.value.first})" },
        )
    }

    private fun childNames(directory: Path): List<String> =
        runCatching {
            Files.list(directory).use { stream -> stream.limit(4).map { it.fileName.toString() }.toList() }
        }.getOrDefault(emptyList())

    private fun report(subject: String, sink: FindingSink, facts: Map<String, String>) = ScanReport(
        tool = BuildInfo.NAME,
        toolVersion = BuildInfo.version,
        subject = subject,
        subjectKind = "worlds",
        findings = sink.findings(),
        facts = facts,
    )
}
