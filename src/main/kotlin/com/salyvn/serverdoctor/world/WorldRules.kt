package com.salyvn.serverdoctor.world

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.Severity

/**
 * Rules about a world on disk.
 *
 * A world is the only thing on a Minecraft server that cannot be reinstalled, so the bar here is
 * different from the other audits: nothing guesses, and nothing that could be a normal state is
 * reported as damage. What is reported is either structurally impossible (region data with no
 * `level.dat`), self-inconsistent (two worlds of one server saved by different game versions), or a
 * setting whose consequence is irreversible for a player (hardcore).
 */
object WorldRules {

    private const val MIGRATION = "PaperMC/Paper paper-server/src/main/java/io/papermc/paper/world/migration/WorldFolderMigration.java:33-37,108"

    private const val REGION_HEADER = "PaperMC/Paper paper-server/patches/features/" +
        "0026-Attempt-to-recalculate-regionfile-header-if-it-is-co.patch:176,313 - the first two " +
        "4 KiB sectors are the header, and each of the 1024 locations is sector offset << 8 | length " +
        "in sectors"

    val LEVEL_DAT_MISSING = Rule(
        id = "W001",
        area = RuleArea.WORLD,
        severity = Severity.CRITICAL,
        title = "A world has chunk data but no level.dat",
        rationale = "level.dat holds the seed, the generator settings and the spawn. Without it the " +
            "server treats the folder as a new world and generates a different one around the chunks " +
            "that are already there.",
        provenance = "$MIGRATION - the level data is read from the Data compound of level.dat",
        fix = "Restore level.dat from a backup before starting the server. If only level.dat_old " +
            "survives, copy that to level.dat.",
    )

    val LEVEL_DAT_UNREADABLE = Rule(
        id = "W002",
        area = RuleArea.WORLD,
        severity = Severity.BLOCKER,
        title = "level.dat is not readable NBT",
        rationale = "The server reads this file before anything else in the world. A truncated one is " +
            "what a crash during save, or a copy taken while the server was running, leaves behind.",
        provenance = "Parsed here as NBT; the message is the reason the parse stopped",
        fix = "Replace it with level.dat_old or with a backup.",
    )

    val ONLY_BACKUP_LEVEL_DAT = Rule(
        id = "W003",
        area = RuleArea.WORLD,
        severity = Severity.WARNING,
        title = "Only level.dat_old is present",
        rationale = "The server writes the new file and keeps the previous one as level.dat_old. " +
            "Having only the old one means the last save did not finish.",
        provenance = "Read from this directory: level.dat absent, level.dat_old present",
        fix = "Copy level.dat_old to level.dat, then check the disk the world lives on.",
    )

    val VERSION_MISMATCH = Rule(
        id = "W004",
        area = RuleArea.WORLD,
        severity = Severity.WARNING,
        title = "Worlds on this server were saved by different game versions",
        rationale = "Each world records the version that last wrote it. When they disagree, one of them " +
            "was not loaded after the server was upgraded - usually a world that is configured but " +
            "never visited, and it will be upgraded the moment somebody enters it.",
        provenance = "level.dat Data.DataVersion and Data.Version.Name, compared between worlds",
        fix = "Load each world once after an upgrade, or take the backup now rather than after the " +
            "conversion.",
    )

    val EMPTY_REGION_FILE = Rule(
        id = "W005",
        area = RuleArea.WORLD,
        severity = Severity.CRITICAL,
        title = "A region file is empty",
        rationale = "A zero-length .mca file holds no chunks and no header. Whatever was in those 512 " +
            "by 512 blocks is gone, and reading it fails rather than returning empty terrain.",
        provenance = "Read from this directory: file size is 0",
        fix = "Restore the named file from a backup, or delete it and accept that those chunks " +
            "regenerate as new terrain.",
    )

    val DATAPACK_WITHOUT_METADATA = Rule(
        id = "W006",
        area = RuleArea.WORLD,
        severity = Severity.WARNING,
        title = "A datapack has no pack.mcmeta",
        rationale = "Without that file the pack is not a pack, so it is ignored. The usual cause is a " +
            "zip extracted one level too deep, which looks installed in a file listing.",
        provenance = "Read from this directory: the datapack folder has no pack.mcmeta",
        fix = "Move the folder that contains pack.mcmeta up one level, or re-extract the pack.",
    )

    val BOTH_LEGACY_LAYOUTS = Rule(
        id = "W007",
        area = RuleArea.WORLD,
        severity = Severity.INFO,
        title = "Both historic world layouts are present",
        rationale = "Paper migrates two older shapes: the CraftBukkit one, where the nether and the end " +
            "are sibling folders, and the vanilla one, where they are DIM-1 and DIM1 inside the world " +
            "folder. Finding both means a migration happened and the leftovers were never removed, so " +
            "one of the two sets is dead weight that still looks like a world.",
        provenance = MIGRATION,
        fix = "Confirm which folder the server actually loads, then archive the other rather than " +
            "deleting it outright.",
    )

    val HARDCORE = Rule(
        id = "W008",
        area = RuleArea.WORLD,
        severity = Severity.WARNING,
        title = "The world is hardcore",
        rationale = "On death a player is banned from the world rather than respawned. It is a " +
            "deliberate choice on some servers and a surprise inherited with a downloaded map on " +
            "others, and it cannot be undone for whoever dies first.",
        provenance = "level.dat Data.hardcore",
        fix = "If this was not intended, change it before players join.",
    )

    val CHEATS_ENABLED = Rule(
        id = "W009",
        area = RuleArea.WORLD,
        severity = Severity.INFO,
        title = "The world was saved with cheats allowed",
        rationale = "allowCommands is set on worlds created in single-player with cheats. It says where " +
            "this world came from, which is worth knowing when its permissions look odd.",
        provenance = "level.dat Data.allowCommands",
        fix = null,
    )

    val REGION_HEADER_INCOMPLETE = Rule(
        id = "W010",
        area = RuleArea.WORLD,
        severity = Severity.CRITICAL,
        title = "A region file is smaller than its own header",
        rationale = "The first 8 KiB of a region file is the table that says where each of its 1024 " +
            "chunks lives. A file shorter than that has data in it and no way to find any of it, which " +
            "is what a copy taken while the server was writing looks like.",
        provenance = REGION_HEADER,
        fix = "Restore the named file from a backup. A file this short has nothing recoverable in it.",
    )

    val REGION_HEADER_POINTS_OUTSIDE = Rule(
        id = "W011",
        area = RuleArea.WORLD,
        severity = Severity.CRITICAL,
        title = "A region file's chunk table points outside the file",
        rationale = "A location names a sector that is inside the header or past the end of the file, so " +
            "the chunk it describes cannot be read from where it says it is. Paper notices this on load, " +
            "warns, and rebuilds the header by scanning the file - which is a recovery, and recoveries " +
            "are better done from a copy.",
        provenance = "$REGION_HEADER; the sector-overlaps-header case is the warning in paper-server/" +
            "patches/sources/net/minecraft/world/level/chunk/storage/RegionFile.java.patch:15-17",
        fix = "Copy the world before starting the server again, then let Paper rebuild the header and " +
            "read what it says it lost.",
    )

    val all: List<Rule> = listOf(
        LEVEL_DAT_MISSING,
        LEVEL_DAT_UNREADABLE,
        ONLY_BACKUP_LEVEL_DAT,
        VERSION_MISMATCH,
        EMPTY_REGION_FILE,
        DATAPACK_WITHOUT_METADATA,
        BOTH_LEGACY_LAYOUTS,
        HARDCORE,
        CHEATS_ENABLED,
        REGION_HEADER_INCOMPLETE,
        REGION_HEADER_POINTS_OUTSIDE,
    )
}
