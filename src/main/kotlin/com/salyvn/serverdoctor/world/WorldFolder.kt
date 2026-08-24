package com.salyvn.serverdoctor.world

import java.nio.file.Files
import java.nio.file.Path

/**
 * One world on disk, and the files a diagnosis needs from it.
 *
 * Discovery is deliberately shape-based rather than name-based. A server's worlds are whatever
 * directories hold a `level.dat` or a `region/`, because operators rename worlds, mount them from
 * elsewhere, and keep old copies next to live ones; a list of expected names would miss exactly the
 * folder that is the problem.
 */
class WorldFolder(val root: Path) {

    val name: String get() = root.fileName.toString()

    val levelDat: Path = root.resolve("level.dat")
    val levelDatOld: Path = root.resolve("level.dat_old")
    val sessionLock: Path = root.resolve("session.lock")
    val datapacks: Path = root.resolve("datapacks")

    val hasLevelDat: Boolean get() = Files.isRegularFile(levelDat)
    val hasLevelDatOld: Boolean get() = Files.isRegularFile(levelDatOld)
    val hasSessionLock: Boolean get() = Files.isRegularFile(sessionLock)

    /** `region/` in both layouts, plus the vanilla dimension folders when they are inside this one. */
    fun regionDirectories(): List<Path> = buildList {
        add(root.resolve("region"))
        add(root.resolve("DIM-1").resolve("region"))
        add(root.resolve("DIM1").resolve("region"))
    }.filter { Files.isDirectory(it) }

    fun regionFiles(): List<Path> = regionDirectories().flatMap { directory ->
        Files.list(directory).use { stream ->
            stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".mca") }.toList()
        }
    }

    /** True when the vanilla layout keeps other dimensions inside this folder. */
    val hasVanillaDimensions: Boolean
        get() = Files.isDirectory(root.resolve("DIM-1")) || Files.isDirectory(root.resolve("DIM1"))

    fun playerDataCount(): Int {
        val directory = root.resolve("playerdata")
        if (!Files.isDirectory(directory)) return 0
        return Files.list(directory).use { stream ->
            stream.filter { it.fileName.toString().endsWith(".dat") }.count().toInt()
        }
    }

    fun datapackFolders(): List<Path> {
        if (!Files.isDirectory(datapacks)) return emptyList()
        return Files.list(datapacks).use { stream -> stream.sorted().toList() }
    }

    fun sizeOfRegions(): Long = regionFiles().sumOf { runCatching { Files.size(it) }.getOrDefault(0L) }

    companion object {

        /** Does this directory look like a world rather than like a folder that happens to be here? */
        fun isWorld(directory: Path): Boolean =
            Files.isRegularFile(directory.resolve("level.dat")) ||
                Files.isRegularFile(directory.resolve("level.dat_old")) ||
                Files.isDirectory(directory.resolve("region"))

        /**
         * Worlds under a server directory. The CraftBukkit layout keeps the nether and the end as
         * sibling folders, so they are found the same way and reported the same way; which of them the
         * server loads is a question for the config audit, not for this one.
         */
        fun discover(serverDirectory: Path): List<WorldFolder> {
            if (isWorld(serverDirectory)) return listOf(WorldFolder(serverDirectory))
            if (!Files.isDirectory(serverDirectory)) return emptyList()
            return Files.list(serverDirectory).use { stream ->
                stream.filter { Files.isDirectory(it) && isWorld(it) }.sorted().toList()
            }.map { WorldFolder(it) }
        }
    }
}
