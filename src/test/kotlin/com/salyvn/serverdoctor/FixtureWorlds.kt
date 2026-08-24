package com.salyvn.serverdoctor

import java.io.DataOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPOutputStream

/**
 * Builds worlds on disk for the world tests.
 *
 * `level.dat` is written as real gzipped NBT rather than copied in as a binary blob, so the fixture
 * says what it contains and the reader under test is exercised on bytes it did not produce. The same
 * writer produces the truncated file, which is the case the audit exists for.
 */
object FixtureWorlds {

    private const val TAG_END = 0
    private const val TAG_BYTE = 1
    private const val TAG_INT = 3
    private const val TAG_STRING = 8
    private const val TAG_COMPOUND = 10

    /** A world folder with a valid level.dat and one region file. */
    fun world(
        root: Path,
        name: String,
        levelName: String = name,
        dataVersion: Int = 4189,
        versionName: String = "1.21.4",
        hardcore: Boolean = false,
        allowCommands: Boolean = false,
        regionFiles: Int = 1,
    ): Path {
        val world = root.resolve(name)
        levelDat(world.resolve("level.dat"), levelName, dataVersion, versionName, hardcore, allowCommands)
        repeat(regionFiles) { index -> regionFile(world.resolve("region").resolve("r.0.$index.mca"), 4096) }
        return world
    }

    fun levelDat(
        target: Path,
        levelName: String,
        dataVersion: Int,
        versionName: String,
        hardcore: Boolean = false,
        allowCommands: Boolean = false,
    ): Path {
        Files.createDirectories(target.parent)
        DataOutputStream(GZIPOutputStream(Files.newOutputStream(target))).use { out ->
            out.writeByte(TAG_COMPOUND)
            out.writeUTF("")

            out.writeByte(TAG_COMPOUND)
            out.writeUTF("Data")

            out.writeByte(TAG_INT)
            out.writeUTF("DataVersion")
            out.writeInt(dataVersion)

            out.writeByte(TAG_STRING)
            out.writeUTF("LevelName")
            out.writeUTF(levelName)

            out.writeByte(TAG_BYTE)
            out.writeUTF("hardcore")
            out.writeByte(if (hardcore) 1 else 0)

            out.writeByte(TAG_BYTE)
            out.writeUTF("allowCommands")
            out.writeByte(if (allowCommands) 1 else 0)

            out.writeByte(TAG_COMPOUND)
            out.writeUTF("Version")
            out.writeByte(TAG_STRING)
            out.writeUTF("Name")
            out.writeUTF(versionName)
            out.writeByte(TAG_INT)
            out.writeUTF("Id")
            out.writeInt(dataVersion)
            out.writeByte(TAG_END)

            out.writeByte(TAG_END)
            out.writeByte(TAG_END)
        }
        return target
    }

    /** A level.dat that stops in the middle of a tag, as a crash during save leaves it. */
    fun truncatedLevelDat(target: Path): Path {
        Files.createDirectories(target.parent)
        DataOutputStream(Files.newOutputStream(target)).use { out ->
            out.writeByte(TAG_COMPOUND)
            out.writeUTF("")
            out.writeByte(TAG_INT)
            out.writeUTF("DataVersion")
            // The four bytes of the value never arrive.
        }
        return target
    }

    fun regionFile(target: Path, bytes: Int): Path {
        Files.createDirectories(target.parent)
        Files.write(target, ByteArray(bytes))
        return target
    }

    fun playerData(world: Path, count: Int) {
        val directory = Files.createDirectories(world.resolve("playerdata"))
        repeat(count) { index ->
            Files.write(directory.resolve("0000000$index-0000-0000-0000-000000000000.dat"), ByteArray(64))
        }
    }

    fun datapack(world: Path, name: String, withMetadata: Boolean) {
        val pack = Files.createDirectories(world.resolve("datapacks").resolve(name))
        if (withMetadata) {
            Files.writeString(pack.resolve("pack.mcmeta"), """{"pack":{"pack_format":48,"description":"$name"}}""")
        } else {
            Files.createDirectories(pack.resolve("data").resolve("example").resolve("function"))
        }
    }
}
