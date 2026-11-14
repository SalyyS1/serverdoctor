package com.salyvn.serverdoctor.world

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/**
 * The header of a `.mca` region file, and what is wrong with it.
 *
 * A region file starts with two 4 KiB sectors: 1024 four-byte locations, then 1024 timestamps. Each
 * location packs the chunk's sector offset in the top three bytes and its length in sectors in the
 * bottom one, so the header alone says where every chunk in those 512 by 512 blocks is meant to be.
 * Only that header is read here - never a chunk - which is enough to tell a file that lost its tail
 * from a file that is merely large.
 *
 * The one case that must not be reported is Spigot's oversized chunk: a length of 255 sectors means the
 * real length is written in the chunk's own four-byte prefix, so the header's number is a marker rather
 * than a size and cannot be bounds-checked against the file.
 */
class RegionFileHeader(
    val path: Path,
    val sizeBytes: Long,
    /** Locations that name a chunk, whether or not the chunk is where they say. */
    val chunkCount: Int,
    /** One line per malformed location, worst first, capped. */
    val problems: List<String>,
    val problemCount: Int,
    /** The file is not empty and is smaller than the two header sectors. */
    val headerIncomplete: Boolean,
    val error: String? = null,
) {

    val ok: Boolean get() = error == null

    companion object {

        const val SECTOR_BYTES = 4096
        const val HEADER_SECTORS = 2
        const val LOCATIONS = 32 * 32

        /** Sectors are unsigned bytes, and 255 is Spigot's marker for a chunk stored oversized. */
        private const val OVERSIZED_MARKER = 255
        private const val MAX_PROBLEMS_KEPT = 6

        fun read(file: Path): RegionFileHeader {
            val size = runCatching { Files.size(file) }.getOrElse {
                return failure(file, 0L, it)
            }

            if (size < (SECTOR_BYTES * HEADER_SECTORS).toLong()) {
                return RegionFileHeader(
                    path = file,
                    sizeBytes = size,
                    chunkCount = 0,
                    problems = emptyList(),
                    problemCount = 0,
                    headerIncomplete = size > 0,
                )
            }

            val locations = ByteBuffer.allocate(SECTOR_BYTES)
            try {
                FileChannel.open(file, StandardOpenOption.READ).use { channel ->
                    var read = 0
                    while (read < SECTOR_BYTES) {
                        val count = channel.read(locations, read.toLong())
                        if (count <= 0) break
                        read += count
                    }
                    if (read < SECTOR_BYTES) {
                        return RegionFileHeader(file, size, 0, emptyList(), 0, headerIncomplete = true)
                    }
                }
            } catch (cause: IOException) {
                return failure(file, size, cause)
            }

            locations.rewind()
            val totalSectors = size / SECTOR_BYTES
            var chunks = 0
            var problemCount = 0
            val problems = mutableListOf<String>()

            for (index in 0 until LOCATIONS) {
                val packed = locations.getInt()
                if (packed == 0) continue
                chunks++

                val sector = packed ushr 8
                val sectors = packed and 0xFF
                val complaint = when {
                    sector < HEADER_SECTORS ->
                        "chunk $index is at sector $sector, which is inside the header"

                    sectors == 0 ->
                        "chunk $index is at sector $sector and claims no sectors"

                    // An oversized chunk's real length is in its own prefix, so only its start can be
                    // checked. Treating 255 sectors as a size is how a healthy file gets accused.
                    sectors == OVERSIZED_MARKER ->
                        if (sector.toLong() >= totalSectors) {
                            "chunk $index is stored oversized at sector $sector, past the end of the file"
                        } else {
                            null
                        }

                    sector.toLong() + sectors > totalSectors ->
                        "chunk $index needs sectors $sector to ${sector + sectors - 1} and the file has " +
                            "$totalSectors"

                    else -> null
                }

                if (complaint != null) {
                    problemCount++
                    if (problems.size < MAX_PROBLEMS_KEPT) problems += complaint
                }
            }

            return RegionFileHeader(file, size, chunks, problems, problemCount, headerIncomplete = false)
        }

        private fun failure(file: Path, size: Long, cause: Throwable) = RegionFileHeader(
            path = file,
            sizeBytes = size,
            chunkCount = 0,
            problems = emptyList(),
            problemCount = 0,
            headerIncomplete = false,
            error = cause.message ?: cause.javaClass.simpleName,
        )
    }
}
