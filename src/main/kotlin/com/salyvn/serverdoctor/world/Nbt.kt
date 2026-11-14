package com.salyvn.serverdoctor.world

import java.io.DataInputStream
import java.io.EOFException
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream

/**
 * Just enough NBT to read a `level.dat`.
 *
 * Writing this rather than taking a dependency keeps the jar small and the trust boundary obvious: the
 * reader only ever produces maps, lists and primitives, so a world file cannot cause anything to be
 * constructed or executed. Both caps below exist because the file being read may be corrupt - that is
 * the case this audit is for - and a corrupt length prefix is how a parser is talked into allocating
 * everything it can.
 */
object Nbt {

    private const val MAX_BYTES = 8L * 1024 * 1024
    private const val MAX_DEPTH = 64

    /** Tag ids, in the order the format defines them. */
    private const val END = 0
    private const val BYTE = 1
    private const val SHORT = 2
    private const val INT = 3
    private const val LONG = 4
    private const val FLOAT = 5
    private const val DOUBLE = 6
    private const val BYTE_ARRAY = 7
    private const val STRING = 8
    private const val LIST = 9
    private const val COMPOUND = 10
    private const val INT_ARRAY = 11
    private const val LONG_ARRAY = 12

    /** A parsed file: the root compound, or the reason it could not be read. */
    class Document(val root: Map<String, Any>?, val error: String? = null) {

        val ok: Boolean get() = root != null

        /** `Data.Version.Name`, resolved through nested compounds. Null when any step is absent. */
        @Suppress("UNCHECKED_CAST")
        fun value(path: String): Any? {
            var current: Any? = root ?: return null
            for (segment in path.split('.')) {
                val map = current as? Map<String, Any> ?: return null
                current = map[segment] ?: return null
            }
            return current
        }

        fun string(path: String): String? = value(path) as? String

        fun int(path: String): Int? = when (val raw = value(path)) {
            is Int -> raw
            is Byte -> raw.toInt()
            is Short -> raw.toInt()
            is Long -> raw.toInt()
            else -> null
        }

        fun long(path: String): Long? = when (val raw = value(path)) {
            is Long -> raw
            is Int -> raw.toLong()
            else -> null
        }

        /** NBT has no boolean: the format stores a byte, and 0 is false. */
        fun boolean(path: String): Boolean? = when (val raw = value(path)) {
            is Byte -> raw != 0.toByte()
            is Int -> raw != 0
            else -> null
        }
    }

    fun read(file: Path): Document {
        val size = runCatching { Files.size(file) }.getOrDefault(0L)
        if (size > MAX_BYTES) return Document(null, "file is ${size / 1024} KiB, past the ${MAX_BYTES / 1024} KiB cap")

        return try {
            Files.newInputStream(file).use { raw ->
                val head = raw.readNBytes(2)
                val rest = Files.newInputStream(file)
                // level.dat is gzipped in practice, but an uncompressed one still has to be read:
                // a hand-edited or partially written file is exactly what this audit looks at.
                val gzipped = head.size == 2 && head[0] == 0x1f.toByte() && head[1] == 0x8b.toByte()
                val stream = if (gzipped) GZIPInputStream(rest) else rest
                DataInputStream(stream.buffered()).use { input ->
                    val type = input.readUnsignedByte()
                    if (type != COMPOUND) return Document(null, "root tag is type $type, not a compound")
                    input.readUTF() // the root compound's name, empty in every level.dat
                    @Suppress("UNCHECKED_CAST")
                    val root = readPayload(input, COMPOUND, 0) as Map<String, Any>
                    Document(root)
                }
            }
        } catch (failure: EOFException) {
            Document(null, "the file ends mid-tag, so it was truncated while being written")
        } catch (failure: Exception) {
            Document(null, failure.message ?: failure.javaClass.simpleName)
        }
    }

    private fun readPayload(input: DataInputStream, type: Int, depth: Int): Any {
        if (depth > MAX_DEPTH) throw IllegalStateException("nesting deeper than $MAX_DEPTH tags")
        return when (type) {
            BYTE -> input.readByte()
            SHORT -> input.readShort()
            INT -> input.readInt()
            LONG -> input.readLong()
            FLOAT -> input.readFloat()
            DOUBLE -> input.readDouble()
            STRING -> input.readUTF()

            BYTE_ARRAY -> ByteArray(readLength(input)).also { input.readFully(it) }

            INT_ARRAY -> {
                val length = readLength(input)
                IntArray(length) { input.readInt() }
            }

            LONG_ARRAY -> {
                val length = readLength(input)
                LongArray(length) { input.readLong() }
            }

            LIST -> {
                val elementType = input.readUnsignedByte()
                val length = readLength(input)
                if (elementType == END) return emptyList<Any>()
                List(length) { readPayload(input, elementType, depth + 1) }
            }

            COMPOUND -> {
                val entries = LinkedHashMap<String, Any>()
                while (true) {
                    val entryType = input.readUnsignedByte()
                    if (entryType == END) break
                    val name = input.readUTF()
                    entries[name] = readPayload(input, entryType, depth + 1)
                }
                entries
            }

            else -> throw IllegalStateException("unknown tag type $type")
        }
    }

    /** A negative or absurd length means the file is damaged, not that a huge array follows. */
    private fun readLength(input: DataInputStream): Int {
        val length = input.readInt()
        if (length < 0 || length > MAX_BYTES) throw IllegalStateException("array length $length is not credible")
        return length
    }
}
