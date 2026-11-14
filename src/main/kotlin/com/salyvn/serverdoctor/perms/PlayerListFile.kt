package com.salyvn.serverdoctor.perms

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID

/** One line of a server's access lists: an operator, a whitelisted player, a ban. */
data class ListedEntry(
    val uuid: String?,
    val name: String?,
    val level: Int? = null,
    val bypassesPlayerLimit: Boolean? = null,
    val ip: String? = null,
    val expires: String? = null,
    val source: String? = null,
    val reason: String? = null,
) {
    /** How to name this entry to a human, preferring what they typed over what the server stored. */
    val label: String get() = name ?: ip ?: uuid ?: "an entry with no name"

    val hasUsableUuid: Boolean get() = uuid?.let { runCatching { UUID.fromString(it) }.isSuccess } == true
}

/**
 * One of the four JSON lists a server keeps beside its properties.
 *
 * These files are written by the server and read again on reload, so they are normally well formed;
 * every problem worth reporting in them comes from somebody editing them by hand while the server was
 * down. That is why the reader is deliberately tolerant - it collects what is there and lets the audit
 * decide what is wrong - and why an entry that is a bare string rather than an object is kept rather
 * than dropped.
 */
class PlayerListFile(
    val path: Path,
    val kind: Kind,
    val entries: List<ListedEntry>,
    val present: Boolean,
    val parseError: String? = null,
) {

    val ok: Boolean get() = parseError == null

    val name: String get() = path.fileName.toString()

    /** Entries that name the same player or address more than once, keyed by that name. */
    fun duplicates(): Map<String, List<ListedEntry>> = entries
        .groupBy { (it.name ?: it.ip ?: it.uuid ?: "").lowercase() }
        .filterKeys { it.isNotEmpty() }
        .filterValues { it.size > 1 }

    enum class Kind(val fileName: String, val singular: String) {
        OPS("ops.json", "operator"),
        WHITELIST("whitelist.json", "whitelisted player"),
        BANNED_PLAYERS("banned-players.json", "banned player"),
        BANNED_IPS("banned-ips.json", "banned address"),
    }

    companion object {

        private val JSON = Json { ignoreUnknownKeys = true; isLenient = false }

        fun read(root: Path, kind: Kind): PlayerListFile {
            val path = root.resolve(kind.fileName)
            if (!Files.isRegularFile(path)) {
                return PlayerListFile(path, kind, emptyList(), present = false)
            }

            val text = runCatching { Files.readString(path, StandardCharsets.UTF_8) }.getOrElse {
                return PlayerListFile(path, kind, emptyList(), present = true, parseError = it.message ?: "unreadable")
            }

            if (text.isBlank()) {
                return PlayerListFile(path, kind, emptyList(), present = true, parseError = "the file is empty")
            }

            val element = runCatching { JSON.parseToJsonElement(text) }.getOrElse {
                return PlayerListFile(
                    path = path,
                    kind = kind,
                    entries = emptyList(),
                    present = true,
                    parseError = it.message?.lineSequence()?.first() ?: "not valid JSON",
                )
            }

            if (element !is JsonArray) {
                return PlayerListFile(
                    path = path,
                    kind = kind,
                    entries = emptyList(),
                    present = true,
                    parseError = "the file holds a ${element::class.simpleName} where the server writes an array",
                )
            }

            val entries = element.map { item ->
                when (item) {
                    is JsonObject -> ListedEntry(
                        uuid = item.string("uuid"),
                        name = item.string("name"),
                        level = item.string("level")?.toIntOrNull(),
                        bypassesPlayerLimit = item.string("bypassesPlayerLimit")?.toBooleanStrictOrNull(),
                        ip = item.string("ip"),
                        expires = item.string("expires"),
                        source = item.string("source"),
                        reason = item.string("reason"),
                    )
                    // A bare string is what hand-editing an old ops.txt into place leaves behind.
                    is JsonPrimitive -> ListedEntry(uuid = null, name = item.contentOrNullSafe())
                    else -> ListedEntry(uuid = null, name = null)
                }
            }

            return PlayerListFile(path, kind, entries, present = true)
        }

        private fun JsonObject.string(key: String): String? =
            (this[key] as? JsonPrimitive)?.contentOrNullSafe()

        private fun JsonPrimitive.contentOrNullSafe(): String? =
            content.takeIf { it.isNotBlank() && it != "null" }
    }
}
