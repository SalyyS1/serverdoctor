package com.salyvn.serverdoctor.perms

import com.salyvn.serverdoctor.core.BuildInfo
import com.salyvn.serverdoctor.core.FindingSink
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.input.PropertiesSource
import com.salyvn.serverdoctor.input.YamlSource
import java.nio.file.Files
import java.nio.file.Path

/**
 * Audits the access lists and the permissions file of one server directory.
 *
 * The lists are read together with `server.properties` because most of what matters is a relation
 * between them rather than a value in one: operators only mean something once you know whether the
 * server checks identity, and an empty whitelist only matters when the whitelist is on.
 */
class PermsAudit {

    fun analyse(root: Path, subject: String): ScanReport {
        val sink = FindingSink()
        val facts = linkedMapOf<String, String>()

        val properties = root.resolve("server.properties")
            .takeIf { Files.isRegularFile(it) }
            ?.let { PropertiesSource.read(it) }
        val bukkit = yaml(root.resolve("bukkit.yml"))
        val paperGlobal = yaml(root.resolve("config/paper-global.yml"))
        val spigot = yaml(root.resolve("spigot.yml"))

        val ops = PlayerListFile.read(root, PlayerListFile.Kind.OPS)
        val whitelist = PlayerListFile.read(root, PlayerListFile.Kind.WHITELIST)
        val bannedPlayers = PlayerListFile.read(root, PlayerListFile.Kind.BANNED_PLAYERS)
        val bannedIps = PlayerListFile.read(root, PlayerListFile.Kind.BANNED_IPS)
        val lists = listOf(ops, whitelist, bannedPlayers, bannedIps)

        val onlineMode = properties?.bool("online-mode")
        val whitelistOn = properties?.bool("white-list")
        val forwarding = listOfNotNull(
            "velocity".takeIf { paperGlobal?.bool("proxies.velocity.enabled") == true },
            "bungeecord".takeIf { spigot?.bool("settings.bungeecord") == true },
        )

        for (list in lists) if (list.present) facts[list.kind.fileName] = describe(list)
        onlineMode?.let { facts["online-mode"] = it.toString() }
        whitelistOn?.let { facts["white-list"] = it.toString() }
        properties?.bool("enforce-whitelist")?.let { facts["enforce-whitelist"] = it.toString() }
        if (forwarding.isNotEmpty()) facts["forwarding"] = forwarding.joinToString(" and ")

        checkLists(lists, sink)
        checkIdentity(ops, onlineMode, forwarding, properties, sink)
        checkWhitelist(whitelistOn, whitelist, sink)
        checkOperatorBans(ops, bannedPlayers, sink)
        checkPermissionsFile(root, bukkit, sink, facts)

        return ScanReport(
            tool = BuildInfo.NAME,
            toolVersion = BuildInfo.version,
            subject = subject,
            subjectKind = "perms",
            findings = sink.findings(),
            facts = facts,
        )
    }

    private fun yaml(path: Path): YamlSource? =
        path.takeIf { Files.isRegularFile(it) }?.let { YamlSource.read(it) }

    private fun describe(list: PlayerListFile): String = when {
        !list.ok -> "unreadable"
        list.entries.isEmpty() -> "empty"
        else -> "${list.entries.size} ${list.kind.singular}${if (list.entries.size == 1) "" else "s"}"
    }

    private fun checkLists(lists: List<PlayerListFile>, sink: FindingSink) {
        for (list in lists) {
            if (!list.present) continue

            if (!list.ok) {
                sink.add(PermsRules.LIST_NOT_JSON, list.name, list.parseError ?: "not valid JSON")
                continue
            }

            // banned-ips.json is keyed on the address, so it has no id to check.
            if (list.kind != PlayerListFile.Kind.BANNED_IPS) {
                val nameless = list.entries.filter { !it.hasUsableUuid }
                if (nameless.isNotEmpty()) {
                    sink.add(
                        rule = PermsRules.ENTRY_WITHOUT_UUID,
                        location = list.name,
                        detail = "${nameless.size} of ${list.entries.size} entries have no usable id: " +
                            nameless.take(NAMES_IN_DETAIL).joinToString(", ") { it.label } + ".",
                        evidence = nameless.take(MAX_EVIDENCE).map { entry ->
                            "${entry.label}: uuid=${entry.uuid ?: "absent"}"
                        },
                    )
                }
            }

            for ((who, group) in list.duplicates()) {
                sink.add(
                    rule = PermsRules.DUPLICATE_ENTRY,
                    location = list.name,
                    detail = "$who appears ${group.size} times.",
                    evidence = group.map { "${it.label}: uuid=${it.uuid ?: "absent"}" },
                )
            }
        }
    }

    private fun checkIdentity(
        ops: PlayerListFile,
        onlineMode: Boolean?,
        forwarding: List<String>,
        properties: PropertiesSource?,
        sink: FindingSink,
    ) {
        if (onlineMode != false || forwarding.isNotEmpty() || ops.entries.isEmpty()) return
        val line = properties?.get("online-mode")?.line
        sink.add(
            rule = PermsRules.OPS_WITHOUT_IDENTITY,
            location = listOfNotNull(properties?.path?.fileName?.toString(), line?.toString()).joinToString(":"),
            detail = "online-mode=false with no proxy forwarding configured, and ops.json names " +
                "${ops.entries.size} ${ops.kind.singular}${if (ops.entries.size == 1) "" else "s"}.",
            evidence = ops.entries.take(MAX_EVIDENCE).map { entry ->
                listOfNotNull(entry.label, entry.level?.let { "level $it" }).joinToString(", ")
            },
        )
    }

    private fun checkWhitelist(whitelistOn: Boolean?, whitelist: PlayerListFile, sink: FindingSink) {
        if (whitelistOn != true) return
        if (!whitelist.ok) return
        when {
            !whitelist.present -> sink.add(
                rule = PermsRules.WHITELIST_ON_BUT_EMPTY,
                location = "server.properties",
                detail = "white-list=true and there is no whitelist.json in this directory.",
            )

            whitelist.entries.isEmpty() -> sink.add(
                rule = PermsRules.WHITELIST_ON_BUT_EMPTY,
                location = whitelist.name,
                detail = "white-list=true and whitelist.json holds no entries.",
            )
        }
    }

    private fun checkOperatorBans(ops: PlayerListFile, bans: PlayerListFile, sink: FindingSink) {
        if (ops.entries.isEmpty() || bans.entries.isEmpty()) return
        val bannedNames = bans.entries.mapNotNull { it.name?.lowercase() }.toSet()
        val bannedIds = bans.entries.mapNotNull { it.uuid?.lowercase() }.toSet()

        for (op in ops.entries) {
            val byName = op.name?.lowercase()?.let { it in bannedNames } == true
            val byId = op.uuid?.lowercase()?.let { it in bannedIds } == true
            if (!byName && !byId) continue
            val ban = bans.entries.firstOrNull { candidate ->
                (op.name != null && candidate.name?.equals(op.name, ignoreCase = true) == true) ||
                    (op.uuid != null && candidate.uuid?.equals(op.uuid, ignoreCase = true) == true)
            }
            sink.add(
                rule = PermsRules.OPERATOR_IS_BANNED,
                location = ops.name,
                detail = "${op.label} is an operator and is on the ban list" +
                    (ban?.reason?.let { ", banned for \"$it\"" } ?: "") + ".",
                evidence = listOfNotNull(
                    "ops.json: ${op.label}${op.level?.let { " (level $it)" } ?: ""}",
                    ban?.let { "banned-players.json: ${it.label}${it.source?.let { by -> " by $by" } ?: ""}" },
                ),
            )
        }

        val bypassing = ops.entries.filter { it.bypassesPlayerLimit == true }
        if (bypassing.isNotEmpty()) {
            sink.add(
                rule = PermsRules.BYPASSES_PLAYER_LIMIT,
                location = ops.name,
                detail = "${bypassing.size} of ${ops.entries.size} operators can join a full server: " +
                    bypassing.take(NAMES_IN_DETAIL).joinToString(", ") { it.label } + ".",
                evidence = bypassing.take(MAX_EVIDENCE).map { it.label },
            )
        }
    }

    /**
     * The permissions file is the one part of this audit whose location is configurable, so the name is
     * read from bukkit.yml rather than assumed. A missing default file is normal and says nothing.
     */
    private fun checkPermissionsFile(
        root: Path,
        bukkit: YamlSource?,
        sink: FindingSink,
        facts: MutableMap<String, String>,
    ) {
        val configured = bukkit?.text("settings.permissions-file")?.takeIf { it.isNotBlank() } ?: DEFAULT_FILE
        val file = root.resolve(configured)

        if (!Files.isRegularFile(file)) {
            if (configured != DEFAULT_FILE) {
                sink.add(
                    rule = PermsRules.PERMISSIONS_FILE_MISSING,
                    location = "bukkit.yml:${bukkit?.get("settings.permissions-file")?.line ?: 0}",
                    detail = "settings.permissions-file is \"$configured\" and no such file is here.",
                )
            }
            return
        }

        val document = YamlSource.read(file)
        if (document.parseError != null) {
            sink.add(
                rule = PermsRules.PERMISSIONS_NOT_YAML,
                location = configured,
                detail = document.parseError,
            )
            return
        }

        val nodes = document.entries.map { it.path.substringBefore('.') }.distinct()
        facts["permissions file"] = configured
        facts["permission nodes"] = nodes.size.toString()
    }

    private companion object {
        const val DEFAULT_FILE = "permissions.yml"
        const val MAX_EVIDENCE = 12
        const val NAMES_IN_DETAIL = 4
    }
}
