package com.salyvn.serverdoctor.perms

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.Severity

/**
 * Rules about who a server lets in and what it lets them do.
 *
 * The four JSON lists and `permissions.yml` are the whole access surface of a vanilla-derived server,
 * and they fail quietly: a hand-edited list keeps working for everyone already on it, and a broken
 * `permissions.yml` is skipped with one line at startup that nobody reads twice. Nothing here judges a
 * server for having operators or for being open - only for states that do not mean what they look like.
 */
object PermsRules {

    private const val OFFLINE_ID = "PaperMC/Paper paper-server/src/main/java/org/bukkit/craftbukkit/" +
        "CraftServer.java:1941-1948 - an account's real id is only looked up when online mode is on; " +
        "otherwise the id is created from the name that was typed"

    private const val PERMISSIONS_FILE = "PaperMC/Paper paper-server/src/main/java/org/bukkit/" +
        "craftbukkit/CraftServer.java:1114-1148 - the path comes from bukkit.yml settings.permissions-" +
        "file, a file that is not there returns silently, and YAML that does not parse is logged once " +
        "and the whole file skipped"

    val OPS_WITHOUT_IDENTITY = Rule(
        id = "S001",
        area = RuleArea.PERMS,
        severity = Severity.CRITICAL,
        title = "The server has operators but does not verify who anybody is",
        rationale = "With online mode off and nothing forwarding a verified identity, a player is " +
            "whoever they say they are, and the operator list is keyed on exactly that. Anyone who " +
            "knows an operator's name can connect as them.",
        provenance = OFFLINE_ID,
        fix = "Turn online-mode on, or put the server behind a proxy that forwards identity and block " +
            "direct connections to this port at the firewall.",
    )

    val LIST_NOT_JSON = Rule(
        id = "S002",
        area = RuleArea.PERMS,
        severity = Severity.CRITICAL,
        title = "An access list is not readable JSON",
        rationale = "The server writes these files itself, so a syntax error means the file was edited " +
            "by hand. Whatever the server does with it, it is not the list somebody meant to write.",
        provenance = "Read from this directory; the message is the reason the parse stopped",
        fix = "Restore the file from a backup, or fix the JSON and reload before trusting the list.",
    )

    val ENTRY_WITHOUT_UUID = Rule(
        id = "S003",
        area = RuleArea.PERMS,
        severity = Severity.WARNING,
        title = "An access list entry has no usable id",
        rationale = "The server matches these entries by id, and writes both the id and the name so the " +
            "file stays readable. An entry with a name and no id is one somebody typed.",
        provenance = "Read from this file: the uuid field is missing, empty or not a UUID",
        fix = "Re-add the player with the server's own command so the id is written, then remove the " +
            "hand-written entry.",
    )

    val DUPLICATE_ENTRY = Rule(
        id = "S004",
        area = RuleArea.PERMS,
        severity = Severity.WARNING,
        title = "An access list names one player twice",
        rationale = "The server does not write a name twice. Two entries for one player usually means an " +
            "id changed under the name - a rename, or a switch between online and offline ids - and one " +
            "of the two is now dead weight that looks live.",
        provenance = "Read from this file: two entries share a name or an address",
        fix = "Keep the entry whose id matches how players connect today and remove the other.",
    )

    val OPERATOR_IS_BANNED = Rule(
        id = "S005",
        area = RuleArea.PERMS,
        severity = Severity.WARNING,
        title = "An operator is also on the ban list",
        rationale = "The two lists contradict each other, so which one wins is not something to find out " +
            "during an incident. It is what a de-op that never finished looks like.",
        provenance = "Read from this directory: one name is in both ops.json and banned-players.json",
        fix = "Decide which it is: pardon them, or take the operator entry out.",
    )

    val PERMISSIONS_NOT_YAML = Rule(
        id = "S006",
        area = RuleArea.PERMS,
        severity = Severity.CRITICAL,
        title = "The permissions file is not valid YAML",
        rationale = "The server logs one warning and then ignores the entire file, so every permission " +
            "defined in it is simply absent. Nothing else says so, and the plugins that rely on those " +
            "nodes fail one command at a time.",
        provenance = PERMISSIONS_FILE,
        fix = "Fix the YAML - the error names the line - and reload. Until then no node in this file " +
            "exists.",
    )

    val PERMISSIONS_FILE_MISSING = Rule(
        id = "S007",
        area = RuleArea.PERMS,
        severity = Severity.WARNING,
        title = "The configured permissions file is not there",
        rationale = "bukkit.yml points the server at a permissions file by name. When that name does not " +
            "exist the server returns without a word, which looks identical to having no permissions to " +
            "load.",
        provenance = PERMISSIONS_FILE,
        fix = "Correct settings.permissions-file in bukkit.yml, or put the file where it points.",
    )

    val WHITELIST_ON_BUT_EMPTY = Rule(
        id = "S008",
        area = RuleArea.PERMS,
        severity = Severity.WARNING,
        title = "The whitelist is on and holds nobody",
        rationale = "A whitelist with no entries admits no named player. It is the state a server is in " +
            "after the list is lost, and it looks the same from the console as a working one.",
        provenance = "Read from this directory: server.properties white-list is true and whitelist.json " +
            "has no entries",
        fix = "Restore whitelist.json, or turn white-list off until the list is back.",
    )

    val BYPASSES_PLAYER_LIMIT = Rule(
        id = "S009",
        area = RuleArea.PERMS,
        severity = Severity.INFO,
        title = "An operator is recorded as bypassing the player limit",
        rationale = "The flag is stored per operator and is easy to forget, because it only shows itself " +
            "on a full server. Worth knowing before wondering how somebody got in.",
        provenance = "Read from ops.json: bypassesPlayerLimit is true",
        fix = null,
    )

    val all: List<Rule> = listOf(
        OPS_WITHOUT_IDENTITY,
        LIST_NOT_JSON,
        ENTRY_WITHOUT_UUID,
        DUPLICATE_ENTRY,
        OPERATOR_IS_BANNED,
        PERMISSIONS_NOT_YAML,
        PERMISSIONS_FILE_MISSING,
        WHITELIST_ON_BUT_EMPTY,
        BYPASSES_PLAYER_LIMIT,
    )
}
