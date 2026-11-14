package com.salyvn.serverdoctor.config

import com.salyvn.serverdoctor.core.Rule
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.Severity

/**
 * Configuration rules.
 *
 * These are the ones where a default was changed and the consequence is not visible until something
 * has already happened: a spoofed login, an exploit, a hang nobody caught. Every default quoted here
 * was read from the field that declares it in Paper's own configuration classes, because a tuning
 * guide that has drifted a version behind is how a "fix" becomes a regression.
 *
 * Deliberately absent: taste. There is no rule that says a view distance of 10 is wrong, because that
 * depends on hardware nobody can see from a config file.
 */
object ConfigRules {

    private const val GLOBAL = "PaperMC/Paper paper-server/src/main/java/io/papermc/paper/configuration/GlobalConfiguration.java"
    private const val WORLD = "PaperMC/Paper paper-server/src/main/java/io/papermc/paper/configuration/WorldConfiguration.java"
    private const val SPIGOT = "PaperMC/Paper paper-server/src/main/java/org/spigotmc/SpigotConfig.java"
    private const val WATCHDOG = "PaperMC/Paper paper-server/src/main/java/org/spigotmc/WatchdogThread.java:41"

    val OFFLINE_MODE_NO_PROXY = Rule(
        id = "C001",
        area = RuleArea.CONFIG,
        severity = Severity.CRITICAL,
        title = "Offline mode with no proxy in front",
        rationale = "With online-mode=false the server accepts whatever username a client claims. " +
            "That is intended only when a proxy has already authenticated the player and forwards " +
            "the result, so the combination of offline mode and no configured forwarding means " +
            "anyone can log in as anyone, operators included.",
        provenance = "$GLOBAL:112-121 (proxies.bungee-cord / proxies.velocity), $SPIGOT:195 (settings.bungeecord)",
        fix = "Set online-mode=true, or configure the proxy forwarding you meant to use and firewall " +
            "the port so only the proxy can reach it.",
    )

    val VELOCITY_SECRET_EMPTY = Rule(
        id = "C002",
        area = RuleArea.CONFIG,
        severity = Severity.BLOCKER,
        title = "Velocity forwarding is on with an empty secret",
        rationale = "The secret is what proves a connection came from the proxy. Empty means the " +
            "handshake cannot succeed, so every join fails with a forwarding error.",
        provenance = "$GLOBAL:119-121 (proxies.velocity.enabled, .secret defaults to empty)",
        fix = "Copy forwarding.secret from the proxy into proxies.velocity.secret.",
    )

    val TWO_FORWARDING_SCHEMES = Rule(
        id = "C003",
        area = RuleArea.CONFIG,
        severity = Severity.CRITICAL,
        title = "Two proxy forwarding schemes are enabled at once",
        rationale = "BungeeCord forwarding and Velocity modern forwarding read the same handshake " +
            "differently. With both on, which one applies is not a decision the operator made.",
        provenance = "$GLOBAL:112-121, $SPIGOT:195",
        fix = "Enable exactly the one your proxy uses.",
    )

    val UNSUPPORTED_SETTING_ENABLED = Rule(
        id = "C004",
        area = RuleArea.CONFIG,
        severity = Severity.CRITICAL,
        title = "An unsupported-settings toggle is enabled",
        rationale = "This section exists to let a server keep a duplication or exploit behaviour on " +
            "purpose. Every switch in it ships off, and turning one on is a decision to accept item " +
            "duplication, block-break exploits or unvalidated usernames.",
        provenance = "$GLOBAL:171-186 (all default false except perform-username-validation)",
        fix = "Set it back to its default unless you can name why this server needs the old behaviour.",
    )

    val CONSOLE_ALL_PERMISSIONS = Rule(
        id = "C005",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "The console holds every permission",
        rationale = "With has-all-permissions on, anything that can write to the console - a badly " +
            "scoped RCON, a panel integration, a plugin that pipes input - acts with full authority " +
            "rather than with the permissions it was granted.",
        provenance = "$GLOBAL:149 (console.has-all-permissions, default false)",
        fix = "Leave it off and grant the console the permissions it actually needs.",
    )

    val RCON_WITHOUT_PASSWORD = Rule(
        id = "C006",
        area = RuleArea.CONFIG,
        severity = Severity.CRITICAL,
        title = "RCON is enabled with no password",
        rationale = "RCON runs arbitrary console commands over TCP. With an empty password the only " +
            "thing standing between the internet and the console is the firewall.",
        provenance = "server.properties keys enable-rcon / rcon.password, read from this file",
        fix = "Set a long random rcon.password, bind RCON to localhost, or turn it off.",
    )

    val SIMULATION_OVER_VIEW = Rule(
        id = "C007",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "Simulation distance is larger than view distance",
        rationale = "The server ticks entities and blocks further out than any player can see. The " +
            "cost is real and none of it reaches a screen.",
        provenance = "server.properties keys view-distance / simulation-distance, compared as written",
        fix = "Bring simulation-distance down to view-distance or below.",
    )

    val WATCHDOG_TIMEOUT_HIGH = Rule(
        id = "C008",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "The watchdog timeout is long enough to hide a hang",
        rationale = "timeout-time is how long the main thread may be stuck before the watchdog dumps " +
            "threads and stops the server. Raising it does not fix the hang; it converts a crash " +
            "with a diagnosis into minutes of unexplained freeze. A non-positive value does not " +
            "disable the watchdog either: Paper falls back to 300 seconds.",
        provenance = "$SPIGOT:177 (default 60), $WATCHDOG (timeoutTime <= 0 becomes 300)",
        fix = "Put it back near the default and diagnose the hang from the thread dump.",
    )

    val CONFIG_NOT_PARSEABLE = Rule(
        id = "C009",
        area = RuleArea.CONFIG,
        severity = Severity.BLOCKER,
        title = "A configuration file is not valid YAML",
        rationale = "The server cannot read it either. Depending on the file, start-up either aborts " +
            "or continues with defaults that silently replace everything configured here.",
        provenance = "Parsed with SnakeYAML; the message is the parser's own",
        fix = "Fix the reported line. Tabs used for indentation are the usual cause.",
    )

    val DUPLICATE_KEY = Rule(
        id = "C010",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "A key appears twice in one file",
        rationale = "The loader keeps the last occurrence and says nothing. An edit made at the top " +
            "of the file therefore has no effect, which is impossible to see by reading around it.",
        provenance = "Detected by composing the document instead of loading it, so duplicates survive",
        fix = "Delete the copy you do not want.",
    )

    val LEGACY_PAPER_YML = Rule(
        id = "C011",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "A legacy paper.yml is still present and is being ignored",
        rationale = "Paper's configuration lives in config/paper-global.yml and config/" +
            "paper-world-defaults.yml. An old paper.yml left in the server root is not read, so " +
            "edits made to it do nothing while appearing to be the configuration.",
        provenance = "$GLOBAL (the class backing config/paper-global.yml)",
        fix = "Move anything still wanted into the config/ files, then delete paper.yml.",
    )

    val NO_CONFIG_VERSION = Rule(
        id = "C012",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "A Paper config has no version key",
        rationale = "Paper stamps a schema version into these files and uses it to migrate renamed " +
            "keys. Without it the file looks ancient to the migrator, which is what a hand-written " +
            "or partially copied config looks like.",
        provenance = "$GLOBAL:82 (version = CURRENT_VERSION)",
        fix = "Let the server regenerate the file, then reapply your changes on top.",
    )

    val SECURE_PROFILE_DISABLED = Rule(
        id = "C013",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "Secure chat profiles are not enforced",
        rationale = "With enforce-secure-profile=false the server accepts players whose chat is not " +
            "signed. It is a deliberate choice on some networks and a surprise on others, and it is " +
            "worth knowing which this is.",
        provenance = "server.properties key enforce-secure-profile, read from this file",
        fix = "Leave it enabled unless the network genuinely needs unsigned chat.",
    )

    val EULA_NOT_ACCEPTED = Rule(
        id = "C014",
        area = RuleArea.CONFIG,
        severity = Severity.BLOCKER,
        title = "eula.txt is missing or not accepted",
        rationale = "The server exits during start-up, and the line it prints is logged at INFO, so " +
            "the reason is easy to miss in a panel that only surfaces errors.",
        provenance = "PaperMC/Paper paper-server/patches/sources/net/minecraft/server/Main.java.patch:81-84",
        fix = "Set eula=true in eula.txt if you accept Mojang's EULA.",
    )

    val WORLD_DIRECTORY_MISSING = Rule(
        id = "C015",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "level-name points at a directory that is not there",
        rationale = "The server will generate a brand new world under that name. On a server that " +
            "already had one, this is how a world goes missing after a rename or a restore.",
        provenance = "server.properties key level-name, checked against this directory",
        fix = "Point level-name at the world directory you meant, or restore it before starting.",
    )

    val ANTI_XRAY_ENABLED = Rule(
        id = "C016",
        area = RuleArea.CONFIG,
        severity = Severity.INFO,
        title = "Anti-xray is on",
        rationale = "It ships off because it costs CPU on every chunk sent. Worth knowing it is on " +
            "when chunk sending is the thing being investigated.",
        provenance = "$WORLD:98 (anticheat.anti-xray.enabled, default false)",
        fix = null,
    )

    val SPARK_DISABLED = Rule(
        id = "C017",
        area = RuleArea.CONFIG,
        severity = Severity.INFO,
        title = "The bundled profiler is disabled",
        rationale = "Paper ships spark enabled. With it off, the next performance complaint has no " +
            "profiler to answer it and the window to catch the cause has closed.",
        provenance = "$GLOBAL:103 (spark.enabled, default true)",
        fix = "Re-enable spark, or install it separately, before you need it.",
    )

    val CHUNK_SYSTEM_BOTTLENECK = Rule(
        id = "C018",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "Paper chunk-system threads or rate limits create an I/O bottleneck",
        rationale = "Paper's Moonrise chunk system defaults io-threads and worker-threads to -1 so " +
            "pool sizes track the machine's CPU count. Setting io-threads to 0 disables dedicated " +
            "asynchronous region I/O, and pinning worker-threads to 1 or below -1 serialises chunk " +
            "generation and lighting onto a single bottleneck queue.",
        provenance = "$GLOBAL (ChunkSystem: io-threads=-1, worker-threads=-1)",
        fix = "Reset chunk-system.io-threads and chunk-system.worker-threads to -1 unless dedicated " +
            "benchmarking on this host proved a specific pool count.",
    )

    val PAPER_26_CONFIG_SCHEMA_VERSION = Rule(
        id = "C019",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "Paper 26.3 configuration schema version mismatch or deprecated root key",
        rationale = "Paper 26.3 modernizes global and per-world configuration schemas. Config files " +
            "declaring legacy schema versions (< 30) or containing obsolete root sections (such as " +
            "root timings:, legacy chunk-loading: instead of chunk-system:, or legacy messages:) " +
            "trigger automated lossy schema rewriting or silent omission of modern defaults.",
        provenance = "$GLOBAL (CURRENT_VERSION = 30+)",
        fix = "Let Paper 26.3 regenerate config/paper-global.yml and config/paper-world-defaults.yml, " +
            "or remove deprecated root sections and update the version key.",
    )

    val NETWORK_COMPRESSION_HAZARD = Rule(
        id = "C020",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "network-compression-threshold in server.properties causes CPU exhaustion or bandwidth saturation",
        rationale = "network-compression-threshold defines the packet byte size threshold before Netty " +
            "applies deflate compression. Setting it between 0 and 64 forces Netty to attempt compression " +
            "on tiny keepalive and movement packets, wasting CPU and often expanding payload size. " +
            "Setting it to -1 on public servers sends all chunk data uncompressed, saturating uplink bandwidth.",
        provenance = "server.properties key network-compression-threshold (vanilla default 256, Paper recommended 256-512)",
        fix = "Set network-compression-threshold=256 (or 512 for high-throughput networks). Avoid " +
            "values <= 64 or -1 on public internet servers.",
    )

    val NETTY_THREADS_BOTTLENECK = Rule(
        id = "C021",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "Spigot netty-threads setting is pinned to 1 or below, serialising network I/O",
        rationale = "settings.netty-threads in spigot.yml controls the number of Netty EventLoop worker " +
            "threads dedicated to handling player socket I/O, encryption, and packet compression. " +
            "Setting netty-threads to 1 or below bottlenecks all connected players onto a single " +
            "thread, causing packet queueing and latency spikes under concurrent player load.",
        provenance = "$SPIGOT:182 (settings.netty-threads, default min(4, availableProcessors))",
        fix = "Set settings.netty-threads to 4 or higher (or remove the override to let Paper " +
            "automatically scale with CPU cores).",
    )

    val PAPER_26_ITEM_COMPONENT_VALIDATION = Rule(
        id = "C022",
        area = RuleArea.CONFIG,
        severity = Severity.WARNING,
        title = "Paper 26.3 item component validation or book profile checks are disabled",
        rationale = "Minecraft 1.20.5+ through 26.3 transitioned item metadata to structured Data " +
            "Components. In paper-global.yml, disabling item validation (such as setting " +
            "item-validation.resolve-selectors-in-books: true or disabling max component size / " +
            "display-name checks) allows malicious book NBT and complex nested component payloads " +
            "to exploit server parser loops or crash clients.",
        provenance = "$GLOBAL (item-validation section)",
        fix = "Keep item-validation.resolve-selectors-in-books=false and leave item-validation " +
            "limits at their default Paper 26.3 values.",
    )

    val all: List<Rule> = listOf(
        OFFLINE_MODE_NO_PROXY,
        VELOCITY_SECRET_EMPTY,
        TWO_FORWARDING_SCHEMES,
        UNSUPPORTED_SETTING_ENABLED,
        CONSOLE_ALL_PERMISSIONS,
        RCON_WITHOUT_PASSWORD,
        SIMULATION_OVER_VIEW,
        WATCHDOG_TIMEOUT_HIGH,
        CONFIG_NOT_PARSEABLE,
        DUPLICATE_KEY,
        LEGACY_PAPER_YML,
        NO_CONFIG_VERSION,
        SECURE_PROFILE_DISABLED,
        EULA_NOT_ACCEPTED,
        WORLD_DIRECTORY_MISSING,
        ANTI_XRAY_ENABLED,
        SPARK_DISABLED,
        CHUNK_SYSTEM_BOTTLENECK,
        PAPER_26_CONFIG_SCHEMA_VERSION,
        NETWORK_COMPRESSION_HAZARD,
        NETTY_THREADS_BOTTLENECK,
        PAPER_26_ITEM_COMPONENT_VALIDATION,
    )
}
