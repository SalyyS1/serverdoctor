# serverdoctor

[![build](https://github.com/SalyyS1/serverdoctor/actions/workflows/build.yml/badge.svg)](https://github.com/SalyyS1/serverdoctor/actions/workflows/build.yml)

Diagnostics for a Minecraft server, read from the artifacts it has already produced: its log, its
configuration files, its start script and the jars in its plugins directory. It does not start a
server, connect to one, or load a line of plugin code.

That constraint is the point. The moment you need a diagnosis is the moment the server is down, the
host has handed you a folder and a log, and nothing can be reproduced. Everything here works on that
folder, offline, on the same box that produced it.

| Command | Question it answers |
| --- | --- |
| `scan` | Everything below, over one server directory, in one pass. |
| `log` | What went wrong, which plugin is to blame, and what to do about it. |
| `config` | Is this server exposed or misconfigured — judged across `server.properties`, `bukkit.yml`, `spigot.yml` and the Paper configs together, not one file at a time? |
| `flags` | Do the JVM flags in the start script do what whoever wrote them thought? |
| `plugins` | What is installed, what is broken about the set, and where did each jar come from? |

There is also an `mcp` mode that serves the same audits to an AI coding agent over the Model Context
Protocol, so "why did this server crash" becomes something the agent answers from the log instead of
from your summary of it.

## Why these

Each audit exists because the server does not tell you the thing you need to know.

- **A log tells you what happened, not who did it.** Paper names the plugin when a listener throws,
  and says nothing when a plugin's thread corrupts a chunk twenty minutes later. Findings here carry
  the attribution and say how it was made — from the logger prefix, from the server's own blame line,
  or from a stack frame matched against the jars you actually have installed.
- **The absence of a warning is not good news.** Paper deletes vanilla's
  `Can't keep up! Is the server overloaded?` and replaces the tick loop with catch-up logic, so on
  Paper that line never appears no matter how far behind the server falls. If your log has it, your
  log is not from Paper — which is itself worth knowing before you follow Paper-specific advice.
- **The line that stopped your server can be logged at INFO.** `You need to agree to the EULA in
  order to run the server` is INFO, so a panel that surfaces only errors shows a clean shutdown and
  no reason.
- **A setting can do nothing and look like it works.** `timeout-time: -1` in `spigot.yml` does not
  disable the watchdog; Paper substitutes 300 seconds. An old `paper.yml` in the server root is not
  read at all once `config/paper-global.yml` exists. A key that appears twice keeps the last copy
  silently.
- **`folia-supported: true` is a claim, not a check.** It is the only thing Folia tests at load, and
  it is written by the plugin's author.

Every rule states one fact and records where that fact came from — a file and line in Paper or Folia,
a JEP, an API response. `serverdoctor rules` prints the catalogue with those sources, so a finding can
be argued with instead of believed.

## Requirements

Java 21 or newer. Nothing else; the release jar is self-contained. The network is used only by
`plugins --online`, and never otherwise.

## Install

Download `serverdoctor-<version>.jar` from the
[releases](https://github.com/SalyyS1/serverdoctor/releases) page:

```
java -jar serverdoctor.jar --help
```

## Quick start

```
# The whole server folder, every applicable audit
java -jar serverdoctor.jar scan /srv/mc --host-memory 8G

# Just the log, with plugin attribution from the jars that are installed
java -jar serverdoctor.jar log /srv/mc/logs/latest.log --plugins /srv/mc/plugins

# A rolled log from a host, straight out of the archive
java -jar serverdoctor.jar log logs/2026-08-24-1.log.gz

# Configuration, judged across files
java -jar serverdoctor.jar config /srv/mc

# Flags, from a start script or from something pasted into chat
java -jar serverdoctor.jar flags /srv/mc --host-memory 8G
java -jar serverdoctor.jar flags --command "java -Xms2G -Xmx8G -XX:+UseG1GC -jar paper.jar"

# What is installed, and what a public index says each file is
java -jar serverdoctor.jar plugins /srv/mc/plugins --online

# Every rule, with its rationale and its source
java -jar serverdoctor.jar rules --area log
```

Output is plain text by default, `--format json` for a machine, `-o file` to write it, and
`--fail-on critical` (the default) decides the exit code so a scan can gate a deploy.

## What the output looks like

Both samples are real output, captured from the deliberately broken fixtures in
`src/test/resources`, which is also what CI runs against.

Triage of a log where a plugin blocks the main thread on MySQL until the watchdog kills the server:

```
$ java -jar serverdoctor.jar log logs/latest.log

log: logs/latest.log
  minecraft    26.2
  server       Paper version 26.2-116-main (MC: 26.2)
  startup      19.114s
  lines read   62
  log entries  33
  line format  paper
  covers       22:30:58 to 22:53:09

[blocker] L001  The watchdog fired: a tick took longer than the timeout
    line 39
      A tick did not finish before the watchdog timeout, so the server was considered hung. The thread dump that follows names what was running.
        at com.mysql.cj.protocol.a.SimplePacketReader.readMessage(SimplePacketReader.java:66)
        at com.example.worldtools.storage.MySqlStore.load(MySqlStore.java:88)
        at com.example.worldtools.JoinListener.onJoin(JoinListener.java:37)
    fix: Read the Server thread dump below the message: the topmost plugin frame is what was blocking. Raising timeout-time hides the crash and converts it into lag.

[blocker] L006  A plugin was compiled for a newer Java release than the server runs
    line 9
      com.example.regionguard.RegionGuard needs Java 25 (class file major 69); this runtime accepts up to Java 21.
        java.lang.UnsupportedClassVersionError: com/example/regionguard/RegionGuard has been compiled by a more recent version of the Java Runtime (class file version 69.0), this version of the Java Runtime only recognizes class file versions up to 65.0
    fix: Run the server on the Java release the plugin needs, or install a build of the plugin compiled for yours.

[critical] L002  A plugin touched the server from the wrong thread
    line 17 (x2)
      "Entity add" ran off the owning thread, reached from com.example.spawnhelper. Thread: Craft Scheduler Thread - 12
        at org.spigotmc.AsyncCatcher.catchOp(AsyncCatcher.java:10)
        at net.minecraft.server.level.ServerLevel.addFreshEntity(ServerLevel.java:1204)
    fix: The named operation has to run on the owning thread: the main thread on Paper, the region or entity scheduler on Folia.

[critical] L003  A plugin's event handler threw
    line 27 (x2)
      WorldTools v3.0.1 threw while handling PlayerJoinEvent: java.lang.NullPointerException
        at com.example.worldtools.JoinListener.onJoin(JoinListener.java:41)
        at org.bukkit.plugin.EventExecutor$2.execute(EventExecutor.java:77)
    fix: Report it to the named plugin with the stack trace. If it fires on a common event, expect knock-on breakage in unrelated features.

    [four more findings omitted here: the load failures, the ambiguous plugin name, the EULA line,
     the out-of-memory error and one exception no rule explains]

Summary: 6 blockers, 3 criticals, 2 warnings, 1 info
```

Note the `(x2)`: the same handler failing twice is one finding with a count, not two entries. A log
from a server that has been crash-looping for a day stays readable.

The configuration audit on the same fixture, which is offline-mode behind a Velocity proxy whose
secret was never filled in:

```
$ java -jar serverdoctor.jar config /srv/mc

server: /srv/mc
  server       paper
  files        server.properties, spigot.yml, paper-global.yml
  online-mode  false
  forwarding   velocity
  distances    view 10, simulation 12
  level-name   world

[blocker] C002  Velocity forwarding is on with an empty secret
    config/paper-global.yml:9
      proxies.velocity.enabled is true and proxies.velocity.secret is empty.
    fix: Copy forwarding.secret from the proxy into proxies.velocity.secret.

[critical] C004  An unsupported-settings toggle is enabled
    config/paper-global.yml:15
      unsupported-settings.allow-piston-duplication is true, and it ships as false.
    fix: Set it back to its default unless you can name why this server needs the old behaviour.

[critical] C006  RCON is enabled with no password
    server.properties:5
      enable-rcon=true with an empty rcon.password on port 25575.
    fix: Set a long random rcon.password, bind RCON to localhost, or turn it off.

[warning] C008  The watchdog timeout is long enough to hide a hang
    spigot.yml:4
      settings.timeout-time is 900 seconds; the default is 60.
    fix: Put it back near the default and diagnose the hang from the thread dump.

[warning] C010  A key appears twice in one file
    server.properties:14
      online-mode appears 2 times; the server uses "false".
        line 3: online-mode=false
        line 14: online-mode=false
    fix: Delete the copy you do not want.
```

What is *not* reported there matters as much: `online-mode=false` produces no finding, because
Velocity forwarding is configured, and that combination is correct for a backend server. The rule for
offline mode fires only when nothing in front of the server is authenticating players — which is the
false positive this audit exists to avoid.

## What it does not do

Stated plainly, because a tool that reports nothing looks the same as a tool that found nothing.

- It does not read your world. No region files, no player data, no NBT.
- It does not open a network connection unless you pass `--online`, and then only to look plugin jars
  up by their hash.
- It does not judge tuning by taste. There is no rule saying your view distance is wrong, because the
  hardware it has to be right for is not in the folder.
- It cannot verify a self-declaration. `folia-supported`, `api-version`, a plugin's own version — all
  of it is what the author wrote. Only the file hash identifies a build.
- Log attribution is best effort and says which method it used. A shaded or relocated plugin can put
  a library's package in the frame you would otherwise blame, and the bracketed name in a log line is
  the descriptor's `prefix:` when one is set, which need not resemble the plugin's name.
- `plugins --online` matching nothing is not a safety finding. Paid plugins, private builds and
  pruned releases all fail to match for ordinary reasons.

## With an AI agent

`serverdoctor mcp` speaks the Model Context Protocol over stdio, exposing `triage_log`,
`audit_config`, `audit_jvm_flags`, `audit_plugins` and `list_rules`. All five are read-only and return
the JSON report. For a client that reads the usual config file:

```json
{
  "mcpServers": {
    "serverdoctor": {
      "command": "java",
      "args": ["-jar", "/opt/serverdoctor/serverdoctor.jar", "mcp"]
    }
  }
}
```

The agent gets the same rule ids and the same sources, so when it tells someone their server is
hanging on MySQL it can point at the line that says so.

## Rules and their sources

```
$ java -jar serverdoctor.jar rules --area flags

  F003  [critical] The watchdog is switched off
      why:    disable.watchdog stops Paper from dumping threads and ending a hung server. A
              deadlock then presents as a server that is up, accepts connections and never ticks,
              and no diagnosis is written to the log.
      fix:    Remove -Ddisable.watchdog and fix the hang it was hiding.
      source: PaperMC/Paper paper-server/src/main/java/org/spigotmc/WatchdogThread.java:16
```

Fifty-six rules across the four audits. Every `source:` line names a file and line in Paper or Folia,
a JEP, or an API response that was checked, and the whole catalogue is in
[`docs/rules.md`](docs/rules.md).

## Building

```
./gradlew build
```

Kotlin 2.4.10 on a JDK 21 toolchain, Gradle 9.7.1 through the wrapper. `build/libs/serverdoctor-<version>.jar`
is the self-contained CLI; the `-thin` classifier is the unshaded jar and is not the one to run. The
test suite works against the fixtures in `src/test/resources`, which are deliberately broken servers
and logs rather than mocks.

## Credits

serverdoctor is an independent project. It is not affiliated with, endorsed by or sponsored by PaperMC,
Mojang, Microsoft or Modrinth.

No code was copied from any other project. Several solved a neighbouring problem first and are
credited in [NOTICE](NOTICE) alongside the sources every rule's underlying fact was read from —
including [aternosorg/mclogs](https://github.com/aternosorg/mclogs), whose hosted analyser is the
closest existing thing to the `log` command, [birdflop/botflop](https://github.com/birdflop/botflop),
which answers configuration questions from timings reports, and
[YouHaveTrouble/minecraft-optimization](https://github.com/YouHaveTrouble/minecraft-optimization),
the guide most of this ecosystem's tuning advice traces back to.

Two earlier tools by the same author cover the build side of the same problem:
[foliascan](https://github.com/SalyyS1/foliascan) reports where a plugin jar breaks on Folia, and
[pluginscope](https://github.com/SalyyS1/pluginscope) audits jar packaging, API compatibility and
resource packs.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

