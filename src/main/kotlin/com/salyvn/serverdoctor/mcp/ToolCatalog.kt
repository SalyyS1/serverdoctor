package com.salyvn.serverdoctor.mcp

import com.salyvn.serverdoctor.config.ConfigAudit
import com.salyvn.serverdoctor.config.ServerConfigSet
import com.salyvn.serverdoctor.core.RuleArea
import com.salyvn.serverdoctor.core.RuleCatalog
import com.salyvn.serverdoctor.core.ScanReport
import com.salyvn.serverdoctor.crash.CrashAudit
import com.salyvn.serverdoctor.crash.CrashReportFile
import com.salyvn.serverdoctor.diff.ServerDiff
import com.salyvn.serverdoctor.diff.ServerSnapshot
import com.salyvn.serverdoctor.flags.FlagsAudit
import com.salyvn.serverdoctor.flags.JvmCommandLine
import com.salyvn.serverdoctor.flags.StartScriptReader
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.LogTriage
import com.salyvn.serverdoctor.perms.PermsAudit
import com.salyvn.serverdoctor.plugins.HangarClient
import com.salyvn.serverdoctor.plugins.ModrinthClient
import com.salyvn.serverdoctor.plugins.PluginIndex
import com.salyvn.serverdoctor.plugins.PluginsAudit
import com.salyvn.serverdoctor.report.JsonReporter
import com.salyvn.serverdoctor.world.WorldAudit
import com.salyvn.serverdoctor.world.WorldFolder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.nio.file.Files
import java.nio.file.Path

/**
 * The audits, exposed as MCP tools.
 *
 * They return the JSON report rather than the console rendering, because the caller is a model that
 * will quote rule ids and severities back to a human, and JSON removes the step where it has to parse
 * a layout meant for a terminal.
 *
 * Every tool is read-only and takes absolute paths. Nothing here starts a server, writes a file, or
 * loads a plugin class.
 */
object ToolCatalog {

    fun tools(): List<McpTool> = listOf(
        LogTool,
        ConfigTool,
        FlagsTool,
        PluginsTool,
        WorldsTool,
        CrashTool,
        AccessTool,
        DiffTool,
        RulesTool,
    )

    private fun argument(arguments: JsonObject, name: String): String? =
        (arguments[name] as? JsonPrimitive)?.content?.takeIf { it.isNotBlank() }

    private fun flag(arguments: JsonObject, name: String): Boolean =
        (arguments[name] as? JsonPrimitive)?.content?.equals("true", ignoreCase = true) == true

    private fun render(reports: List<ScanReport>): ToolResult = ToolResult(JsonReporter.render(reports))

    private fun missing(what: String, path: String) = ToolResult("$what not found: $path", isError = true)

    private object LogTool : McpTool {
        override val name = "triage_log"
        override val title = "Triage a Minecraft server log"
        override val description =
            "Read a server log, a rolled *.log.gz or a crash report and return rule-identified " +
                "findings, worst first, with the plugin each one is attributable to. Pass plugins_dir " +
                "when the plugins directory is available: stack frames are then matched against the " +
                "jars actually installed instead of guessed at."
        override val inputSchema = McpServer.objectSchema(
            required = listOf("path"),
            properties = mapOf(
                "path" to ("string" to "Absolute path to the log file"),
                "plugins_dir" to ("string" to "Absolute path to the plugins directory, optional"),
            ),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val path = argument(arguments, "path") ?: return ToolResult("No path given", isError = true)
            val file = Path.of(path)
            if (!Files.isRegularFile(file)) return missing("Log", path)
            val index = argument(arguments, "plugins_dir")
                ?.let { PluginIndex.read(Path.of(it)) }
                ?: PluginIndex.EMPTY
            return render(listOf(LogTriage(index).analyse(LogSource.of(file))))
        }
    }

    private object ConfigTool : McpTool {
        override val name = "audit_config"
        override val title = "Audit a server's configuration"
        override val description =
            "Read server.properties together with bukkit.yml, spigot.yml and the Paper configs and " +
                "report security, correctness and layout problems. Give the server directory: the " +
                "useful checks compare files against each other, so a single file yields less."
        override val inputSchema = McpServer.objectSchema(
            required = listOf("path"),
            properties = mapOf("path" to ("string" to "Absolute path to the server directory")),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val path = argument(arguments, "path") ?: return ToolResult("No path given", isError = true)
            val directory = Path.of(path)
            if (!Files.isDirectory(directory)) return missing("Directory", path)
            val configs = ServerConfigSet.read(directory)
            if (configs.isEmpty) return ToolResult("No configuration files under $path", isError = true)
            return render(listOf(ConfigAudit().analyse(configs)))
        }
    }

    private object FlagsTool : McpTool {
        override val name = "audit_jvm_flags"
        override val title = "Audit JVM start-up flags"
        override val description =
            "Audit the flags a server starts with. Pass command with the java command line itself, or " +
                "path pointing at a start script or the server directory holding one. host_memory " +
                "(e.g. 8G) enables the check that the heap leaves room for the operating system."
        override val inputSchema = McpServer.objectSchema(
            required = emptyList(),
            properties = mapOf(
                "command" to ("string" to "The java command line, quoted as one string"),
                "path" to ("string" to "Absolute path to a start script or server directory"),
                "host_memory" to ("string" to "Total machine memory, e.g. 8G"),
            ),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val hostBytes = argument(arguments, "host_memory")?.let { JvmCommandLine.parseSize(it) }
            val audit = FlagsAudit(hostBytes)

            argument(arguments, "command")?.let { literal ->
                return render(listOf(audit.analyse("command", JvmCommandLine.parse(literal))))
            }

            val path = argument(arguments, "path")
                ?: return ToolResult("Give either command or path", isError = true)
            val candidate = Path.of(path)
            val script = if (Files.isDirectory(candidate)) StartScriptReader.findScript(candidate) else candidate
                .takeIf { Files.isRegularFile(it) }
            if (script == null) return missing("Start script", path)
            val parsed = StartScriptReader.readCommand(script)?.let { JvmCommandLine.parse(it) }
            return render(listOf(audit.analyse(script.toString(), parsed)))
        }
    }

    private object PluginsTool : McpTool {
        override val name = "audit_plugins"
        override val title = "Inventory and audit a plugins directory"
        override val description =
            "List what is installed and report the problems that exist between plugins: missing hard " +
                "dependencies, two jars claiming one name, jars that are not plugins. Set online to " +
                "true to additionally identify each file by hash against Modrinth, fall back to " +
                "Hangar by project name, and report provenance, newer versions and archived projects. " +
                "online performs network requests."
        override val inputSchema = McpServer.objectSchema(
            required = listOf("path"),
            properties = mapOf(
                "path" to ("string" to "Absolute path to the plugins directory or the server directory"),
                "online" to ("boolean" to "Look files up by hash on Modrinth. Default false."),
            ),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val path = argument(arguments, "path") ?: return ToolResult("No path given", isError = true)
            val given = Path.of(path)
            val directory = when {
                Files.isDirectory(given.resolve("plugins")) -> given.resolve("plugins")
                Files.isDirectory(given) -> given
                else -> return missing("Directory", path)
            }
            val index = PluginIndex.read(directory)
            if (index.jars.isEmpty()) return ToolResult("No jars in $directory", isError = true)
            val audit = if (flag(arguments, "online")) {
                PluginsAudit(ModrinthClient(), HangarClient())
            } else {
                PluginsAudit()
            }
            return render(listOf(audit.analyse(index, directory.toString())))
        }
    }

    private object WorldsTool : McpTool {
        override val name = "audit_worlds"
        override val title = "Check the worlds on disk"
        override val description =
            "Read every world under a server directory: whether level.dat is there and parseable, " +
                "whether the worlds agree on the game version that last saved them, empty region " +
                "files, datapacks the server will ignore, hardcore and cheat flags. Reads NBT " +
                "directly; nothing is written."
        override val inputSchema = McpServer.objectSchema(
            required = listOf("path"),
            properties = mapOf(
                "path" to ("string" to "Absolute path to the server directory, or to one world folder"),
            ),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val path = argument(arguments, "path") ?: return ToolResult("No path given", isError = true)
            val directory = Path.of(path)
            if (!Files.isDirectory(directory)) return missing("Directory", path)
            val worlds = WorldFolder.discover(directory)
            if (worlds.isEmpty()) return ToolResult("No worlds under $path", isError = true)
            return render(listOf(WorldAudit().analyse(worlds, path)))
        }
    }

    private object CrashTool : McpTool {
        override val name = "read_crash_reports"
        override val title = "Read crash reports"
        override val description =
            "Parse crash-reports/crash-*.txt: what the server was doing, the first frame that is not " +
                "the server's own code, out-of-memory, the object being ticked, and whether the same " +
                "crash was written more than once. A report also carries the JVM flags the server ran " +
                "with, so those are audited from the file itself."
        override val inputSchema = McpServer.objectSchema(
            required = listOf("path"),
            properties = mapOf(
                "path" to ("string" to "Absolute path to a crash report, a crash-reports directory, or a server directory"),
                "plugins_dir" to ("string" to "Absolute path to the plugins directory, optional"),
            ),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val path = argument(arguments, "path") ?: return ToolResult("No path given", isError = true)
            val given = Path.of(path)
            val files = CrashReportFile.discover(given)
            if (files.isEmpty()) return ToolResult("No crash reports under $path", isError = true)

            val index = argument(arguments, "plugins_dir")
                ?.let { PluginIndex.read(Path.of(it)) }
                ?: given.resolve("plugins").takeIf { Files.isDirectory(it) }?.let { PluginIndex.read(it) }
                ?: PluginIndex.EMPTY

            val reports = files.map { CrashReportFile.read(it) }
            val crash = CrashAudit(index).analyse(reports, path)
            val flags = reports.lastOrNull { it.jvmFlags != null }?.let { report ->
                FlagsAudit().analyse("${report.name} (JVM Flags)", JvmCommandLine.parse(report.jvmFlags!!))
            }
            return render(listOfNotNull(crash, flags))
        }
    }

    private object AccessTool : McpTool {
        override val name = "audit_access_lists"
        override val title = "Audit operators, whitelist, bans and permissions"
        override val description =
            "Read ops.json, whitelist.json, banned-players.json, banned-ips.json and the permissions " +
                "file, and check them against how the server verifies identity: operators on a server " +
                "in offline mode with no proxy forwarding, hand-edited entries with no id, a whitelist " +
                "that is on and empty, a permissions file the server silently skips."
        override val inputSchema = McpServer.objectSchema(
            required = listOf("path"),
            properties = mapOf("path" to ("string" to "Absolute path to the server directory")),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val path = argument(arguments, "path") ?: return ToolResult("No path given", isError = true)
            val directory = Path.of(path)
            if (!Files.isDirectory(directory)) return missing("Directory", path)
            return render(listOf(PermsAudit().analyse(directory, path)))
        }
    }

    private object DiffTool : McpTool {
        override val name = "diff_servers"
        override val title = "Compare two servers"
        override val description =
            "Compare two server directories: configuration values, keys present on one side only, the " +
                "plugin set, plugin versions, jars that claim one version and are not the same file, " +
                "and the JVM flags each starts with. Ports, addresses, secrets and the seed are skipped."
        override val inputSchema = McpServer.objectSchema(
            required = listOf("left", "right"),
            properties = mapOf(
                "left" to ("string" to "Absolute path to the first server directory"),
                "right" to ("string" to "Absolute path to the second server directory"),
            ),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val left = argument(arguments, "left") ?: return ToolResult("No left path given", isError = true)
            val right = argument(arguments, "right") ?: return ToolResult("No right path given", isError = true)
            val a = Path.of(left)
            val b = Path.of(right)
            if (!Files.isDirectory(a)) return missing("Directory", left)
            if (!Files.isDirectory(b)) return missing("Directory", right)
            return render(listOf(ServerDiff().compare(ServerSnapshot.read(a), ServerSnapshot.read(b))))
        }
    }

    private object RulesTool : McpTool {
        override val name = "list_rules"
        override val title = "List the rule catalogue"
        override val description =
            "Every rule the tool can report, with its severity, rationale and the source the " +
                "underlying fact was established from. Use this to explain a rule id to a human, or " +
                "to check what the tool does and does not look at before claiming a server is clean."
        override val inputSchema = McpServer.objectSchema(
            required = emptyList(),
            properties = mapOf(
                "area" to ("string" to "log, config, flags, plugins, world, crash, perms or diff. Omit for all."),
            ),
        )

        override fun call(arguments: JsonObject): ToolResult {
            val requested = argument(arguments, "area")
            val areas = if (requested == null) {
                RuleArea.entries.toList()
            } else {
                val match = RuleArea.entries.firstOrNull { it.label.equals(requested, ignoreCase = true) }
                    ?: return ToolResult("Unknown area: $requested", isError = true)
                listOf(match)
            }
            val text = buildString {
                for (area in areas) {
                    for (rule in RuleCatalog.byArea(area)) {
                        appendLine("${rule.id}\t${area.label}\t${rule.severity.label}\t${rule.title}")
                        appendLine("\twhy: ${rule.rationale}")
                        rule.fix?.let { appendLine("\tfix: $it") }
                        appendLine("\tsource: ${rule.provenance}")
                    }
                }
            }
            return ToolResult(text)
        }
    }
}
