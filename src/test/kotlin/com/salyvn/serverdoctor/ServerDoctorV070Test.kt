package com.salyvn.serverdoctor

import com.github.ajalt.clikt.core.parse
import com.github.ajalt.clikt.core.subcommands
import com.salyvn.serverdoctor.cli.SparkCommand
import com.salyvn.serverdoctor.input.LogSource
import com.salyvn.serverdoctor.log.LogEvent
import com.salyvn.serverdoctor.log.LogTriage
import com.salyvn.serverdoctor.log.SparkFlamegraphAnalyzer
import com.salyvn.serverdoctor.log.SparkMappingDictionary
import com.salyvn.serverdoctor.log.StackFrame
import com.salyvn.serverdoctor.mcp.McpServer
import com.salyvn.serverdoctor.mcp.ToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.io.path.createTempDirectory
import kotlin.io.path.createTempFile
import kotlin.io.path.readText
import kotlin.io.path.writeText

class ServerDoctorV070Test {

    @Test
    fun `detects paper 1_21_4 plugin remapper failures and legacy craftbukkit v1 linkage errors`() {
        val log = """
            [10:00:01] [ServerMain/ERROR]: Encountered exception remapping plugins
            java.lang.RuntimeException: Failed to remap plugin plugins/LegacyCrates-1.8.jar
            	at io.papermc.paper.pluginremap.PluginRemapper.remap(PluginRemapper.java:214)
            	at io.papermc.paper.plugin.provider.source.DirectoryProviderSource.prepareContext(DirectoryProviderSource.java:58)
            [10:00:14] [Server thread/ERROR]: Could not pass event PlayerInteractEvent to HologramPlus v3.2.0
            java.lang.NoClassDefFoundError: org/bukkit/craftbukkit/v1_20_R3/entity/CraftPlayer
            	at com.example.holo.NmsPacketBridge.sendHolo(NmsPacketBridge.java:49)
            	at com.example.holo.InteractListener.onUse(InteractListener.java:27)
        """.trimIndent()

        val report = triageText(log)
        val l029 = report.findings.filter { it.ruleId == "L029" }
        assertEquals(2, l029.size, "expected both remapper and v1_20_R3 linkage hits: $l029")
        assertTrue(l029.any { it.detail.contains("LegacyCrates-1.8.jar") && it.detail.contains("PluginRemapper") }, l029.toString())
        assertTrue(
            l029.any { it.detail.contains("com.example.holo") && it.detail.contains("org.bukkit.craftbukkit.v1_20_R3") },
            l029.toString(),
        )
    }

    @Test
    fun `detects minecraft 1_21_4 data component codec failures and registry bootstrap errors`() {
        val log = """
            [11:02:10] [Server thread/ERROR]: Tried to load invalid item: DataResult.Error['Unknown item model payload for minecraft:item_model: Not a resource location']
            	at net.minecraft.core.component.DataComponentPatch.codec(DataComponentPatch.java:92)
            	at com.example.rpgitems.KitSerializer.decode(KitSerializer.java:74)
            [11:03:00] [Server thread/ERROR]: Failed to load registries due to above errors
            java.lang.IllegalStateException: Registry loading failed for custom_pack:enchantment/frostbite
            	at net.minecraft.resources.RegistryDataLoader.load(RegistryDataLoader.java:148)
        """.trimIndent()

        val report = triageText(log)
        val l030 = report.findings.filter { it.ruleId == "L030" }
        assertEquals(2, l030.size, "expected item component codec and registry bootstrap L030 hits: $l030")
        assertTrue(l030.any { it.detail.contains("minecraft:item_model") && it.detail.contains("com.example.rpgitems") }, l030.toString())
        assertTrue(l030.any { it.detail.contains("registry") && it.detail.contains("custom_pack:enchantment/frostbite") }, l030.toString())
    }

    @Test
    fun `detects signed chat chain rejections configuration phase disconnects and packet limiter kicks`() {
        val log = """
            [12:10:00] [Server thread/WARN]: Chat message validation failure for player Alex: Out-of-order chat packet received
            net.minecraft.network.chat.SignedMessageChain${'$'}DecodeException: Missing or invalid signature
            	at net.minecraft.network.chat.SignedMessageChain.unpack(SignedMessageChain.java:64)
            	at com.example.chatformat.PacketRewriteHandler.channelRead(PacketRewriteHandler.java:83)
            [12:11:05] [Server thread/WARN]: Failed to handle packet during configuration phase: Missing registry entries for KnownPacks
            	at net.minecraft.server.network.ServerConfigurationPacketListenerImpl.handleSelectKnownPacks(ServerConfigurationPacketListenerImpl.java:119)
            [12:12:30] [Netty Epoll Server IO #0/WARN]: Steve (/198.51.100.42:54120) was kicked for exceeding packet rate limit (624.0 > 500.0 packets/s)
        """.trimIndent()

        val report = triageText(log)
        val l031 = report.findings.filter { it.ruleId == "L031" }
        assertEquals(3, l031.size, "expected signed chat, config phase, and packet-limiter L031 findings: $l031")
        assertTrue(l031.any { it.detail.contains("Signed chat chain") && it.detail.contains("com.example.chatformat") }, l031.toString())
        assertTrue(l031.any { it.detail.contains("CONFIGURATION") }, l031.toString())
        assertTrue(l031.any { it.detail.contains("PacketLimiter") }, l031.toString())
    }

    @Test
    fun `deobfuscates proguard line intervals tiny v2 and tsrg frames and demangles jdk21 lambdas`() {
        val proguardText = """
            # Mojang official ProGuard header comment
            net.minecraft.server.MinecraftServer -> net.minecraft.server.MinecraftServer:
                100:180:void tickServer(java.util.function.BooleanSupplier) -> a
            net.minecraft.server.level.ServerLevel -> aaq:
                80:119:void tickWeather() -> a
                120:190:void tick(java.util.function.BooleanSupplier) -> a
            net.minecraft.world.level.block.entity.HopperBlockEntity -> bcu:
                40:95:boolean pushItems(net.minecraft.world.level.Level,net.minecraft.core.BlockPos) -> b
        """.trimIndent()

        val dict = SparkMappingDictionary.parse(proguardText)
        assertEquals(3, dict.mappedClassCount)

        // Line-interval disambiguation on overloaded obfuscated method `a` in `aaq`:
        val weather = dict.deobfuscateFrame("aaq.a(SourceFile:95)")
        assertEquals("net.minecraft.server.level.ServerLevel.tickWeather", weather.qualifiedFrame)
        assertTrue(weather.wasRemapped)

        val levelTick = dict.deobfuscateFrame("aaq.a(SourceFile:144)")
        assertEquals("net.minecraft.server.level.ServerLevel.tick", levelTick.qualifiedFrame)

        // JDK 21 hidden-class lambda with module/classloader prefix + synthetic lambda method:
        val hiddenLambda = dict.deobfuscateFrame("ShopPlugin.jar//com.example.shop.SqlLedger\$\$Lambda/0x0000000801234567.apply(Unknown Source)")
        assertEquals("com.example.shop.SqlLedger.apply", hiddenLambda.qualifiedFrame)
        assertTrue(hiddenLambda.wasLambdaDemangled)

        val synthMethod = dict.deobfuscateFrame("com.example.shop.SqlLedger.lambda\$fetchBalance\$3(SqlLedger.java:91)")
        assertEquals("com.example.shop.SqlLedger.fetchBalance", synthMethod.qualifiedFrame)
        assertTrue(synthMethod.wasLambdaDemangled)

        // Verify StackFrame.parse also preserves package name on JDK 21 hidden-class lambda frames:
        val parsedStackFrame = StackFrame.parse("\tat ShopPlugin.jar//com.example.shop.SqlLedger\$\$Lambda/0x0000000801234567.run(Unknown Source)")
        assertNotNull(parsedStackFrame)
        assertEquals("com.example.shop.SqlLedger", parsedStackFrame!!.className)
        assertEquals("com.example.shop", parsedStackFrame.packageName)

        // Tiny v2 3-namespace (`official`, `intermediary`, `named`) verification:
        val tinyText = buildString {
            appendLine("tiny\t2\t0\tofficial\tintermediary\tnamed")
            appendLine("c\tbcu\tnet/minecraft/class_2614\tnet/minecraft/world/level/block/entity/HopperBlockEntity")
            appendLine("\tm\t(Lnet/minecraft/world/level/Level;)Z\tb\tmethod_11246\tpushItems")
        }
        val tinyDict = SparkMappingDictionary.parse(tinyText)
        assertEquals(
            "net.minecraft.world.level.block.entity.HopperBlockEntity.pushItems",
            tinyDict.deobfuscateFrame("net.minecraft.class_2614.method_11246()").qualifiedFrame,
        )
        assertEquals(
            "net.minecraft.world.level.block.entity.HopperBlockEntity.pushItems",
            tinyDict.deobfuscateFrame("bcu.b()").qualifiedFrame,
        )

        // TSRG v1 verification:
        val tsrgText = buildString {
            appendLine("aaq net/minecraft/server/level/ServerLevel")
            appendLine("\ta (Ljava/util/function/BooleanSupplier;)V tick")
        }
        val tsrgDict = SparkMappingDictionary.parse(tsrgText)
        assertEquals("net.minecraft.server.level.ServerLevel.tick", tsrgDict.deobfuscateFrame("aaq.a()").qualifiedFrame)
    }

    @Test
    fun `spark analyzer classifies obfuscated call-trees with mappings and detects async pool saturation`() {
        val mappingsText = """
            net.minecraft.server.level.ServerLevel -> aaq:
                120:190:void tick(java.util.function.BooleanSupplier) -> a
            net.minecraft.world.level.block.entity.HopperBlockEntity -> bcu:
                40:95:boolean pushItems(net.minecraft.world.level.Level,net.minecraft.core.BlockPos) -> b
        """.trimIndent()
        val dict = SparkMappingDictionary.parse(mappingsText)

        val obfuscatedAndAsyncTree = """
            Server thread 100.00% (5000ms)
              |- net.minecraft.server.MinecraftServer.tickServer() 92.00% (4600ms)
              |  \- aaq.a(SourceFile:150) 44.00% (2200ms)
              |     \- bcu.b(SourceFile:60) 41.50% (2075ms)
            Folia Async Scheduler Thread #1 100.00%
              |- com.example.auth.LoginPool${'$'}${'$'}Lambda/0x0000000801ab00.run() 78.00%
              |  |- com.example.auth.LoginPool.lambda${'$'}verifySession${'$'}1() 78.00%
              |  |  \- com.zaxxer.hikari.pool.HikariPool.getConnection() 76.50%
            Craft Scheduler Thread - 3 100.00%
              \- java.util.concurrent.ThreadPoolExecutor.getTask() 99.20%
                 \- java.util.concurrent.SynchronousQueue.poll() 99.20%
                    \- java.util.concurrent.locks.LockSupport.parkNanos() 99.20%
        """.trimIndent()

        // Without mappings, `bcu.b` looks like an unknown default-package frame and does not classify as Hopper:
        val unmapped = SparkFlamegraphAnalyzer.analyseText("obf", obfuscatedAndAsyncTree)
        assertTrue(unmapped.findings.none { it.ruleId == "L027" && it.detail.contains("Hopper") })

        // With mappings, `bcu.b` deobfuscates to HopperBlockEntity.pushItems (L027) AND Folia Async Hikari starvation fires L032,
        // while idle Craft Scheduler Thread stays silent!
        val mapped = SparkFlamegraphAnalyzer.analyseText("obf", obfuscatedAndAsyncTree, mappings = dict)
        val ids = mapped.findings.map { it.ruleId }.toSet()
        assertTrue("L027" in ids, "expected deobfuscated Hopper L027 in ${mapped.findings}")
        assertTrue("L032" in ids, "expected async pool Hikari saturation L032 in ${mapped.findings}")
        val hopper = mapped.findings.single { it.ruleId == "L027" }
        assertTrue(hopper.detail.contains("HopperBlockEntity.pushItems") && hopper.detail.contains("41.5%"), hopper.detail)
        val asyncHit = mapped.findings.single { it.ruleId == "L032" }
        assertTrue(
            asyncHit.detail.contains("Folia Async Scheduler Thread #1") &&
                asyncHit.detail.contains("HikariPool.getConnection") &&
                asyncHit.detail.contains("com.example.auth"),
            asyncHit.detail,
        )
        assertEquals("2", mapped.facts["frames deobfuscated"])
        assertEquals("2", mapped.facts["lambda frames demangled"])

        // Also test CLI `spark --mappings` and MCP `analyze_spark_profile` `mappings_content`:
        val dir = createTempDirectory("sd-v070")
        try {
            val profFile = dir.resolve("sample.txt").also { it.writeText(obfuscatedAndAsyncTree) }
            val mapFile = dir.resolve("server.txt").also { it.writeText(mappingsText) }
            val outJson = dir.resolve("out.json")
            val cli = ServerDoctorCommand().subcommands(SparkCommand())
            cli.parse(listOf("spark", profFile.toString(), "--mappings", mapFile.toString(), "--json", "-o", outJson.toString(), "--fail-on", "never"))
            val jsonText = outJson.readText()
            assertTrue(jsonText.contains("HopperBlockEntity.pushItems"), jsonText)
            assertTrue(jsonText.contains("\"L032\""), jsonText)

            val mcp = McpServer(ToolCatalog.tools(), "serverdoctor", "0.7.0")
            val escapedProf = obfuscatedAndAsyncTree.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
            val escapedMap = mappingsText.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
            val resp = mcp.handle(
                """{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"analyze_spark_profile","arguments":{"content":"$escapedProf","mappings_content":"$escapedMap"}}}""",
            )!!
            assertTrue(resp.contains("HopperBlockEntity.pushItems"), resp)
            assertTrue(resp.contains("L032"), resp)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun `analyzes folia scheduler thread affinity mismatches and scheduled task faults`() {
        val foliaTraceLog = """
            [13:01:00] [Global Region Scheduler/ERROR]: Thread Global Region Scheduler failed main thread check: Cannot access chunk off-owning region
            java.lang.IllegalStateException: Cannot read block state from GlobalRegionScheduler
            	at ca.spottedleaf.moonrise.common.util.TickThread.ensureTickThread(TickThread.java:62)
            	at net.minecraft.server.level.ServerLevel.getBlockState(ServerLevel.java:418)
            	at com.example.weatherboss.AltarSpawner.checkAltar(AltarSpawner.java:52)
            	at io.papermc.paper.threadedregions.scheduler.FoliaGlobalRegionScheduler${'$'}GlobalScheduledTask.run(FoliaGlobalRegionScheduler.java:178)
            [13:02:10] [Region Scheduler Thread #2/ERROR]: Thread Region Scheduler Thread #2 failed region thread check: Entity is not owned by current region
            java.lang.IllegalStateException: Cannot access entity off-owning region
            	at ca.spottedleaf.moonrise.common.util.TickThread.ensureTickThread(TickThread.java:74)
            	at org.bukkit.craftbukkit.entity.CraftPlayer.teleportAsync(CraftPlayer.java:1120)
            	at com.example.duels.ArenaCountdown.tickArena(ArenaCountdown.java:89)
            	at io.papermc.paper.threadedregions.scheduler.FoliaRegionScheduler${'$'}LocationScheduledTask.run(FoliaRegionScheduler.java:142)
            [13:03:20] [Folia Async Scheduler Thread #0/WARN]: Task #19 for DungeonBosses v2.0.1 generated an exception
            java.lang.NullPointerException: Cannot invoke "String.length()" because "lootTable" is null
            	at com.example.dungeons.LootFetcher.refreshCache(LootFetcher.java:41)
            	at io.papermc.paper.threadedregions.scheduler.FoliaAsyncScheduler${'$'}AsyncScheduledTask.run(FoliaAsyncScheduler.java:211)
            [13:04:05] [Region Scheduler Thread #1/WARN]: ThreadedRegionizer merge across 312 sections exceeded regional split budget
        """.trimIndent()

        val report = triageText(foliaTraceLog)
        val l033 = report.findings.filter { it.ruleId == "L033" }
        assertEquals(2, l033.size, "expected GlobalRegion->chunk and RegionScheduler->entity affinity L033 hits: $l033")
        assertTrue(
            l033.any {
                it.detail.contains("GlobalRegionScheduler") &&
                    it.detail.contains("com.example.weatherboss") &&
                    it.detail.contains("RegionScheduler.execute")
            },
            l033.toString(),
        )
        assertTrue(
            l033.any {
                it.detail.contains("RegionScheduler") &&
                    it.detail.contains("com.example.duels") &&
                    it.detail.contains("entity.getScheduler().run")
            },
            l033.toString(),
        )

        val l034 = report.findings.filter { it.ruleId == "L034" }
        assertEquals(2, l034.size, "expected FoliaAsyncScheduler task exception and ThreadedRegionizer merge L034 hits: $l034")
        assertTrue(l034.any { it.detail.contains("FoliaAsyncScheduler") && it.detail.contains("DungeonBosses") }, l034.toString())
        assertTrue(l034.any { it.detail.contains("ThreadedRegionizer") }, l034.toString())
        assertFalse(report.findings.any { it.ruleId == "L016" }, "Folia task exception should be explained by L034 rather than falling into L016")
    }

    private fun triageText(text: String) = createTempFile(suffix = ".log").let { file ->
        file.writeText(text + "\n")
        try {
            LogTriage().analyse(LogSource.of(file))
        } finally {
            file.toFile().delete()
        }
    }
}
