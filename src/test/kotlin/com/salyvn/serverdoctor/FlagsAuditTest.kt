package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.flags.FlagsAudit
import com.salyvn.serverdoctor.flags.JvmCommandLine
import com.salyvn.serverdoctor.flags.StartScriptReader
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FlagsAuditTest {

    @Test
    fun `parses heap sizes, toggles and system properties`() {
        val command = JvmCommandLine.parse(
            "/usr/bin/java -Xms4G -Xmx4096M -XX:+UseG1GC -XX:MaxGCPauseMillis=200 " +
                "-Dfile.encoding=UTF-8 -jar paper.jar --nogui",
        )
        assertEquals(4L * 1024 * 1024 * 1024, command.initialHeapBytes)
        assertEquals(4L * 1024 * 1024 * 1024, command.maxHeapBytes)
        assertEquals(true, command.toggle("UseG1GC"))
        assertEquals("200", command.flag("MaxGCPauseMillis"))
        assertEquals("UTF-8", command.systemProperties["file.encoding"])
        assertEquals("paper.jar", command.jarPath)
        assertEquals(listOf("--nogui"), command.applicationArguments)
    }

    @Test
    fun `keeps quoted paths in one token`() {
        val tokens = JvmCommandLine.tokenize("\"C:\\Program Files\\Java\\bin\\java.exe\" -Xmx2G -jar \"my server.jar\"")
        assertEquals("C:\\Program Files\\Java\\bin\\java.exe", tokens.first())
        assertTrue(tokens.contains("my server.jar"))
    }

    @Test
    fun `pulls the java line out of a wrapped start script`() {
        val extracted = StartScriptReader.readCommand(TestFixtures.path("/server/start.sh"))
        assertNotNull(extracted)
        assertTrue(extracted!!.startsWith("java "), extracted)
        assertTrue(extracted.contains("-jar paper.jar"), extracted)
    }

    @Test
    fun `reports the real defects in the fixture script`() {
        val command = JvmCommandLine.parse(StartScriptReader.readCommand(TestFixtures.path("/server/start.sh"))!!)
        val ids = FlagsAudit(16L * 1024 * 1024 * 1024).analyse("start.sh", command).findings.map { it.ruleId }
        assertTrue("F003" in ids, "the watchdog kill switch must be critical: $ids")
        assertTrue("F001" in ids, "-Xms 2G against -Xmx 14G: $ids")
        assertTrue("F005" in ids, "three collectors selected: $ids")
        assertTrue("F006" in ids, "CMS flags on a modern JVM: $ids")
        assertTrue("F004" in ids, "eula accepted by flag: $ids")
    }

    @Test
    fun `a documented flag set produces no warnings`() {
        val aikars = "java -Xms10G -Xmx10G -XX:+UseG1GC -XX:+ParallelRefProcEnabled " +
            "-XX:MaxGCPauseMillis=200 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC " +
            "-XX:+AlwaysPreTouch -XX:G1NewSizePercent=30 -XX:G1MaxNewSizePercent=40 " +
            "-XX:G1HeapRegionSize=8M -XX:G1ReservePercent=20 -XX:G1HeapWastePercent=5 " +
            "-XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=15 " +
            "-XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 " +
            "-XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1 " +
            "-jar paper.jar --nogui"
        val report = FlagsAudit(32L * 1024 * 1024 * 1024).analyse("aikar", JvmCommandLine.parse(aikars))
        assertTrue(report.findings.isEmpty(), "expected nothing to report, got ${report.findings.map { it.ruleId }}")
    }

    @Test
    fun `MaxRAMPercentage counts as sizing the heap`() {
        val command = JvmCommandLine.parse("java -XX:MaxRAMPercentage=75 -jar paper.jar")
        val ids = FlagsAudit().analyse("container", command).findings.map { it.ruleId }
        assertFalse("F002" in ids, "a container heap is sized, just not with -Xmx: $ids")
    }

    @Test
    fun `says so instead of guessing when there is no java command`() {
        val ids = FlagsAudit().analyse("empty", null).findings.map { it.ruleId }
        assertEquals(listOf("F012"), ids)
    }
}
