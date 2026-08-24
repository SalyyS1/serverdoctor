package com.salyvn.serverdoctor

import com.salyvn.serverdoctor.core.RuleCatalog
import com.salyvn.serverdoctor.mcp.McpServer
import com.salyvn.serverdoctor.mcp.ToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class McpServerTest {

    private val server = McpServer(ToolCatalog.tools(), "serverdoctor", "test")

    @Test
    fun `answers the handshake with the version the client asked for`() {
        val response = server.handle(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"""
        )
        assertTrue(response!!.contains("\"protocolVersion\":\"2025-06-18\""), response)
        assertTrue(response.contains("\"serverInfo\""))
    }

    @Test
    fun `falls back to its own revision for an unknown one`() {
        val response = server.handle(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"""
        )
        assertTrue(response!!.contains("\"protocolVersion\":\"${McpServer.PROTOCOL_VERSION}\""), response)
    }

    @Test
    fun `lists every tool as read-only`() {
        val response = server.handle("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""")!!
        for (tool in ToolCatalog.tools()) assertTrue(response.contains("\"${tool.name}\""), tool.name)
        assertTrue(response.contains("\"readOnlyHint\":true"))
    }

    @Test
    fun `never answers a notification`() {
        assertNull(server.handle("""{"jsonrpc":"2.0","method":"notifications/initialized"}"""))
        assertNull(server.handle(""))
    }

    @Test
    fun `rejects an unknown method instead of guessing`() {
        val response = server.handle("""{"jsonrpc":"2.0","id":9,"method":"resources/list"}""")!!
        assertTrue(response.contains("-32601"), response)
    }

    @Test
    fun `turns malformed input into a parse error rather than a crash`() {
        val response = server.handle("this is not json")!!
        assertTrue(response.contains("-32700"), response)
    }

    @Test
    fun `a failed tool call comes back as content, not as a protocol error`() {
        val response = server.handle(
            """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"triage_log","arguments":{"path":"/nope/latest.log"}}}"""
        )!!
        assertTrue(response.contains("\"isError\":true"), response)
        assertTrue(response.contains("not found"), response)
    }

    @Test
    fun `triages a real log through the tool surface`() {
        val path = TestFixtures.path("/logs/broken-paper-server.log").toString().replace("\\", "\\\\")
        val response = server.handle(
            """{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"triage_log","arguments":{"path":"$path"}}}"""
        )!!
        assertTrue(response.contains("L001"), "the watchdog finding should reach the agent")
        assertTrue(response.contains("\"isError\":false"))
    }

    @Test
    fun `the rule catalogue has unique ids and no empty provenance`() {
        val rules = RuleCatalog.all
        assertEquals(rules.size, rules.map { it.id }.toSet().size, "duplicate rule ids")
        for (rule in rules) {
            assertTrue(rule.provenance.isNotBlank(), "${rule.id} has no source")
            assertTrue(rule.rationale.length > 40, "${rule.id} explains too little")
        }
    }
}
