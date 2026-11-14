package com.salyvn.serverdoctor.mcp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * The slice of JSON-RPC 2.0 that MCP over stdio needs.
 *
 * Framing is newline-delimited JSON - one object per line, no `Content-Length` headers - and nothing
 * except protocol messages may be written to stdout. Both rules come from the MCP stdio transport
 * specification, so everything this tool would otherwise print goes to stderr while it is serving.
 */
internal object JsonRpc {

    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
    }

    const val PARSE_ERROR = -32700
    const val METHOD_NOT_FOUND = -32601
    const val INVALID_PARAMS = -32602

    data class Incoming(val id: JsonElement?, val method: String, val params: JsonObject) {
        /** A message without an id is a notification, and a notification is never answered. */
        val isNotification: Boolean get() = id == null || id is JsonNull
    }

    fun parse(line: String): Result<Incoming> = runCatching {
        val root = json.parseToJsonElement(line) as? JsonObject
            ?: throw IllegalArgumentException("top-level value is not an object")
        val method = (root["method"] as? JsonPrimitive)?.content
            ?: throw IllegalArgumentException("no method")
        Incoming(
            id = root["id"],
            method = method,
            params = root["params"] as? JsonObject ?: JsonObject(emptyMap()),
        )
    }

    fun result(id: JsonElement?, result: JsonObject): String = buildJsonObject {
        put("jsonrpc", "2.0")
        put("id", id ?: JsonNull)
        put("result", result)
    }.toString()

    fun error(id: JsonElement?, code: Int, message: String): String = buildJsonObject {
        put("jsonrpc", "2.0")
        put("id", id ?: JsonNull)
        put(
            "error",
            buildJsonObject {
                put("code", code)
                put("message", message)
            },
        )
    }.toString()
}
