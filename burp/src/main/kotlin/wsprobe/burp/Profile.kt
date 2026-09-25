// SPDX-License-Identifier: MIT
// wsprobe Burp companion - part of the wsprobe toolkit, MIT licensed.
// See ../../../../README.md and the repository LICENSE.

package wsprobe.burp

/**
 * In-memory mirror of the wsprobe profile contract (profile.schema.json).
 *
 * These types carry only the fields the schema defines. The YAML writer below
 * emits the same minimal shape the Python tool's own emitter produces
 * (pydantic model_dump with exclude_none + exclude_defaults): a field left at
 * its default is omitted, so a drafted file stays small and loads cleanly back
 * into wsprobe, which fills the defaults in again on load.
 *
 * Field defaults mirror the pydantic models:
 *   Handshake.framing      = "json"
 *   MessageMap.type_field  = "type"
 *   MessageMap.correlation_keys = ["cid"]
 *   Auth.*                 = all default (login none, token_location query,
 *                            token_param token, refresh per-dial)
 */

/** Framing enum values from the schema. */
enum class Framing(val wire: String) {
    JSON("json"),
    SOCKETIO("socketio"),
    LENGTH_PREFIXED("length-prefixed"),
    BINARY("binary"),
}

/** 5.1 Handshake: how to open the socket. */
data class Handshake(
    val url: String,
    val query: LinkedHashMap<String, String> = LinkedHashMap(),
    val headers: LinkedHashMap<String, String> = LinkedHashMap(),
    val origin: String? = null,
    val subprotocol: String? = null,
    val framing: Framing = Framing.JSON,
)

/** 5.2 Auth: how a token is acquired, placed, and kept fresh. */
data class Auth(
    val tokenParam: String = "token",       // schema default "token"
    val tokenLocation: String = "query",    // schema default "query"
    // Everything else on the schema's Auth is left at its default and therefore
    // never emitted by a capture-sourced draft; the operator fills login,
    // refresh, and the token source in by hand.
) {
    /** True when this Auth is entirely default and should be omitted from YAML. */
    fun isDefault(): Boolean = tokenParam == "token" && tokenLocation == "query"
}

/** 5.3 Message and opcode map. */
data class MessageMap(
    val typeField: String = "type",
    val correlationKeys: List<String> = listOf("cid"),
    val opcodeNames: LinkedHashMap<String, String> = LinkedHashMap(),
) {
    fun isDefault(): Boolean =
        typeField == "type" && correlationKeys == listOf("cid") && opcodeNames.isEmpty()
}

/** 5.4 Heartbeat suppression. */
data class Heartbeat(
    val types: List<String> = emptyList(),
    val payloads: List<String> = emptyList(),
) {
    fun isDefault(): Boolean = types.isEmpty() && payloads.isEmpty()
}

/** One authoritative socket. */
data class Channel(
    val name: String,
    val handshake: Handshake,
    val auth: Auth = Auth(),
    val messages: MessageMap = MessageMap(),
    val heartbeat: Heartbeat = Heartbeat(),
)

/** A portable, reusable description of one target's WebSocket surface. */
data class Profile(
    val name: String,
    val channels: List<Channel>,
)
