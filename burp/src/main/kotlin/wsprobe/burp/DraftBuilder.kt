// SPDX-License-Identifier: MIT
// wsprobe Burp companion - part of the wsprobe toolkit, MIT licensed.

package wsprobe.burp

import org.yaml.snakeyaml.Yaml
import java.net.URI

/**
 * Accumulates one channel's live evidence and drafts a profile from it.
 *
 * The message-map heuristics mirror wsprobe's offline capture analyzer so the
 * profile drafted from live Burp traffic matches what an offline capture
 * analysis of the same frames would produce:
 *   - the type field is the most common of a candidate set seen carrying a
 *     string/number value;
 *   - correlation keys are the two most common of a candidate set (default cid);
 *   - a message type whose name is a known keepalive is a heartbeat, dropped
 *     from the opcode map and recorded under heartbeat.types.
 *
 * The one thing live traffic gives that an offline stub URL cannot is a real
 * handshake: the upgrade URL, Origin, negotiated subprotocol, and - read
 * conservatively - where a token rides in the query string.
 */
class DraftBuilder(private val channelName: String = "default") {

    // Candidate field names, kept identical to the Python analyzer.
    private val typeCandidates = listOf("type", "event", "op", "action", "method", "cmd")
    private val corrCandidates = listOf("cid", "id", "reqId", "requestId", "seq", "correlationId", "nonce")
    private val heartbeatHints = setOf("ping", "pong", "heartbeat", "hb", "keepalive", "2", "3")
    // Query keys that conventionally carry an auth token on a WebSocket upgrade,
    // since browsers forbid an Authorization header on a WebSocket.
    private val tokenQueryHints = listOf("token", "access_token", "accessToken", "jwt", "auth", "authorization", "apikey", "api_key")

    private val yaml = Yaml()

    // Handshake evidence, captured from the first upgrade seen on this channel.
    @Volatile private var url: String? = null
    @Volatile private var origin: String? = null
    @Volatile private var subprotocol: String? = null
    private val queryParams = LinkedHashMap<String, String>()

    // Frame evidence.
    private val typeFieldVotes = HashMap<String, Int>()
    private val corrVotes = HashMap<String, Int>()
    private val typeCounts = HashMap<String, Int>()   // non-heartbeat message types
    private val heartbeatTypes = LinkedHashSet<String>()
    private var sawSocketIo = false
    @Volatile private var frameCount = 0
    @Volatile private var droppedHeartbeats = 0

    fun frames(): Int = frameCount
    fun dropped(): Int = droppedHeartbeats

    /** Record the handshake (upgrade request) for this channel. */
    @Synchronized
    fun observeHandshake(rawUrl: String?, headerOrigin: String?, negotiatedSubprotocol: String?) {
        if (url == null && rawUrl != null) {
            url = normalizeWsUrl(rawUrl)
            parseQuery(rawUrl)
        }
        if (origin == null && !headerOrigin.isNullOrBlank()) origin = headerOrigin
        if (subprotocol == null && !negotiatedSubprotocol.isNullOrBlank()) subprotocol = negotiatedSubprotocol
    }

    /**
     * Record one text frame. Returns true if the frame was classified as a
     * heartbeat, so the caller can annotate it in the WebSocket history.
     */
    @Synchronized
    fun observeText(payload: String): Boolean {
        frameCount++
        val trimmed = payload.trim()

        // Engine.IO / Socket.IO bare ping/pong frames are "2"/"3".
        if (trimmed == "2" || trimmed == "3") {
            sawSocketIo = true
            heartbeatTypes.add(trimmed)
            droppedHeartbeats++
            return true
        }
        if (trimmed.isNotEmpty() && trimmed[0].isDigit() && (trimmed.contains('[') || trimmed.contains('{'))) {
            sawSocketIo = true
        }

        val map = parseObject(payload) ?: return false

        // Vote for a type field, then read the type value with it.
        for (cand in typeCandidates) {
            val v = map[cand]
            if (v is String || v is Number) typeFieldVotes.merge(cand, 1, Int::plus)
        }
        val typeField = currentTypeField()
        for (cand in corrCandidates) {
            if (cand == typeField) continue
            if (map.containsKey(cand)) corrVotes.merge(cand, 1, Int::plus)
        }

        val typeVal = map[typeField]?.toString()
        if (typeVal != null && typeVal.lowercase() in heartbeatHints) {
            heartbeatTypes.add(typeVal)
            droppedHeartbeats++
            return true
        }
        if (typeVal != null) typeCounts.merge(typeVal, 1, Int::plus)
        return false
    }

    /** Whether anything at all has been observed yet. */
    @Synchronized
    fun hasEvidence(): Boolean = url != null || frameCount > 0

    /** Build the draft profile from everything observed so far. */
    @Synchronized
    fun build(profileName: String): Profile {
        val typeField = currentTypeField()
        val corrKeys = corrVotes.entries.sortedByDescending { it.value }.take(2).map { it.key }
            .ifEmpty { listOf("cid") }
        val opcodes = LinkedHashMap<String, String>()
        for (t in typeCounts.keys.sorted()) opcodes[t] = t

        val handshakeUrl = url ?: "wss://ws.example.test/socket" // stub, matches the offline emitter
        val handshake = Handshake(
            url = handshakeUrl,
            headers = LinkedHashMap(),
            origin = origin,
            subprotocol = subprotocol,
            framing = if (sawSocketIo) Framing.SOCKETIO else Framing.JSON,
        )

        // Conservative auth inference: only when the upgrade URL query names a
        // conventional token key. Anything richer (login recipe, refresh
        // policy, header/subprotocol token) stays for the operator to fill in.
        var auth = Auth()
        for (hint in tokenQueryHints) {
            val match = queryParams.keys.firstOrNull { it.equals(hint, ignoreCase = true) }
            if (match != null) { auth = Auth(tokenParam = match, tokenLocation = "query"); break }
        }

        val messages = MessageMap(
            typeField = typeField,
            correlationKeys = corrKeys,
            opcodeNames = opcodes,
        )
        val heartbeat = Heartbeat(types = heartbeatTypes.toList())

        val channel = Channel(
            name = channelName,
            handshake = handshake,
            auth = auth,
            messages = messages,
            heartbeat = heartbeat,
        )
        return Profile(name = profileName, channels = listOf(channel))
    }

    private fun currentTypeField(): String =
        typeFieldVotes.entries.maxByOrNull { it.value }?.key ?: "type"

    @Suppress("UNCHECKED_CAST")
    private fun parseObject(payload: String): Map<String, Any?>? {
        return try {
            val loaded = yaml.load<Any?>(payload) // YAML is a JSON superset; parses JSON objects
            if (loaded is Map<*, *>) loaded as Map<String, Any?> else null
        } catch (_: Exception) {
            null
        }
    }

    private fun normalizeWsUrl(raw: String): String {
        val u = raw.trim()
        return when {
            u.startsWith("ws://") || u.startsWith("wss://") -> u
            u.startsWith("http://") -> "ws://" + u.removePrefix("http://")
            u.startsWith("https://") -> "wss://" + u.removePrefix("https://")
            else -> u
        }
    }

    private fun parseQuery(raw: String) {
        try {
            val q = URI(raw).rawQuery ?: return
            for (pair in q.split("&")) {
                if (pair.isEmpty()) continue
                val idx = pair.indexOf('=')
                val k = if (idx >= 0) pair.substring(0, idx) else pair
                val v = if (idx >= 0) pair.substring(idx + 1) else ""
                queryParams[urlDecode(k)] = urlDecode(v)
            }
        } catch (_: Exception) {
            // A malformed URL just means no query evidence; the draft still builds.
        }
    }

    private fun urlDecode(s: String): String =
        try { java.net.URLDecoder.decode(s, Charsets.UTF_8) } catch (_: Exception) { s }
}
