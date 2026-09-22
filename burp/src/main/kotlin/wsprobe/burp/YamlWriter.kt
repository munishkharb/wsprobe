// SPDX-License-Identifier: MIT
// wsprobe Burp companion — part of the wsprobe toolkit, MIT licensed.

package wsprobe.burp

/**
 * Hand-written YAML writer for the wsprobe profile.
 *
 * It is deliberately hand-rolled rather than delegated to a generic dumper so
 * the output matches the exact minimal shape wsprobe's own emitter produces:
 * two-space indent, block sequences, and every field left at its schema default
 * omitted. The result round-trips through wsprobe's pydantic loader, which
 * restores the omitted defaults.
 */
object YamlWriter {

    fun toYaml(profile: Profile): String {
        val sb = StringBuilder()
        sb.append("name: ").append(scalar(profile.name)).append('\n')
        sb.append("channels:\n")
        for (ch in profile.channels) {
            channel(sb, ch)
        }
        return sb.toString()
    }

    private fun channel(sb: StringBuilder, ch: Channel) {
        // Sequence item: first key sits on the dash line, rest indented to match.
        sb.append("- name: ").append(scalar(ch.name)).append('\n')
        val i = "  " // indent for keys under this list item

        // handshake (always present; url is required)
        sb.append(i).append("handshake:\n")
        val h = ch.handshake
        sb.append(i).append("  url: ").append(scalar(h.url)).append('\n')
        if (h.query.isNotEmpty()) {
            sb.append(i).append("  query:\n")
            for ((k, v) in h.query) sb.append(i).append("    ").append(scalar(k)).append(": ").append(scalar(v)).append('\n')
        }
        if (h.headers.isNotEmpty()) {
            sb.append(i).append("  headers:\n")
            for ((k, v) in h.headers) sb.append(i).append("    ").append(scalar(k)).append(": ").append(scalar(v)).append('\n')
        }
        if (h.origin != null) sb.append(i).append("  origin: ").append(scalar(h.origin)).append('\n')
        if (h.subprotocol != null) sb.append(i).append("  subprotocol: ").append(scalar(h.subprotocol)).append('\n')
        if (h.framing != Framing.JSON) sb.append(i).append("  framing: ").append(scalar(h.framing.wire)).append('\n')

        // auth (omitted entirely when default)
        if (!ch.auth.isDefault()) {
            sb.append(i).append("auth:\n")
            val a = ch.auth
            if (a.tokenLocation != "query") sb.append(i).append("  token_location: ").append(scalar(a.tokenLocation)).append('\n')
            if (a.tokenParam != "token") sb.append(i).append("  token_param: ").append(scalar(a.tokenParam)).append('\n')
        }

        // messages (omitted when fully default; individual fields omitted when default)
        if (!ch.messages.isDefault()) {
            sb.append(i).append("messages:\n")
            val m = ch.messages
            if (m.typeField != "type") sb.append(i).append("  type_field: ").append(scalar(m.typeField)).append('\n')
            if (m.correlationKeys != listOf("cid")) {
                sb.append(i).append("  correlation_keys:\n")
                for (k in m.correlationKeys) sb.append(i).append("  - ").append(scalar(k)).append('\n')
            }
            if (m.opcodeNames.isNotEmpty()) {
                sb.append(i).append("  opcode_names:\n")
                for ((k, v) in m.opcodeNames) sb.append(i).append("    ").append(scalar(k)).append(": ").append(scalar(v)).append('\n')
            }
        }

        // heartbeat (omitted when empty)
        if (!ch.heartbeat.isDefault()) {
            sb.append(i).append("heartbeat:\n")
            val hb = ch.heartbeat
            if (hb.types.isNotEmpty()) {
                sb.append(i).append("  types:\n")
                for (t in hb.types) sb.append(i).append("  - ").append(scalar(t)).append('\n')
            }
            if (hb.payloads.isNotEmpty()) {
                sb.append(i).append("  payloads:\n")
                for (p in hb.payloads) sb.append(i).append("  - ").append(scalar(p)).append('\n')
            }
        }
    }

    /**
     * Quote a scalar only when YAML would otherwise misread it. Keeps the
     * common case (plain identifiers and ws:// URLs) unquoted like the Python
     * emitter, and double-quotes anything with structural characters, a leading
     * indicator, or a value YAML would coerce to a non-string.
     */
    private fun scalar(raw: String): String {
        if (raw.isEmpty()) return "\"\""
        val needsQuote =
            raw != raw.trim() ||
            raw.first() in ":#&*!|>%@`\"'?-{}[]," ||
            raw.contains(": ") || raw.endsWith(":") ||
            raw.contains(" #") ||
            raw.any { it == '\n' || it == '\t' } ||
            looksNonString(raw)
        if (!needsQuote) return raw
        val esc = raw.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\t", "\\t")
        return "\"$esc\""
    }

    private fun looksNonString(s: String): Boolean {
        val low = s.lowercase()
        if (low in setOf("true", "false", "null", "yes", "no", "on", "off", "~")) return true
        if (s.toLongOrNull() != null) return true
        if (s.toDoubleOrNull() != null) return true
        return false
    }
}
