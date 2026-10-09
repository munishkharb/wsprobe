// SPDX-License-Identifier: MIT
// wsprobe Burp companion - part of the wsprobe toolkit, MIT licensed.

package wsprobe.burp

import org.yaml.snakeyaml.Yaml
import java.math.BigDecimal

/**
 * One observed frame, in the shape wsprobe's own NDJSON capture uses.
 */
data class CapturedFrame(val ts: Double, val direction: String, val channel: String, val frame: Any?)

/**
 * Turn the frames Burp has already proxied into a wsprobe NDJSON capture, so
 * `wsprobe analyze` (and every offline-driven capability) can run from
 * Burp-observed traffic - the history-import path, without an export file
 * format in between.
 *
 * The output matches wsprobe's own capture reader (capture.py `_from_native`):
 * one JSON object per line, {ts, direction, channel, frame}. Secrets are
 * redacted on write with the same best-effort name pattern the Python
 * CaptureWriter uses, so a token sitting in a frame field is not written in
 * cleartext. It is best-effort, not a guarantee: treat captures as sensitive.
 *
 * Kept free of Montoya and Swing so the redaction and JSON encoding are
 * unit-tested without Burp.
 */
object CaptureCodec {

    const val SEND = "send"
    const val RECV = "recv"

    // Matches src/wsprobe/capture.py `_SECRET_KEYS`.
    private val secretKeys = Regex("(token|password|passwd|secret|authorization|api[_-]?key|cookie)", RegexOption.IGNORE_CASE)
    private const val MASK = "[redacted]"

    private val yaml = Yaml()

    /** Parse a text payload as JSON (YAML is a JSON superset). A payload that is
     *  not an object or list is kept as the raw string, so nothing is lost. */
    fun parseFrame(payload: String): Any? =
        try {
            yaml.load<Any?>(payload) ?: payload
        } catch (_: Exception) {
            payload
        }

    /** Recursively mask dict values whose key looks like a credential. */
    fun redact(value: Any?): Any? = when (value) {
        is Map<*, *> -> {
            val out = LinkedHashMap<Any?, Any?>()
            for ((k, v) in value) {
                out[k] = if (k is String && secretKeys.containsMatchIn(k)) MASK else redact(v)
            }
            out
        }
        is List<*> -> value.map { redact(it) }
        else -> value
    }

    /** Render frames as NDJSON, one {ts, direction, channel, frame} per line,
     *  redacted. */
    fun toNdjson(frames: List<CapturedFrame>): String {
        val sb = StringBuilder()
        for (f in frames) {
            val obj = linkedMapOf<String, Any?>(
                "ts" to round6(f.ts),
                "direction" to f.direction,
                "channel" to f.channel,
                "frame" to redact(f.frame),
            )
            sb.append(encode(obj)).append('\n')
        }
        return sb.toString()
    }

    private fun round6(d: Double): BigDecimal =
        BigDecimal.valueOf(d).setScale(6, java.math.RoundingMode.HALF_UP).stripTrailingZeros()

    /** A minimal, compact JSON encoder for the value types SnakeYAML produces
     *  (Map, List, String, Boolean, Number, null) plus BigDecimal. */
    fun encode(value: Any?): String = when (value) {
        null -> "null"
        is String -> encodeString(value)
        is Boolean -> value.toString()
        is BigDecimal -> value.toPlainString()
        is Double, is Float -> BigDecimal.valueOf((value as Number).toDouble()).toPlainString()
        is Number -> value.toString()
        is Map<*, *> -> value.entries.joinToString(",", "{", "}") { (k, v) ->
            encodeString(k.toString()) + ":" + encode(v)
        }
        is List<*> -> value.joinToString(",", "[", "]") { encode(it) }
        else -> encodeString(value.toString())
    }

    private fun encodeString(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) {
            when (c) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        return sb.append('"').toString()
    }
}
