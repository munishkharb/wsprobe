// SPDX-License-Identifier: MIT
// Pure tests for the capture export: redaction, JSON encoding, and the NDJSON
// shape wsprobe's own reader expects. No Montoya, no Burp.

package wsprobe.burp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CaptureTest {

    @Test
    fun `redacts credential-looking fields recursively`() {
        val frame = mapOf(
            "type" to "login",
            "token" to "secret123",
            "nested" to mapOf("password" to "p", "ok" to 1),
        )
        val red = CaptureCodec.redact(frame) as Map<*, *>
        assertEquals("[redacted]", red["token"])
        assertEquals("login", red["type"])
        val nested = red["nested"] as Map<*, *>
        assertEquals("[redacted]", nested["password"])
        assertEquals(1, nested["ok"])
    }

    @Test
    fun `encodes compact json with string escaping`() {
        val encoded = CaptureCodec.encode(linkedMapOf("a" to 1, "b" to "x\"y", "c" to listOf(true, null)))
        assertEquals("""{"a":1,"b":"x\"y","c":[true,null]}""", encoded)
    }

    @Test
    fun `ndjson carries ts direction channel and a redacted frame per line`() {
        val frames = listOf(
            CapturedFrame(1.0, CaptureCodec.SEND, "default", mapOf("type" to "login", "token" to "abc")),
            CapturedFrame(2.5, CaptureCodec.RECV, "default", mapOf("type" to "ok")),
        )
        val lines = CaptureCodec.toNdjson(frames).trim().split("\n")
        assertEquals(2, lines.size)
        assertTrue(""""direction":"send"""" in lines[0])
        assertTrue(""""channel":"default"""" in lines[0])
        assertTrue("[redacted]" in lines[0])
        assertTrue("abc" !in lines[0]) // the token value never reaches the file
        assertTrue(""""direction":"recv"""" in lines[1])
    }

    @Test
    fun `a bare text payload is kept, never dropped`() {
        assertEquals("hello", CaptureCodec.parseFrame("hello"))
        val line = CaptureCodec.toNdjson(listOf(CapturedFrame(1.0, "recv", "default", "hello"))).trim()
        assertTrue(""""frame":"hello"""" in line)
    }
}
