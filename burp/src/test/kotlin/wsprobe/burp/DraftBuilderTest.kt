// SPDX-License-Identifier: MIT
// Pure-logic tests for the draft builder and YAML writer. No Montoya needed,
// so these run under `gradle test` without Burp.

package wsprobe.burp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DraftBuilderTest {

    @Test
    fun `drafts message map and heartbeats from observed frames`() {
        val b = DraftBuilder()
        b.observeHandshake("wss://ws.example.test/socket?token=abc", "https://app.example.test", null)
        b.observeText("""{"type":"whoami","cid":1}""")
        b.observeText("""{"type":"whoami","cid":1,"user":"a"}""")
        b.observeText("""{"type":"read_note","cid":2,"id":9}""")
        assertTrue(b.observeText("""{"type":"ping"}"""))   // heartbeat -> true
        assertTrue(b.observeText("2"))                      // engine.io ping -> true

        val p = b.build("drafted-target")
        val ch = p.channels.single()
        assertEquals("type", ch.messages.typeField)
        assertTrue(ch.messages.opcodeNames.keys.containsAll(setOf("whoami", "read_note")))
        assertTrue("ping" in ch.heartbeat.types)
        assertTrue("2" in ch.heartbeat.types)
        // cid is the most common correlation key.
        assertEquals("cid", ch.messages.correlationKeys.first())
        // Live handshake evidence the offline stub cannot supply.
        assertEquals("wss://ws.example.test/socket?token=abc", ch.handshake.url)
        assertEquals("https://app.example.test", ch.handshake.origin)
        // token=... in the query is inferred as query-located auth.
        assertEquals("token", ch.auth.tokenParam)
    }

    @Test
    fun `yaml omits defaults and round-trips the required shape`() {
        val b = DraftBuilder()
        b.observeHandshake("wss://ws.example.test/socket", null, "graphql-ws")
        b.observeText("""{"event":"sub","reqId":"r1"}""")
        b.observeText("""{"event":"data","reqId":"r1"}""")
        val yaml = YamlWriter.toYaml(b.build("t"))

        // Required top-level keys are present.
        assertTrue(yaml.startsWith("name: t\n"))
        assertTrue("channels:" in yaml)
        assertTrue("- name: default" in yaml)
        assertTrue("url: wss://ws.example.test/socket" in yaml)
        assertTrue("subprotocol: graphql-ws" in yaml)
        // type_field was voted "event", so it is emitted (non-default).
        assertTrue("type_field: event" in yaml)
        // auth is fully default here, so it is omitted.
        assertTrue("auth:" !in yaml)
    }

    @Test
    fun `heartbeat-only default heartbeat block is omitted`() {
        val b = DraftBuilder()
        b.observeHandshake("wss://ws.example.test/s", null, null)
        b.observeText("""{"type":"hello","cid":"1"}""")
        val yaml = YamlWriter.toYaml(b.build("t"))
        assertTrue("heartbeat:" !in yaml) // no keepalives seen -> block omitted
    }
}
