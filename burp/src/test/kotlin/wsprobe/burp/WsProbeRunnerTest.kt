// SPDX-License-Identifier: MIT
// Pure-logic tests for the invocation tier: command building, binary
// resolution, and JSON rendering. No Montoya and no real process, so these run
// under `gradle test` without Burp.

package wsprobe.burp

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WsProbeRunnerTest {

    @Test
    fun `handshake args carry --json and an optional token file`() {
        assertEquals(
            listOf("wsprobe", "handshake", "p.yaml", "--json"),
            WsProbeCli.handshakeArgs("wsprobe", "p.yaml", null),
        )
        assertEquals(
            listOf("wsprobe", "handshake", "p.yaml", "--token-file", "t.tok", "--json"),
            WsProbeCli.handshakeArgs("wsprobe", "p.yaml", "t.tok"),
        )
    }

    @Test
    fun `fuzz args carry the frame, field, values, optional token, and --json`() {
        assertEquals(
            listOf(
                "wsprobe", "fuzz", "p.yaml",
                "--frame", "{\"id\":0}", "--field", "id", "--values", "1,2,3",
                "--json",
            ),
            WsProbeCli.fuzzArgs("wsprobe", "p.yaml", "{\"id\":0}", "id", "1,2,3", null),
        )
        assertEquals(
            listOf(
                "wsprobe", "fuzz", "p.yaml",
                "--frame", "{\"id\":0}", "--field", "id", "--values", "1,2,3",
                "--token-file", "t.tok", "--json",
            ),
            WsProbeCli.fuzzArgs("wsprobe", "p.yaml", "{\"id\":0}", "id", "1,2,3", "t.tok"),
        )
    }

    @Test
    fun `persist args carry the frame and a scripted settle interval`() {
        assertEquals(
            listOf(
                "wsprobe", "persist", "p.yaml",
                "--frame", "{\"type\":\"x\"}", "--settle", "15.0", "--json",
            ),
            WsProbeCli.persistArgs("wsprobe", "p.yaml", "{\"type\":\"x\"}", 15.0, null),
        )
    }

    @Test
    fun `race args always carry --yes because the probe moves state`() {
        val argv = WsProbeCli.raceArgs("wsprobe", "p.yaml", "{\"type\":\"claim\"}", 20, "t.tok")
        assertEquals(
            listOf(
                "wsprobe", "race", "p.yaml",
                "--frame", "{\"type\":\"claim\"}", "--count", "20",
                "--token-file", "t.tok", "--yes", "--json",
            ),
            argv,
        )
        assertTrue("--yes" in argv)
    }

    @Test
    fun `diff args carry the frame, both tokens, and --json`() {
        val argv = WsProbeCli.diffArgs("wsprobe", "p.yaml", """{"type":"read_note","owner":"bob"}""", "a.tok", "b.tok")
        assertEquals(
            listOf(
                "wsprobe", "diff", "p.yaml",
                "--frame", """{"type":"read_note","owner":"bob"}""",
                "--token-a", "a.tok",
                "--token-b", "b.tok",
                "--json",
            ),
            argv,
        )
    }

    @Test
    fun `bridge args carry the frame template and port, no --json`() {
        val argv = WsProbeCli.bridgeArgs("wsprobe", "p.yaml", "{\"q\":\"§FUZZ§\"}", 8081, null)
        assertEquals(
            listOf("wsprobe", "bridge", "p.yaml", "--frame", "{\"q\":\"§FUZZ§\"}", "--port", "8081"),
            argv,
        )
        assertTrue("--json" !in argv)
    }

    @Test
    fun `shell command single-quotes the frame value`() {
        val argv = WsProbeCli.bridgeArgs("wsprobe", "p.yaml", "{\"q\":\"§FUZZ§\"}", 8081, "t.tok")
        val cmd = WsProbeCli.shellCommand(argv)
        assertEquals(
            "wsprobe bridge p.yaml --frame '{\"q\":\"§FUZZ§\"}' --port 8081 --token-file t.tok",
            cmd,
        )
    }

    @Test
    fun `a stored preference that exists wins`() {
        val binary = WsProbeCli.resolveBinary(
            preference = "/venv/bin/wsprobe",
            pathEnv = "/usr/bin${File.pathSeparator}/bin",
            exists = { it == "/venv/bin/wsprobe" },
        )
        assertEquals("/venv/bin/wsprobe", binary)
    }

    @Test
    fun `a missing preference falls back to a PATH lookup`() {
        val binary = WsProbeCli.resolveBinary(
            preference = "/venv/bin/wsprobe", // does not exist
            pathEnv = "/usr/bin${File.pathSeparator}/opt/tools",
            exists = { it == File("/opt/tools", "wsprobe").path },
        )
        assertEquals(File("/opt/tools", "wsprobe").path, binary)
    }

    @Test
    fun `nothing resolvable returns null`() {
        assertNull(WsProbeCli.resolveBinary(null, "/usr/bin${File.pathSeparator}/bin", exists = { false }))
        assertNull(WsProbeCli.resolveBinary("", null, exists = { false }))
    }

    @Test
    fun `renders a matrix payload as a readable table without the word confirmed`() {
        val json = """
            {
              "schema": "wsprobe.matrix/v1",
              "command": "matrix",
              "profile": "drafted-target",
              "channel": "default",
              "observations": [
                {"check": "unauth-upgrade", "observed": "upgraded-without-auth",
                 "reading": "insecure-shape", "detail": {"upgraded": true}},
                {"check": "expired-token", "observed": "rejected",
                 "reading": "control-present", "detail": {"upgraded": false}}
              ]
            }
        """.trimIndent()
        val text = WsProbeRender.render(json)
        assertTrue("matrix  profile=drafted-target  channel=default" in text)
        assertTrue("unauth-upgrade" in text)
        assertTrue("insecure-shape" in text)
        assertTrue("control-present" in text)
        assertTrue("detail:" in text)
        assertTrue("confirmed" !in text.lowercase())
    }

    @Test
    fun `renders a diff payload with the reading and both replies`() {
        val json = """
            {
              "schema": "wsprobe.diff/v1",
              "command": "diff",
              "profile": "drafted-target",
              "channel": "default",
              "frame": {"type": "read_note", "owner": "bob"},
              "identity_a": "alice",
              "identity_b": "bob",
              "reading": "same-across-identities",
              "reply_a": {"type": "note", "content": "x"},
              "reply_b": {"type": "note", "content": "x"}
            }
        """.trimIndent()
        val text = WsProbeRender.render(json)
        assertTrue("reading: same-across-identities" in text)
        assertTrue("alice vs bob" in text)
        assertTrue("reply alice:" in text)
        assertTrue("reply bob:" in text)
        assertTrue("confirmed" !in text.lowercase())
    }

    @Test
    fun `renders a sweep payload with the field and each row`() {
        val json = """
            {
              "schema": "wsprobe.sweep/v1", "command": "sweep",
              "profile": "p", "channel": "default",
              "field": "id", "distinct_replies": 2,
              "rows": [
                {"value": 1001, "frame": {"id": 1001}, "reply": {"type": "note"}},
                {"value": 1002, "frame": {"id": 1002}, "reply": {"type": "error"}}
              ]
            }
        """.trimIndent()
        val text = WsProbeRender.render(json)
        assertTrue("fuzz  profile=p" in text)
        assertTrue("field=id" in text)
        assertTrue("distinct_replies=2" in text)
        assertTrue("1001 ->" in text)
        assertTrue("confirmed" !in text.lowercase())
    }

    @Test
    fun `renders a persist payload with the observed reading`() {
        val json = """
            {
              "schema": "wsprobe.persist/v1", "command": "persist",
              "profile": "p", "channel": "default",
              "observed": "still-served-after-revocation", "reading": "insecure-shape",
              "detail": {"reply_after": {"type": "note"}}
            }
        """.trimIndent()
        val text = WsProbeRender.render(json)
        assertTrue("persist  profile=p" in text)
        assertTrue("still-served-after-revocation" in text)
        assertTrue("insecure-shape" in text)
        assertTrue("confirmed" !in text.lowercase())
    }

    @Test
    fun `renders a race payload with the accepted count`() {
        val json = """
            {
              "schema": "wsprobe.race/v1", "command": "race",
              "profile": "p", "channel": "default",
              "count": 20, "accepted": 7,
              "observed": "multiple-accepted", "reading": "insecure-shape",
              "detail": {"note": "race window"}
            }
        """.trimIndent()
        val text = WsProbeRender.render(json)
        assertTrue("race  profile=p" in text)
        assertTrue("accepted=7/20" in text)
        assertTrue("multiple-accepted" in text)
        assertTrue("confirmed" !in text.lowercase())
    }

    @Test
    fun `non-JSON output is reported, not swallowed`() {
        // A bare scalar parses as a string, not a payload object.
        val text = WsProbeRender.render("command not found")
        assertTrue("not JSON" in text)
    }
}
