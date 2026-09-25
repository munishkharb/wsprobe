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
    fun `matrix args carry --json and an optional token file`() {
        assertEquals(
            listOf("wsprobe", "matrix", "p.yaml", "--json"),
            WsProbeCli.matrixArgs("wsprobe", "p.yaml", null),
        )
        assertEquals(
            listOf("wsprobe", "matrix", "p.yaml", "--token-file", "t.tok", "--json"),
            WsProbeCli.matrixArgs("wsprobe", "p.yaml", "t.tok"),
        )
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
    fun `non-JSON output is reported, not swallowed`() {
        // A bare scalar parses as a string, not a payload object.
        val text = WsProbeRender.render("command not found")
        assertTrue("not JSON" in text)
    }
}
