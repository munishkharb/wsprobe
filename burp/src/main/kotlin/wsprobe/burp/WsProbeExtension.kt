// SPDX-License-Identifier: MIT
// wsprobe Burp companion - part of the wsprobe toolkit, MIT licensed.
// No target and no default host. Ships nothing to point at.

package wsprobe.burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage
import burp.api.montoya.proxy.websocket.InterceptedTextMessage
import burp.api.montoya.proxy.websocket.ProxyMessageHandler
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction
import java.awt.BorderLayout
import java.awt.Font
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import javax.swing.JComponent
import javax.swing.JFileChooser
import javax.swing.JMenu
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities

/**
 * wsprobe Burp companion.
 *
 * P0: watch the WebSocket handshakes and frames Burp already proxies and, on
 * demand, emit a draft profile.yaml in the exact shape wsprobe loads
 * (profile.schema.json). Second job: mark keepalive frames in the WebSocket
 * history so they can be filtered out of a busy socket.
 *
 * It opens no socket of its own and sends nothing. It only reads traffic Burp
 * has already captured and writes one YAML file where the operator chooses.
 */
class WsProbeExtension : BurpExtension {

    private lateinit var api: MontoyaApi

    // One draft builder per distinct socket (scheme+host+path, query stripped),
    // so a target that runs several sockets drafts one channel each.
    private val builders = ConcurrentHashMap<String, DraftBuilder>()
    private val channelOrder = ArrayList<String>()

    // The last profile this session drafted, offered as the default when the
    // operator runs wsprobe against "the profile the companion drafted".
    @Volatile private var lastDraftPath: Path? = null

    // Every text frame observed, in wsprobe's NDJSON capture shape, so the
    // operator can export Burp-seen traffic and drive the offline capabilities
    // (analyze, replay) from it - the history-import path.
    private val capturedFrames = ConcurrentLinkedQueue<CapturedFrame>()

    // The results tab: rendered output of each Run wsprobe invocation.
    private val results = JTextArea().apply {
        isEditable = false
        lineWrap = false
        font = Font(Font.MONOSPACED, Font.PLAIN, 12)
        text = "wsprobe results\n\nRun wsprobe from the wsprobe menu to drive the CLI against a profile.\n"
    }

    private val processRunner = ProcessRunner()

    override fun initialize(api: MontoyaApi) {
        this.api = api
        api.extension().setName("wsprobe companion")

        api.proxy().registerWebSocketCreationHandler(CreationHandler())
        api.userInterface().registerSuiteTab("wsprobe", resultsComponent())
        registerMenu()

        api.logging().logToOutput(
            "wsprobe companion loaded. Proxy WebSocket traffic, then " +
                "wsprobe > Write draft profile.yaml to emit a profile. " +
                "Run wsprobe > Handshake / Two-account diff / Field sweep / " +
                "Session persistence / Race drives the CLI and shows the " +
                "observations in the wsprobe tab. " +
                "Keepalive frames are marked gray with a 'wsprobe: heartbeat' note."
        )
    }

    private fun resultsComponent(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.add(JScrollPane(results), BorderLayout.CENTER)
        return panel
    }

    // ---- handshake + frame observation -------------------------------------

    private inner class CreationHandler : ProxyWebSocketCreationHandler {
        override fun handleWebSocketCreation(creation: ProxyWebSocketCreation) {
            val req = creation.upgradeRequest()
            val fullUrl = try { req.url() } catch (_: Exception) { null }
            val origin = try { req.headerValue("Origin") } catch (_: Exception) { null }
            val subprotocol = try { req.headerValue("Sec-WebSocket-Protocol") } catch (_: Exception) { null }

            val key = channelKey(fullUrl)
            val builder = builderFor(key, fullUrl)
            builder.observeHandshake(fullUrl, origin, subprotocol)

            creation.proxyWebSocket().registerProxyMessageHandler(MessageHandler(builder, key))
        }
    }

    private inner class MessageHandler(
        private val builder: DraftBuilder,
        private val channel: String,
    ) : ProxyMessageHandler {
        override fun handleTextMessageReceived(message: InterceptedTextMessage): TextMessageReceivedAction {
            val isHeartbeat = try { builder.observeText(message.payload()) } catch (_: Exception) { false }
            recordFrame(CaptureCodec.RECV, message.payload())
            if (isHeartbeat) {
                // Heartbeat filter: mark keepalives so they can be filtered in
                // the WebSocket history. Montoya has no "hide from history" API,
                // so a distinct color + note is the honest equivalent - the
                // operator filters or sorts on it. The frame is not dropped.
                try {
                    message.annotations().setHighlightColor(HighlightColor.GRAY)
                    message.annotations().setNotes("wsprobe: heartbeat")
                } catch (_: Exception) {
                    // Annotation is best-effort; observation already succeeded.
                }
            }
            return TextMessageReceivedAction.continueWith(message)
        }

        override fun handleBinaryMessageReceived(message: InterceptedBinaryMessage): BinaryMessageReceivedAction {
            // Binary framing is profile-declared, not inferred here; pass through.
            return BinaryMessageReceivedAction.continueWith(message)
        }

        // Outbound (client-to-server) frames: the extension is read-only on the
        // wire and drafts from received traffic, so these pass straight through
        // unaltered. Implemented because ProxyMessageHandler requires them.
        override fun handleTextMessageToBeSent(message: InterceptedTextMessage): TextMessageToBeSentAction {
            recordFrame(CaptureCodec.SEND, message.payload())
            return TextMessageToBeSentAction.continueWith(message)
        }

        override fun handleBinaryMessageToBeSent(message: InterceptedBinaryMessage): BinaryMessageToBeSentAction {
            return BinaryMessageToBeSentAction.continueWith(message)
        }

        /** Record one text frame for the capture export. Best-effort: a parse or
         *  enqueue failure never disturbs the proxied traffic. */
        private fun recordFrame(direction: String, payload: String) {
            try {
                val ts = System.currentTimeMillis() / 1000.0
                capturedFrames.add(CapturedFrame(ts, direction, channel, CaptureCodec.parseFrame(payload)))
            } catch (_: Exception) {
                // Capture is a convenience; never let it affect the wire.
            }
        }
    }

    // ---- draft emission ----------------------------------------------------

    private fun registerMenu() {
        // A Swing JMenu, because the Montoya Menu has no submenu nesting and the
        // Run actions read best as a "Run wsprobe" submenu. registerMenu accepts
        // a JMenu directly.
        val menu = JMenu("wsprobe")

        menu.add(item("Write draft profile.yaml") { writeDraft() })
        menu.add(item("Write capture.ndjson") { writeCapture() })
        menu.add(item("Reset observed traffic") {
            builders.clear()
            synchronized(channelOrder) { channelOrder.clear() }
            capturedFrames.clear()
            api.logging().logToOutput("wsprobe companion: observed traffic reset.")
        })

        menu.addSeparator()
        val run = JMenu("Run wsprobe")
        run.add(item("Handshake") { runHandshake() })
        run.add(item("Two-account diff") { runDiff() })
        run.add(item("Field sweep (fuzz)") { runFuzz() })
        run.add(item("Session persistence (persist)") { runPersist() })
        run.add(item("Race (moves real state)") { runRace() })
        run.add(item("Bridge to HTTP tools (show command)") { runBridgeCommand() })
        menu.add(run)

        menu.addSeparator()
        menu.add(item("Configure wsprobe path...") { configureBinary() })

        api.userInterface().menuBar().registerMenu(menu)
    }

    private fun item(label: String, action: () -> Unit): JMenuItem =
        JMenuItem(label).apply { addActionListener { SwingUtilities.invokeLater(action) } }

    private fun writeDraft() {
        val ready = builders.values.any { it.hasEvidence() }
        if (!ready) {
            JOptionPane.showMessageDialog(
                null,
                "No WebSocket traffic observed yet. Proxy a WebSocket session first, then try again.",
                "wsprobe companion",
                JOptionPane.INFORMATION_MESSAGE,
            )
            return
        }

        val nameInput = JOptionPane.showInputDialog(
            null,
            "Profile name (a label for this target, not a hostname):",
            "wsprobe companion",
            JOptionPane.PLAIN_MESSAGE,
        ) ?: return
        val profileName = nameInput.trim().ifEmpty { "drafted-target" }

        val channels = ArrayList<Channel>()
        val keys = synchronized(channelOrder) { ArrayList(channelOrder) }
        var dropped = 0
        var frames = 0
        for (k in keys) {
            val b = builders[k] ?: continue
            if (!b.hasEvidence()) continue
            channels.add(b.build(profileName).channels.first())
            dropped += b.dropped()
            frames += b.frames()
        }
        if (channels.isEmpty()) return
        val profile = Profile(name = profileName, channels = dedupeChannelNames(channels))
        val yaml = YamlWriter.toYaml(profile)

        val chooser = JFileChooser().apply {
            dialogTitle = "Save wsprobe draft profile"
            selectedFile = Paths.get(System.getProperty("user.home"), "profile.yaml").toFile()
        }
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return
        val out = chooser.selectedFile.toPath()
        try {
            Files.writeString(out, yaml)
            lastDraftPath = out
            api.logging().logToOutput(
                "wsprobe companion: wrote $out " +
                    "(${channels.size} channel(s), $frames frames observed, $dropped heartbeats marked)."
            )
            JOptionPane.showMessageDialog(
                null,
                "Wrote draft profile to:\n$out\n\nLoad it with wsprobe once you fill in the auth block.",
                "wsprobe companion",
                JOptionPane.INFORMATION_MESSAGE,
            )
        } catch (e: Exception) {
            api.logging().logToError("wsprobe companion: failed to write profile: ${e.message}")
            JOptionPane.showMessageDialog(
                null, "Failed to write profile: ${e.message}", "wsprobe companion", JOptionPane.ERROR_MESSAGE,
            )
        }
    }

    private fun writeCapture() {
        val frames = capturedFrames.toList()
        if (frames.isEmpty()) {
            JOptionPane.showMessageDialog(
                null,
                "No WebSocket frames observed yet. Proxy a WebSocket session first, then try again.",
                "wsprobe companion",
                JOptionPane.INFORMATION_MESSAGE,
            )
            return
        }
        val chooser = JFileChooser().apply {
            dialogTitle = "Save wsprobe capture (NDJSON)"
            selectedFile = Paths.get(System.getProperty("user.home"), "capture.ndjson").toFile()
        }
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return
        val out = chooser.selectedFile.toPath()
        try {
            Files.writeString(out, CaptureCodec.toNdjson(frames))
            api.logging().logToOutput("wsprobe companion: wrote $out (${frames.size} frame(s)).")
            JOptionPane.showMessageDialog(
                null,
                "Wrote ${frames.size} frame(s) to:\n$out\n\n" +
                    "Drive it with: wsprobe analyze $out --emit-profile profile.yaml\n" +
                    "Credential-looking fields are redacted, but treat captures as sensitive.",
                "wsprobe companion",
                JOptionPane.INFORMATION_MESSAGE,
            )
        } catch (e: Exception) {
            api.logging().logToError("wsprobe companion: failed to write capture: ${e.message}")
            JOptionPane.showMessageDialog(
                null, "Failed to write capture: ${e.message}", "wsprobe companion", JOptionPane.ERROR_MESSAGE,
            )
        }
    }

    // ---- invocation tier: run the wsprobe CLI ------------------------------

    private fun configureBinary() {
        val current = api.persistence().preferences().getString(WsProbeCli.PREF_BINARY) ?: ""
        val input = JOptionPane.showInputDialog(
            null,
            "Path to the wsprobe binary (e.g. /path/to/.venv/bin/wsprobe).\n" +
                "Leave blank to clear and fall back to a PATH lookup.",
            current,
        ) ?: return
        val value = input.trim()
        if (value.isEmpty()) {
            api.persistence().preferences().deleteString(WsProbeCli.PREF_BINARY)
            api.logging().logToOutput("wsprobe companion: wsprobe path cleared; using PATH lookup.")
        } else {
            api.persistence().preferences().setString(WsProbeCli.PREF_BINARY, value)
            api.logging().logToOutput("wsprobe companion: wsprobe path set to $value.")
        }
    }

    /** Resolve the binary, warning the operator plainly when it cannot be found. */
    private fun resolveBinaryOrWarn(): String? {
        val pref = api.persistence().preferences().getString(WsProbeCli.PREF_BINARY)
        val binary = WsProbeCli.resolveBinary(pref, System.getenv("PATH")) { Files.isRegularFile(Paths.get(it)) }
        if (binary == null) {
            JOptionPane.showMessageDialog(
                null,
                "Could not find the wsprobe CLI.\n\n" +
                    "Set its path with wsprobe > Configure wsprobe path... " +
                    "(for example, your venv's .venv/bin/wsprobe), or put wsprobe on your PATH.",
                "wsprobe companion",
                JOptionPane.ERROR_MESSAGE,
            )
        }
        return binary
    }

    private fun runHandshake() {
        val binary = resolveBinaryOrWarn() ?: return
        val profile = chooseProfile() ?: return
        // An optional valid token, used by the Origin and cross-user rows.
        val token = chooseTokenFile("Select a valid token file (optional; Cancel to skip)")
        val argv = WsProbeCli.handshakeArgs(binary, profile.toString(), token?.toString())
        runAsync("handshake", argv)
    }

    private fun runFuzz() {
        val binary = resolveBinaryOrWarn() ?: return
        val profile = chooseProfile() ?: return
        val frame = promptNonEmpty("Base frame as JSON:", "{\"type\":\"getRecord\",\"id\":0}") ?: return
        val field = promptNonEmpty("Field to drive over the value list:", "id") ?: return
        val values = promptNonEmpty("Comma-separated values to try:", "1001,1002,1003") ?: return
        val token = chooseTokenFile("Select a token file (optional; Cancel to skip)")
        val argv = WsProbeCli.fuzzArgs(binary, profile.toString(), frame, field, values, token?.toString())
        runAsync("fuzz", argv)
    }

    private fun runPersist() {
        val binary = resolveBinaryOrWarn() ?: return
        val profile = chooseProfile() ?: return
        val frame = promptNonEmpty("Privileged frame to re-send after the pause, as JSON:", "{\"type\":\"read_note\",\"owner\":\"<id>\"}") ?: return
        val settleInput = promptNonEmpty(
            "Seconds to wait for you to revoke the session out of band\n(logout / reset / role drop / token expiry):",
            "15",
        ) ?: return
        val settle = settleInput.toDoubleOrNull()
        if (settle == null || settle < 0) {
            JOptionPane.showMessageDialog(null, "Enter a non-negative number of seconds.", "wsprobe companion", JOptionPane.ERROR_MESSAGE)
            return
        }
        val token = chooseTokenFile("Select a valid token file (optional; Cancel to skip)")
        val argv = WsProbeCli.persistArgs(binary, profile.toString(), frame, settle, token?.toString())
        runAsync("persist", argv)
    }

    private fun runRace() {
        val binary = resolveBinaryOrWarn() ?: return
        val profile = chooseProfile() ?: return
        val frame = promptNonEmpty("State-changing frame to fire concurrently, as JSON:", "{\"type\":\"claim\",\"item\":\"coupon\"}") ?: return
        val countInput = promptNonEmpty("How many identical frames to fire at once:", "20") ?: return
        val count = countInput.toIntOrNull()
        if (count == null || count < 2) {
            JOptionPane.showMessageDialog(null, "Enter a whole number of at least 2.", "wsprobe companion", JOptionPane.ERROR_MESSAGE)
            return
        }
        val confirm = JOptionPane.showConfirmDialog(
            null,
            "race will fire $count copies of this frame on the target.\n" +
                "This MOVES REAL STATE (a claim, payout or transfer may apply more than once).\n\n" +
                "Fire against a system you are authorized to test?",
            "wsprobe companion: race moves real state",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
        )
        if (confirm != JOptionPane.YES_OPTION) {
            appendResult("race cancelled; nothing sent.\n")
            return
        }
        val token = chooseTokenFile("Select a valid token file (optional; Cancel to skip)")
        val argv = WsProbeCli.raceArgs(binary, profile.toString(), frame, count, token?.toString())
        runAsync("race", argv)
    }

    private fun runBridgeCommand() {
        val binary = resolveBinaryOrWarn() ?: return
        val profile = chooseProfile() ?: return
        val frame = promptNonEmpty(
            "Frame template as JSON, with a §FUZZ§ placeholder where the HTTP tool injects:",
            "{\"type\":\"search\",\"q\":\"§FUZZ§\"}",
        ) ?: return
        val portInput = promptNonEmpty("Loopback port for the bridge:", "8081") ?: return
        val port = portInput.toIntOrNull()
        if (port == null || port !in 1..65535) {
            JOptionPane.showMessageDialog(null, "Enter a port between 1 and 65535.", "wsprobe companion", JOptionPane.ERROR_MESSAGE)
            return
        }
        val token = chooseTokenFile("Select a valid token file (optional; Cancel to skip)")
        val argv = WsProbeCli.bridgeArgs(binary, profile.toString(), frame, port, token?.toString())
        val command = WsProbeCli.shellCommand(argv)

        // The bridge is a long-running server, so it is not spawned here. Show
        // the exact command to run in a terminal, then point an HTTP tool at the
        // loopback port. The command also lands in the results tab and the clipboard.
        appendResult(
            "bridge (run this in a terminal, then point sqlmap / Burp Intruder at http://127.0.0.1:$port):\n\n$command\n",
        )
        try {
            java.awt.Toolkit.getDefaultToolkit().systemClipboard
                .setContents(java.awt.datatransfer.StringSelection(command), null)
        } catch (_: Exception) {
            // Clipboard is best-effort; the command is shown in the tab regardless.
        }
        JOptionPane.showMessageDialog(
            null,
            "The bridge is a long-running server, so run it yourself:\n\n$command\n\n" +
                "Then point your HTTP tool (sqlmap, Burp Intruder) at http://127.0.0.1:$port.\n" +
                "The command has been copied to your clipboard and written to the wsprobe tab.",
            "wsprobe companion: bridge",
            JOptionPane.INFORMATION_MESSAGE,
        )
    }

    private fun promptNonEmpty(message: String, seed: String): String? {
        val input = JOptionPane.showInputDialog(null, message, seed)?.trim() ?: return null
        return input.ifEmpty { null }
    }

    private fun runDiff() {
        val binary = resolveBinaryOrWarn() ?: return
        val profile = chooseProfile() ?: return
        val frame = JOptionPane.showInputDialog(
            null,
            "Frame to send from both identities, as JSON:",
            "{\"type\":\"read_note\",\"owner\":\"<id>\"}",
        )?.trim() ?: return
        if (frame.isEmpty()) return
        val tokenA = chooseTokenFile("Select the token file for identity A") ?: return
        val tokenB = chooseTokenFile("Select the token file for identity B") ?: return
        val argv = WsProbeCli.diffArgs(binary, profile.toString(), frame, tokenA.toString(), tokenB.toString())
        runAsync("diff", argv)
    }

    /** Run the CLI off the EDT, then render its JSON back into the results tab. */
    private fun runAsync(label: String, argv: List<String>) {
        appendResult("$ ${argv.joinToString(" ")}\n")
        Thread {
            val outcome = processRunner.run(argv)
            SwingUtilities.invokeLater {
                if (outcome.error != null) {
                    appendResult("[error] ${outcome.error}\n")
                    JOptionPane.showMessageDialog(
                        null, outcome.error, "wsprobe companion", JOptionPane.ERROR_MESSAGE,
                    )
                } else if (!outcome.ok) {
                    val msg = outcome.stderr.ifBlank { outcome.stdout }.trim()
                    appendResult("[exit ${outcome.exitCode}] $msg\n")
                    JOptionPane.showMessageDialog(
                        null,
                        "wsprobe exited with ${outcome.exitCode}:\n\n${msg.take(2000)}",
                        "wsprobe companion",
                        JOptionPane.ERROR_MESSAGE,
                    )
                } else {
                    appendResult(WsProbeRender.render(outcome.stdout) + "\n")
                }
                api.logging().logToOutput("wsprobe companion: $label run finished (exit ${outcome.exitCode}).")
            }
        }.apply { isDaemon = true; name = "wsprobe-$label"; start() }
    }

    private fun chooseProfile(): Path? {
        val chooser = JFileChooser().apply {
            dialogTitle = "Choose a wsprobe profile to run"
            lastDraftPath?.let { selectedFile = it.toFile() }
        }
        if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return null
        return chooser.selectedFile.toPath()
    }

    private fun chooseTokenFile(title: String): Path? {
        val chooser = JFileChooser().apply { dialogTitle = title }
        if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return null
        return chooser.selectedFile.toPath()
    }

    private fun appendResult(text: String) {
        SwingUtilities.invokeLater {
            results.append("\n" + "-".repeat(72) + "\n" + text)
            results.caretPosition = results.document.length
        }
    }

    // ---- helpers -----------------------------------------------------------

    private fun builderFor(key: String, url: String?): DraftBuilder {
        return builders.computeIfAbsent(key) {
            synchronized(channelOrder) { channelOrder.add(key) }
            DraftBuilder(channelName = channelNameFor(url, key))
        }
    }

    private fun channelKey(url: String?): String {
        if (url == null) return "default"
        return try {
            val u = URI(url)
            val host = u.host ?: ""
            val port = if (u.port >= 0) ":${u.port}" else ""
            val path = u.path ?: ""
            "$host$port$path".ifEmpty { "default" }
        } catch (_: Exception) {
            "default"
        }
    }

    private fun channelNameFor(url: String?, key: String): String {
        if (builders.isEmpty()) return "default" // first socket keeps the emitter's canonical name
        val path = try { URI(url ?: "").path ?: "" } catch (_: Exception) { "" }
        val seg = path.trim('/').substringAfterLast('/')
        return seg.ifEmpty { key.ifEmpty { "channel" } }
    }

    private fun dedupeChannelNames(channels: List<Channel>): List<Channel> {
        val seen = HashMap<String, Int>()
        return channels.map { ch ->
            val n = seen.merge(ch.name, 1, Int::plus)!!
            if (n == 1) ch else ch.copy(name = "${ch.name}-$n")
        }
    }
}
