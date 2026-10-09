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
                "Run wsprobe > Handshake matrix / Two-account diff drives the CLI " +
                "and shows the observations in the wsprobe tab. " +
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

            creation.proxyWebSocket().registerProxyMessageHandler(MessageHandler(builder))
        }
    }

    private inner class MessageHandler(private val builder: DraftBuilder) : ProxyMessageHandler {
        override fun handleTextMessageReceived(message: InterceptedTextMessage): TextMessageReceivedAction {
            val isHeartbeat = try { builder.observeText(message.payload()) } catch (_: Exception) { false }
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
            return TextMessageToBeSentAction.continueWith(message)
        }

        override fun handleBinaryMessageToBeSent(message: InterceptedBinaryMessage): BinaryMessageToBeSentAction {
            return BinaryMessageToBeSentAction.continueWith(message)
        }
    }

    // ---- draft emission ----------------------------------------------------

    private fun registerMenu() {
        // A Swing JMenu, because the Montoya Menu has no submenu nesting and the
        // Run actions read best as a "Run wsprobe" submenu. registerMenu accepts
        // a JMenu directly.
        val menu = JMenu("wsprobe")

        menu.add(item("Write draft profile.yaml") { writeDraft() })
        menu.add(item("Reset observed traffic") {
            builders.clear()
            synchronized(channelOrder) { channelOrder.clear() }
            api.logging().logToOutput("wsprobe companion: observed traffic reset.")
        })

        menu.addSeparator()
        val run = JMenu("Run wsprobe")
        run.add(item("Handshake matrix") { runMatrix() })
        run.add(item("Two-account diff") { runDiff() })
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

    private fun runMatrix() {
        val binary = resolveBinaryOrWarn() ?: return
        val profile = chooseProfile() ?: return
        // An optional valid token, used by the Origin and cross-user rows.
        val token = chooseTokenFile("Select a valid token file (optional; Cancel to skip)")
        val argv = WsProbeCli.matrixArgs(binary, profile.toString(), token?.toString())
        runAsync("matrix", argv)
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
