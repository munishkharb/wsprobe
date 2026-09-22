// SPDX-License-Identifier: MIT
// wsprobe Burp companion - part of the wsprobe toolkit, MIT licensed.
// Clean-room, no target and no default host. Ships nothing to point at.

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
import burp.api.montoya.ui.menu.BasicMenuItem
import burp.api.montoya.ui.menu.Menu
import java.net.URI
import java.nio.file.Files
import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap
import javax.swing.JFileChooser
import javax.swing.JOptionPane
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

    override fun initialize(api: MontoyaApi) {
        this.api = api
        api.extension().setName("wsprobe companion")

        api.proxy().registerWebSocketCreationHandler(CreationHandler())
        registerMenu()

        api.logging().logToOutput(
            "wsprobe companion loaded. Proxy WebSocket traffic, then " +
                "wsprobe > Write draft profile.yaml to emit a profile. " +
                "Keepalive frames are marked gray with a 'wsprobe: heartbeat' note."
        )
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
    }

    // ---- draft emission ----------------------------------------------------

    private fun registerMenu() {
        val write = BasicMenuItem.basicMenuItem("Write draft profile.yaml")
            .withAction { SwingUtilities.invokeLater { writeDraft() } }
        val clear = BasicMenuItem.basicMenuItem("Reset observed traffic")
            .withAction {
                builders.clear()
                synchronized(channelOrder) { channelOrder.clear() }
                api.logging().logToOutput("wsprobe companion: observed traffic reset.")
            }
        api.userInterface().menuBar().registerMenu(Menu.menu("wsprobe").withMenuItems(write, clear))
    }

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
