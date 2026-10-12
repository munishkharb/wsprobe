// SPDX-License-Identifier: MIT
// wsprobe Burp companion - the interactive WebSocket console.

package wsprobe.burp

import burp.api.montoya.ui.editor.WebSocketMessageEditor
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.util.concurrent.CompletionStage
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities

/**
 * An interactive WebSocket console that opens a socket of its OWN - separate
 * from the connection Burp proxied - to a URL you give it, and sends one frame
 * per click from the editable composer above the log.
 *
 * A send puts a real frame on a live target, so Send is gated behind an
 * explicit "arm" checkbox: nothing is sent until you arm it, and the arm is a
 * per-session reminder, not a per-click modal. Built for a small window - the
 * controls wrap, the composer and log share a draggable split, and the log
 * scrolls - so nothing is cut off.
 */
class WsProbeConsole(private val composer: WebSocketMessageEditor) {

    private val mono = Font(Font.MONOSPACED, Font.PLAIN, 12)

    private val url = JTextField("wss://", 34)
    private val header = JTextField("", 22)
    private val arm = JCheckBox("arm (fires a REAL frame)")
    private val connectBtn = JButton("Connect")
    private val sendBtn = JButton("Send").apply { isEnabled = false }
    private val disconnectBtn = JButton("Disconnect").apply { isEnabled = false }
    private val log = JTextArea("Enter a ws:// or wss:// URL, Connect, compose a frame, arm, and Send.\n").apply {
        isEditable = false
        lineWrap = false
        font = mono
    }

    private val client: HttpClient = HttpClient.newHttpClient()
    @Volatile private var socket: WebSocket? = null

    val component: JComponent = build()

    init {
        connectBtn.addActionListener { connect() }
        sendBtn.addActionListener { send() }
        disconnectBtn.addActionListener { disconnect() }
    }

    private fun build(): JComponent {
        val controls = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6)).apply {
            border = BorderFactory.createEmptyBorder(2, 6, 2, 6)
            add(JLabel("url:")); add(url); add(connectBtn); add(disconnectBtn)
            add(JLabel("  header (Name: value, optional):")); add(header)
        }
        val sendRow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2)).apply {
            add(arm); add(sendBtn)
        }
        val top = JPanel(BorderLayout()).apply {
            add(controls, BorderLayout.NORTH)
            add(composer.uiComponent(), BorderLayout.CENTER)
            add(sendRow, BorderLayout.SOUTH)
        }
        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, JScrollPane(log)).apply {
            resizeWeight = 0.55
            isContinuousLayout = true
            topComponent.minimumSize = Dimension(240, 120)
            bottomComponent.minimumSize = Dimension(240, 80)
        }
        return split
    }

    private fun connect() {
        val target = url.text.trim()
        if (!target.startsWith("ws://") && !target.startsWith("wss://")) {
            append("url must start with ws:// or wss://"); return
        }
        var builder = client.newWebSocketBuilder()
        val h = header.text.trim()
        if (h.contains(":")) {
            val name = h.substringBefore(":").trim()
            val value = h.substringAfter(":").trim()
            if (name.isNotEmpty()) builder = builder.header(name, value)
        }
        append("connecting to $target ...")
        connectBtn.isEnabled = false
        builder.buildAsync(URI.create(target), Listener()).whenComplete { ws, err ->
            SwingUtilities.invokeLater {
                if (err != null) {
                    append("connect failed: ${err.message}")
                    setConnected(false)
                } else {
                    socket = ws
                    append("connected.")
                    setConnected(true)
                }
            }
        }
    }

    private fun send() {
        val ws = socket ?: run { append("not connected."); return }
        if (!arm.isSelected) {
            append("not armed - tick 'arm' to send a real frame to the target.")
            return
        }
        val text = composer.getContents().toString()
        if (text.isEmpty()) { append("compose a frame above first."); return }
        ws.sendText(text, true)
        append("-> sent: $text")
    }

    private fun disconnect() {
        socket?.let { it.sendClose(WebSocket.NORMAL_CLOSURE, "closed by operator") }
        socket = null
        setConnected(false)
        append("disconnected.")
    }

    private fun setConnected(connected: Boolean) {
        sendBtn.isEnabled = connected
        disconnectBtn.isEnabled = connected
        connectBtn.isEnabled = !connected
    }

    private fun append(line: String) {
        SwingUtilities.invokeLater {
            log.append(line + "\n")
            log.caretPosition = log.document.length
        }
    }

    private inner class Listener : WebSocket.Listener {
        private val buf = StringBuilder()

        override fun onOpen(webSocket: WebSocket) {
            webSocket.request(1)
        }

        override fun onText(webSocket: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
            buf.append(data)
            if (last) {
                append("<- $buf")
                buf.setLength(0)
            }
            webSocket.request(1)
            return null
        }

        override fun onClose(webSocket: WebSocket, statusCode: Int, reason: String): CompletionStage<*>? {
            append("server closed the socket: $statusCode $reason")
            SwingUtilities.invokeLater { setConnected(false) }
            return null
        }

        override fun onError(webSocket: WebSocket, error: Throwable) {
            append("socket error: ${error.message}")
            SwingUtilities.invokeLater { setConnected(false) }
        }
    }
}
