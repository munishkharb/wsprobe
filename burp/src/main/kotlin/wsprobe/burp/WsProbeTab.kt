// SPDX-License-Identifier: MIT
// wsprobe Burp companion - the suite-tab UI.

package wsprobe.burp

import burp.api.montoya.core.ByteArray
import burp.api.montoya.ui.editor.WebSocketMessageEditor
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel

/**
 * The wsprobe suite tab, built for a small (MacBook) Burp window: nothing is
 * stacked and nothing has a fixed height, so nothing can cut off. A draggable
 * horizontal split puts the observed-frame table on the left and a tabbed
 * Detail / Results pane on the right; every region is in its own scroll pane,
 * and the user owns the divider.
 *
 * It holds no Montoya or socket logic - the extension feeds it frames and run
 * output and wires the toolbar buttons to its own actions, so this file is pure
 * Swing and easy to reason about.
 */
class WsProbeTab(
    runVerbs: List<String>,
    // Burp's native read-only WebSocket message editor (Pretty / Raw / Hex),
    // created by the extension and shown in the Detail tab.
    private val detailEditor: WebSocketMessageEditor,
    // The interactive console's UI, built by the extension.
    private val consoleComponent: java.awt.Component,
    private val onDraftProfile: () -> Unit,
    private val onExportCapture: () -> Unit,
    private val onRun: (verb: String) -> Unit,
) {
    private val mono = Font(Font.MONOSPACED, Font.PLAIN, 12)

    private val model = FrameTableModel()
    private val table = JTable(model).apply {
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        font = mono
        autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
        columnModel.getColumn(0).preferredWidth = 48   // dir
        columnModel.getColumn(1).preferredWidth = 150  // type
        columnModel.getColumn(2).preferredWidth = 420  // preview
    }

    private val results = textArea("Run a verb from the toolbar or the wsprobe menu; output lands here.\n")

    private val hideHeartbeats = JCheckBox("hide heartbeats", true)

    val component: JComponent = build(runVerbs)

    init {
        hideHeartbeats.addActionListener { model.hideHeartbeatRows(hideHeartbeats.isSelected) }
        table.selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) {
                val row = table.selectedRow
                val json = if (row >= 0) model.detailAt(table.convertRowIndexToModel(row)) else ""
                detailEditor.setContents(ByteArray.byteArray(json))
            }
        }
    }

    /** Called by the extension for every observed frame (off or on the EDT). */
    fun addFrame(frame: CapturedFrame, heartbeat: Boolean) {
        SwingUtilities.invokeLater { model.add(frame, heartbeat) }
    }

    fun clearFrames() = SwingUtilities.invokeLater { model.clear() }

    /** Called by the extension to append a line of CLI run output. */
    fun appendResult(text: String) {
        SwingUtilities.invokeLater {
            results.append("\n" + "-".repeat(60) + "\n" + text)
            results.caretPosition = results.document.length
        }
    }

    private fun build(runVerbs: List<String>): JComponent {
        val root = JPanel(BorderLayout())
        root.add(toolbar(runVerbs), BorderLayout.NORTH)

        val right = JTabbedPane()
        right.addTab("Detail", detailEditor.uiComponent())
        right.addTab("Console", consoleComponent)
        right.addTab("Results", JScrollPane(results))

        val split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            JScrollPane(table),
            right,
        ).apply {
            resizeWeight = 0.5
            isContinuousLayout = true
            // A modest minimum so neither side collapses to nothing on a small screen.
            leftComponent.minimumSize = Dimension(220, 120)
            rightComponent.minimumSize = Dimension(260, 120)
        }
        root.add(split, BorderLayout.CENTER)
        return root
    }

    private fun toolbar(runVerbs: List<String>): JComponent {
        // FlowLayout wraps to the next line when the window is narrow, so the
        // controls never run off the edge of a small Burp tab.
        val bar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        bar.border = BorderFactory.createEmptyBorder(2, 6, 2, 6)
        bar.add(JButton("Draft profile").apply { addActionListener { onDraftProfile() } })
        bar.add(JButton("Export capture").apply { addActionListener { onExportCapture() } })
        bar.add(hideHeartbeats)
        bar.add(JLabel("  run:"))
        val combo = JComboBox(runVerbs.toTypedArray())
        bar.add(combo)
        bar.add(JButton("Run").apply {
            addActionListener { (combo.selectedItem as? String)?.let(onRun) }
        })
        return bar
    }

    private fun textArea(seed: String) = javax.swing.JTextArea(seed).apply {
        isEditable = false
        lineWrap = false
        font = mono
    }
}

/**
 * Backs the frame table. Holds every observed frame; hides heartbeat rows when
 * asked without discarding them, so the filter is reversible.
 */
private class FrameTableModel : AbstractTableModel() {
    private data class Row(val captured: CapturedFrame, val heartbeat: Boolean)

    private val all = ArrayList<Row>()
    private val shown = ArrayList<Row>()
    private var hideHeartbeats = true

    private val cols = arrayOf("Dir", "Type", "Preview")

    fun add(frame: CapturedFrame, heartbeat: Boolean) {
        val row = Row(frame, heartbeat)
        all.add(row)
        if (!(hideHeartbeats && heartbeat)) {
            shown.add(row)
            fireTableRowsInserted(shown.size - 1, shown.size - 1)
        }
    }

    fun clear() {
        all.clear(); shown.clear(); fireTableDataChanged()
    }

    fun hideHeartbeatRows(hide: Boolean) {
        hideHeartbeats = hide
        shown.clear()
        for (r in all) if (!(hide && r.heartbeat)) shown.add(r)
        fireTableDataChanged()
    }

    fun detailAt(rowIndex: Int): String {
        // The frame as JSON so Burp's editor can Pretty-print it; direction and
        // channel are already shown in the table row.
        return CaptureCodec.encode(shown[rowIndex].captured.frame)
    }

    override fun getRowCount() = shown.size
    override fun getColumnCount() = cols.size
    override fun getColumnName(c: Int) = cols[c]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val f = shown[rowIndex].captured
        return when (columnIndex) {
            0 -> if (f.direction == CaptureCodec.SEND) "→" else "←"
            1 -> typeOf(f.frame)
            else -> preview(f.frame)
        }
    }

    private fun typeOf(frame: Any?): String {
        if (frame is Map<*, *>) {
            for (k in listOf("type", "event", "op", "action", "method", "cmd")) {
                val v = frame[k]
                if (v is String || v is Number) return v.toString()
            }
        }
        return ""
    }

    private fun preview(frame: Any?): String {
        val s = frame.toString().replace("\n", " ")
        return if (s.length > 200) s.substring(0, 200) + "…" else s
    }
}
