// SPDX-License-Identifier: MIT
// wsprobe Burp companion - part of the wsprobe toolkit, MIT licensed.

package wsprobe.burp

import org.yaml.snakeyaml.Yaml
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * The invocation tier: run the wsprobe CLI from Burp and read its JSON back.
 *
 * This file is deliberately free of Montoya and Swing so the command building,
 * binary resolution, process handling, and JSON rendering are all unit-tested
 * without Burp. The extension supplies the operator's choices (profile path,
 * frame, token files) and the UI; everything mechanical lives here.
 *
 * The companion drafts a profile from proxied traffic; this tier drives wsprobe
 * against that profile (or any profile the operator picks) with --json, so the
 * output is the documented, stable structure from wsprobe's jsonout module
 * rather than a scraped table.
 */
object WsProbeCli {

    /** Preference key the extension stores the wsprobe binary path under. */
    const val PREF_BINARY = "wsprobe.binary.path"

    /** argv for a handshake matrix run. A token file is optional: without one,
     *  the rows that need a seated token report as not-supplied. */
    fun matrixArgs(binary: String, profilePath: String, tokenFile: String?): List<String> {
        val argv = mutableListOf(binary, "matrix", profilePath)
        if (!tokenFile.isNullOrBlank()) {
            argv += "--token-file"
            argv += tokenFile
        }
        argv += "--json"
        return argv
    }

    /** argv for a two-account authorization diff. */
    fun diffArgs(
        binary: String,
        profilePath: String,
        frameJson: String,
        tokenAFile: String,
        tokenBFile: String,
    ): List<String> = listOf(
        binary, "diff", profilePath,
        "--frame", frameJson,
        "--token-a", tokenAFile,
        "--token-b", tokenBFile,
        "--json",
    )

    /**
     * Resolve the wsprobe binary. A stored preference wins when it points at an
     * existing file (an operator's venv, e.g. .venv/bin/wsprobe); otherwise
     * fall back to a PATH lookup for a bare `wsprobe`. Returns null when neither
     * resolves, so the caller can tell the operator plainly.
     *
     * `exists` is injected so this is testable without touching the filesystem.
     */
    fun resolveBinary(preference: String?, pathEnv: String?, exists: (String) -> Boolean): String? {
        if (!preference.isNullOrBlank() && exists(preference)) return preference
        if (pathEnv.isNullOrBlank()) return null
        for (dir in pathEnv.split(File.pathSeparatorChar)) {
            if (dir.isBlank()) continue
            val candidate = File(dir, "wsprobe").path
            if (exists(candidate)) return candidate
        }
        return null
    }
}

/** The outcome of one CLI invocation. `error` is set when the process could not
 *  run at all (binary missing, spawn failure, timeout); otherwise read
 *  exitCode/stdout/stderr. */
data class RunOutcome(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val error: String? = null,
) {
    val ok: Boolean get() = error == null && exitCode == 0
}

/** Runs an argv with a timeout, draining stdout and stderr without deadlocking. */
class ProcessRunner(private val timeoutSeconds: Long = 60) {

    fun run(argv: List<String>): RunOutcome {
        return try {
            val proc = ProcessBuilder(argv).start()
            // Drain stderr on its own thread so a large stream on either pipe
            // cannot block the other.
            val err = StringBuilder()
            val errThread = Thread {
                proc.errorStream.bufferedReader().use { r ->
                    r.forEachLine { err.append(it).append('\n') }
                }
            }.apply { isDaemon = true; start() }

            val out = proc.inputStream.bufferedReader().use { it.readText() }
            val finished = proc.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                proc.destroyForcibly()
                return RunOutcome(-1, out, err.toString(), "wsprobe timed out after ${timeoutSeconds}s")
            }
            errThread.join(1000)
            RunOutcome(proc.exitValue(), out, err.toString())
        } catch (e: Exception) {
            RunOutcome(-1, "", "", "could not run wsprobe: ${e.message}")
        }
    }
}

/**
 * Render a wsprobe --json payload as readable text for the results tab.
 *
 * Dispatches on the payload's `schema` tag. Matrix and diff are the two the Burp
 * actions produce; anything else falls back to a plain key dump so the tab still
 * shows something useful. As everywhere in wsprobe, this only echoes the
 * observation vocabulary and never introduces the word "confirmed".
 */
object WsProbeRender {

    private val yaml = Yaml()

    @Suppress("UNCHECKED_CAST")
    fun render(json: String): String {
        val root = try {
            yaml.load<Any?>(json) as? Map<String, Any?>
        } catch (e: Exception) {
            null
        } ?: return "wsprobe returned output that was not JSON:\n\n$json"

        return when (root["schema"]?.toString()) {
            "wsprobe.matrix/v1" -> renderMatrix(root)
            "wsprobe.diff/v1" -> renderDiff(root)
            else -> renderGeneric(root)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun renderMatrix(root: Map<String, Any?>): String {
        val sb = StringBuilder()
        sb.append("matrix  profile=").append(root["profile"])
            .append("  channel=").append(root["channel"]).append("\n\n")
        val obs = root["observations"] as? List<Map<String, Any?>> ?: emptyList()
        if (obs.isEmpty()) {
            sb.append("(no observations)\n")
            return sb.toString()
        }
        for (o in obs) {
            val check = o["check"]?.toString() ?: ""
            val observed = o["observed"]?.toString() ?: ""
            val reading = o["reading"]?.toString() ?: ""
            sb.append(check.padEnd(26)).append(" observed=").append(observed.padEnd(34))
                .append(" [").append(reading).append("]\n")
            val detail = o["detail"]
            if (detail is Map<*, *> && detail.isNotEmpty()) {
                sb.append("    detail: ").append(detail).append('\n')
            }
        }
        return sb.toString()
    }

    private fun renderDiff(root: Map<String, Any?>): String {
        val sb = StringBuilder()
        sb.append("diff  profile=").append(root["profile"])
            .append("  channel=").append(root["channel"]).append("\n\n")
        sb.append("reading: ").append(root["reading"])
            .append("   (").append(root["identity_a"]).append(" vs ").append(root["identity_b"]).append(")\n")
        sb.append("frame:   ").append(root["frame"]).append('\n')
        sb.append("reply ").append(root["identity_a"]).append(": ").append(root["reply_a"]).append('\n')
        sb.append("reply ").append(root["identity_b"]).append(": ").append(root["reply_b"]).append('\n')
        return sb.toString()
    }

    private fun renderGeneric(root: Map<String, Any?>): String {
        val sb = StringBuilder()
        for ((k, v) in root) sb.append(k).append(": ").append(v).append('\n')
        return sb.toString()
    }
}
