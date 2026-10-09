# wsprobe companion (Burp extension)

A small Burp Suite extension that turns WebSocket traffic Burp already proxies
into a draft `profile.yaml` for the [wsprobe](../) toolkit, and marks keepalive
frames in the WebSocket history so a busy socket stays readable.

It is a companion, not the tool. wsprobe owns its own authenticated sockets and
covers the handshake and authorization surface end to end; this extension only
gives it a running start on the one target-specific artifact wsprobe needs - the
profile - by watching real traffic instead of an exported capture.

## What it does

Four jobs.

1. **Draft a profile from live traffic.** As you browse a target through Burp,
   the extension watches every WebSocket it proxies: the upgrade request (URL,
   `Origin`, negotiated subprotocol, and the query string) and each text frame.
   From the frames it infers the message vocabulary the same way wsprobe's
   offline capture analyzer does - the field that names a message type, the keys
   that correlate a request to its reply, and which message types are
   keepalives. On demand (**wsprobe > Write draft profile.yaml**) it writes a
   `profile.yaml` in the exact shape wsprobe loads.

   The advantage over an offline export: a live handshake carries the real
   upgrade URL, the `Origin`, the subprotocol, and - read conservatively - where
   a token rides in the query string. The offline analyzer has to stub those.

2. **Heartbeat filter for the WebSocket history.** Keepalive frames (an
   app-level `ping`/`pong` or `heartbeat` type, or an Engine.IO `2`/`3`) are
   marked in the history with a gray highlight and a `wsprobe: heartbeat` note,
   so you can filter or sort them out of a socket where keepalives dominate.
   Burp's API has no "hide from history" switch, so marking is the honest
   equivalent; the frame is never dropped or altered in flight.

3. **Run wsprobe from Burp.** Once a profile exists, **wsprobe > Run wsprobe**
   drives the CLI for you: **Handshake**, **Two-account diff**, **Field sweep
   (fuzz)**, **Session persistence (persist)**, and **Race (moves real state)**.
   The extension shells out to the `wsprobe` binary with `--json` against the
   profile you pick (defaulting to the one the companion just drafted), parses
   the stable JSON, and renders the observations in the **wsprobe** suite tab.
   Handshake takes an optional valid token file; diff asks for a frame and two
   token files; fuzz asks for a frame, a field and a value list; persist asks
   for a frame and a scripted settle interval (Burp has no stdin, so the pause
   is timed rather than interactive). **Race moves real state**, so it asks you
   to confirm in a dialog and passes `--yes` to the CLI only after you agree.
   **Bridge** is a long-running server, so instead of spawning it the companion
   shows the exact `wsprobe bridge` command (copied to your clipboard and the
   wsprobe tab) for you to run in a terminal, then point an HTTP tool at the
   loopback port. Where the `wsprobe` binary lives is configurable under **wsprobe
   > Configure wsprobe path...** (for example, your venv's `.venv/bin/wsprobe`);
   with nothing set, the extension looks for `wsprobe` on your `PATH`. If it
   cannot find the CLI, it says so plainly rather than failing silently. As
   everywhere in wsprobe, the panel reports observed behavior and never the word
   "confirmed".

4. **Export a capture (history import).** **wsprobe > Write capture.ndjson**
   writes every WebSocket frame Burp has proxied this session as a wsprobe
   NDJSON capture, in the exact shape `wsprobe analyze` reads. It is the
   history-import path: you drive the offline capabilities from Burp-seen
   traffic without an export-format in between (`wsprobe analyze capture.ndjson
   --emit-profile profile.yaml`). Credential-looking fields (`token`,
   `password`, `authorization`, `cookie`, ...) are redacted on write with the
   same best-effort pattern the CLI's own capture writer uses; it is best-effort,
   so treat captures as sensitive.

A target that runs several distinct sockets drafts one channel each, keyed by
host and path.

Drafting, the heartbeat filter, and the capture export are read-only on the
wire: the extension opens no socket of its own and sends nothing. Run wsprobe is
the one action that reaches a target, and it does so through the wsprobe CLI
against a profile you chose, for a system you are authorized to test.

## How the drafted profile maps to `profile.schema.json`

The emitter follows the same "omit anything left at its default" rule as
wsprobe's own Python emitter, so a drafted file is minimal and loads straight
back in (wsprobe restores the defaults on load).

| Profile field (schema)          | Source in the extension                                             |
|---------------------------------|---------------------------------------------------------------------|
| `name`                          | You are prompted for a label when you write the file.               |
| `channels[].name`               | `default` for the first socket; the path segment for the rest.      |
| `handshake.url`                 | The proxied upgrade URL, normalized to `ws://` / `wss://`.          |
| `handshake.origin`              | The `Origin` header on the upgrade, if present.                     |
| `handshake.subprotocol`         | The `Sec-WebSocket-Protocol` value, if present.                     |
| `handshake.framing`             | `socketio` if Engine.IO/Socket.IO digit-prefixed frames were seen, else the default `json`. |
| `auth.token_param` / `auth.token_location` | Inferred only when a conventional token key (`token`, `access_token`, `jwt`, ...) is in the upgrade query; otherwise left for you to fill in. |
| `messages.type_field`           | The most common of `type`, `event`, `op`, `action`, `method`, `cmd` seen carrying a value. |
| `messages.correlation_keys`     | The two most common of `cid`, `id`, `reqId`, `requestId`, `seq`, `correlationId`, `nonce`. |
| `messages.opcode_names`         | One entry per distinct non-heartbeat message type observed.         |
| `heartbeat.types`               | The keepalive message types observed (`ping`/`pong`/`heartbeat`/... and Engine.IO `2`/`3`). |

The auth *source* (a login command, an HTTP login recipe, or a shared token
file) and the refresh policy are never guessed from traffic - you fill those in.
The draft gets you the handshake and the message map; you finish the auth block.

## Build

Stack: Kotlin 2.2 + the Burp Montoya API, built with Gradle 9 (Kotlin DSL). The
one runtime dependency, SnakeYAML (Apache-2.0), is bundled into the JAR by the
`com.gradleup.shadow` plugin, because Burp puts only the Montoya API on the
extension classpath. Bytecode targets JDK 17, so the JAR loads in Burp's JRE
whatever JDK you build on.

```
# from this directory — the committed wrapper pins Gradle 9
./gradlew build
```

Requirements:

- **JDK 17 or newer** to run the build. The compiler emits JDK 17 bytecode
  regardless, so no specific JDK install is needed.
- **Network access** on the first build to fetch the Gradle distribution (via
  the wrapper), the Kotlin and shadow plugins, the Montoya API, and SnakeYAML.

The loadable artifact is `build/libs/wsprobe-burp-0.2.0.jar` (the shadow JAR).

## Load in Burp

1. Build the JAR (above).
2. Burp Suite > **Extensions** > **Installed** > **Add**.
3. Extension type **Java**, select `build/libs/wsprobe-burp-0.2.0.jar`, **Next**.
4. The Output tab shows `wsprobe companion loaded`.

Then proxy a WebSocket session of a target you are authorized to test. When you
have traffic, **wsprobe > Write draft profile.yaml** in the top menu bar, give
the profile a name, and choose where to save it. **Reset observed traffic**
clears the accumulator to start a fresh draft.

## Feed it to wsprobe

The written file is a normal wsprobe profile. Fill in the `auth` block for how
the target mints and places its token, then drive any wsprobe capability from
it:

```
# after filling in auth in the drafted profile.yaml (profile path is positional)
wsprobe handshake profile.yaml     # handshake authentication test
wsprobe repl   profile.yaml        # interactive authenticated client
wsprobe diff   profile.yaml --frame '{...}' --token-a a.tok --token-b b.tok
```

The drafted profile declares `framing` (json, text, or socketio) and a
`correlation` mode (echo, ordered, or ack); fill in `auth` (including a
`cookie`/`subprotocol`/`login-frame` token location if the target uses one). An
HTTP injection tool can reach a frame field through `wsprobe bridge`. See the
wsprobe README and `profile.schema.json` in the parent directory for the full
profile contract and the capability list.

## Authorized use only

Like wsprobe itself, this is for systems you own or are explicitly authorized to
test. It ships no target and no default host, and it only ever observes traffic
you have already routed through your own Burp.

## License

MIT, matching the wsprobe repository. Bundled dependency: SnakeYAML, Apache
License 2.0 (`org.yaml:snakeyaml`).
