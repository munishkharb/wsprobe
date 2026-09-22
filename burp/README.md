# wsprobe companion (Burp extension)

A small Burp Suite extension that turns WebSocket traffic Burp already proxies
into a draft `profile.yaml` for the [wsprobe](../) toolkit, and marks keepalive
frames in the WebSocket history so a busy socket stays readable.

It is a companion, not the tool. wsprobe owns its own authenticated sockets and
covers the handshake and authorization surface end to end; this extension only
gives it a running start on the one target-specific artifact wsprobe needs — the
profile — by watching real traffic instead of an exported capture.

## What it does

Two jobs, nothing else.

1. **Draft a profile from live traffic.** As you browse a target through Burp,
   the extension watches every WebSocket it proxies: the upgrade request (URL,
   `Origin`, negotiated subprotocol, and the query string) and each text frame.
   From the frames it infers the message vocabulary the same way wsprobe's
   offline capture analyzer does — the field that names a message type, the keys
   that correlate a request to its reply, and which message types are
   keepalives. On demand (**wsprobe > Write draft profile.yaml**) it writes a
   `profile.yaml` in the exact shape wsprobe loads.

   The advantage over an offline export: a live handshake carries the real
   upgrade URL, the `Origin`, the subprotocol, and — read conservatively — where
   a token rides in the query string. The offline analyzer has to stub those.

2. **Heartbeat filter for the WebSocket history.** Keepalive frames (an
   app-level `ping`/`pong` or `heartbeat` type, or an Engine.IO `2`/`3`) are
   marked in the history with a gray highlight and a `wsprobe: heartbeat` note,
   so you can filter or sort them out of a socket where keepalives dominate.
   Burp's API has no "hide from history" switch, so marking is the honest
   equivalent; the frame is never dropped or altered in flight.

A target that runs several distinct sockets drafts one channel each, keyed by
host and path.

Everything above is read-only on the wire. The extension opens no socket of its
own and sends nothing. It writes exactly one file, where you choose to put it.

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
file) and the refresh policy are never guessed from traffic — you fill those in.
The draft gets you the handshake and the message map; you finish the auth block.

## Build

Stack: Kotlin + the Burp Montoya API, built with Gradle (Kotlin DSL). The one
runtime dependency, SnakeYAML (Apache-2.0), is bundled into the JAR by the
shadow plugin, because Burp puts only the Montoya API on the extension
classpath. Bytecode targets JDK 17, so the JAR loads in Burp's JRE.

```
# from this directory
gradle build          # if you have a system Gradle
# or, once the wrapper jar is materialized:
gradle wrapper --gradle-version 8.7   # writes gradle/wrapper/gradle-wrapper.jar
./gradlew build
```

Requirements:

- **JDK 17+** to run the build (a JDK 17–21 is the safe range for the pinned
  Gradle 8.7; a JDK newer than that needs a correspondingly newer Gradle).
- **Network access** on the first build to fetch the Montoya API and SnakeYAML
  from Maven Central, and the Gradle distribution if you use the wrapper.

The loadable artifact is `build/libs/wsprobe-burp-0.1.0.jar` (the shadow JAR).

> The Gradle wrapper *jar* is not committed (it is a binary). Generate it once
> with `gradle wrapper` as shown above, or skip the wrapper and run a system
> `gradle build` directly.

## Load in Burp

1. Build the JAR (above).
2. Burp Suite > **Extensions** > **Installed** > **Add**.
3. Extension type **Java**, select `build/libs/wsprobe-burp-0.1.0.jar`, **Next**.
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
# after filling in auth in the drafted profile.yaml
wsprobe matrix    --profile profile.yaml     # handshake security matrix
wsprobe repl      --profile profile.yaml     # interactive authenticated client
```

See the wsprobe README and `profile.schema.json` in the parent directory for the
full profile contract and the capability list.

## Authorized use only

Like wsprobe itself, this is for systems you own or are explicitly authorized to
test. It ships no target and no default host, and it only ever observes traffic
you have already routed through your own Burp.

## License

MIT, matching the wsprobe repository. Bundled dependency: SnakeYAML, Apache
License 2.0 (`org.yaml:snakeyaml`).
