# wsprobe WebSocket Bambda pack

Two zero-code Bambdas for working a WebSocket target through Burp. Nothing to
build: paste the body into the matching Bambda editor in Burp, or import the
`.bambda` file directly. Both are read-only on the wire.

They line up with the wsprobe companion extension in this folder, so the same
frames the companion marks as heartbeats are the ones the filter hides, and the
token places the companion infers auth from are the ones the helper reads.

| File | Burp location | What it does |
|------|---------------|--------------|
| `HideHeartbeatFrames.bambda` | Proxy > WebSockets history > filter > Bambda (`VIEW_FILTER`) | Hides keepalive frames: Engine.IO/Socket.IO bare `2`/`3`, JSON `type`/`event`/`op`/... naming `ping`/`pong`/`heartbeat`/`hb`/`keepalive`, and anything the companion tagged `wsprobe: heartbeat`. |
| `FreshTokenFromHandshake.bambda` | Proxy > HTTP history > right-click a WS upgrade > Extensions > Custom action (`CUSTOM_ACTION`) | Pulls the current token off the selected handshake (query, then `Sec-WebSocket-Protocol`, `Authorization`, or a cookie) and copies it, so you can paste a live token into a manual reconnect. |

Each file carries a header comment with the exact place it goes in Burp and what
it does. Import via the Bambda editor's import control, or open the file and copy
the block under `source:`.

## License

MIT, matching the wsprobe repository.
