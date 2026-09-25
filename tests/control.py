"""A clean control target: the same rooms-and-notes service as the fixture,
with every control the fixture leaves out put back in. It exists to prove the
tool stays quiet on a server that does the right thing, so a run against it
must produce zero insecure-shape observations.

Controls present:

- The upgrade requires a valid, unexpired, correctly signed token; no token
  means a 401 at the handshake.
- Identity comes from the token only; a URL-supplied identity is ignored.
- Origin is checked against an allowlist; any other Origin, or none, is
  refused with a 403.
- Object ownership is re-checked per frame against the connection identity.
- The claim action is idempotent per identity and item.
- Privileged subscribe topics are refused per frame.

Authorized-use note: this file is a test target, not a component of the tool.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlsplit

from websockets.asyncio.server import ServerConnection, serve

from .fixture import NOTES, verify_token

ALLOWED_ORIGINS = {"https://app.example.test"}


def _resolve_identity(path: str, headers) -> tuple[str | None, int | None]:
    """Return (identity, reject_status). Identity comes from the token only."""
    origin = headers.get("Origin")
    if origin not in ALLOWED_ORIGINS:
        return None, 403
    query = parse_qs(urlsplit(path).query)
    token = query.get("token", [None])[0] or headers.get("authorization")
    if token is None:
        return None, 401
    user = verify_token(token)
    if user is None:
        return None, 401
    return user, None


class Control:
    def __init__(self) -> None:
        self.claimed: set[tuple[str, str]] = set()
        self.balances: dict[str, int] = {}

    def process_request(self, connection: ServerConnection, request):
        identity, status = _resolve_identity(request.path, request.headers)
        if status is not None:
            return connection.respond(status, "refused\n")
        connection.wsprobe_identity = identity  # type: ignore[attr-defined]
        return None

    async def handler(self, connection: ServerConnection) -> None:
        identity = connection.wsprobe_identity  # type: ignore[attr-defined]
        async for raw in connection:
            try:
                frame = json.loads(raw)
            except json.JSONDecodeError:
                continue
            await self._dispatch(connection, identity, frame)

    async def _dispatch(self, connection: ServerConnection, identity: str, frame: dict) -> None:
        mtype = frame.get("type")
        cid = frame.get("cid")

        async def reply(payload: dict) -> None:
            if cid is not None:
                payload.setdefault("cid", cid)
            await connection.send(json.dumps(payload))

        if mtype == "ping":
            await connection.send(json.dumps({"type": "pong"}))
            return
        if mtype == "whoami":
            await reply({"type": "whoami", "user": identity})
            return
        if mtype == "read_note":
            owner = frame.get("owner")
            if owner != identity:
                await reply({"type": "error", "error": "forbidden"})
                return
            await reply({"type": "note", "owner": owner, "content": NOTES.get(owner)})
            return
        if mtype == "subscribe":
            if frame.get("topic") == "admin":
                await reply({"type": "error", "error": "forbidden"})
                return
            await reply({"type": "subscribed", "topic": frame.get("topic")})
            return
        if mtype == "claim":
            key = (identity, str(frame.get("item")))
            if key not in self.claimed:
                self.claimed.add(key)
                self.balances[identity] = self.balances.get(identity, 0) + 10
            await reply({"type": "claim.ok", "item": frame.get("item"), "balance": self.balances.get(identity, 0)})
            return
        await reply({"type": "error", "error": "unknown type"})


@asynccontextmanager
async def run_control(host: str = "127.0.0.1", port: int = 0):
    ctl = Control()
    async with serve(ctl.handler, host, port, process_request=ctl.process_request) as server:
        bound_port = list(server.sockets)[0].getsockname()[1]
        yield host, bound_port


async def _main(host: str, port: int) -> None:
    async with run_control(host, port) as (h, p):
        print(f"control listening on ws://{h}:{p}/socket", flush=True)
        await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="clean control WebSocket target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8798)
    args = parser.parse_args()
    try:
        asyncio.run(_main(args.host, args.port))
    except KeyboardInterrupt:
        pass
