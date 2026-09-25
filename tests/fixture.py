"""A synthetic vulnerable WebSocket server, the de-branded stand-in for a real
target. It is a minimal rooms-and-notes service that seeds one clear bug per
class from the attack catalog, so every capability can be demonstrated end to
end against it with no engagement data and no live target.

Seeded bugs:

- Identity bound only at the handshake. The connecting identity is stamped on
  the connection at the upgrade; object ownership is read from a frame field and
  never re-checked against the connection, so a self-opened authenticated socket
  reads another user's note by swapping an id. This is the BOLA headline.
- Unauthenticated upgrade. A connection with no token still upgrades, bound to
  an anonymous identity.
- Identity from a URL parameter. A `?user=` query parameter overrides the token
  identity, so the connection binds to a URL-supplied principal.
- No Origin validation. The server never inspects Origin, so a cross-site
  handshake succeeds.
- A frame field reflected to other clients unvalidated, so a payload posted by
  one client is fanned out verbatim to the others.
- A state-changing claim with no idempotency guard, so a replayed claim frame
  applies again.

The server does validate a token when one is presented without a `?user=`
override: an expired or bad-signature token is rejected at the upgrade. That is
the one control present, so the matrix's expired and foreign rows read as
rejections while the unauthenticated and URL-identity rows read as insecure.

Authorized-use note: this file is a test target, not a component of the tool.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import time
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlsplit

from websockets.asyncio.server import ServerConnection, serve

_SECRET = b"wsprobe-fixture-signing-key"
_FOREIGN_SECRET = b"a-different-issuer-key"

# Seeded per-user private data. The BOLA demonstration reads one user's note on
# another user's socket.
NOTES = {
    "alice": "alice private note: meeting at the old pier, code 4471",
    "bob": "bob private note: brokerage password hint is the dog's name",
}


def _sign(payload: str, secret: bytes) -> str:
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


def mint_token(user: str, ttl: float = 3600.0, secret: bytes = _SECRET) -> str:
    exp = int(time.time() + ttl)
    payload = f"{user}.{exp}"
    return f"{payload}.{_sign(payload, secret)}"


def mint_expired_token(user: str) -> str:
    return mint_token(user, ttl=-3600.0)


def mint_foreign_token(user: str) -> str:
    return mint_token(user, ttl=3600.0, secret=_FOREIGN_SECRET)


def verify_token(token: str) -> str | None:
    try:
        user, exp, sig = token.split(".")
    except ValueError:
        return None
    if not hmac.compare_digest(_sign(f"{user}.{exp}", _SECRET), sig):
        return None
    if int(exp) < time.time():
        return None
    return user


def _resolve_identity(path: str, headers) -> tuple[str | None, str | None]:
    """Return (identity, reject_reason). A reject_reason means refuse the
    upgrade with a 401."""
    query = parse_qs(urlsplit(path).query)
    if "user" in query:
        # BUG: a URL-supplied identity overrides the token.
        return query["user"][0], None
    token = None
    if "token" in query:
        token = query["token"][0]
    elif "authorization" in headers:
        token = headers["authorization"]
    if token is not None:
        user = verify_token(token)
        if user is None:
            return None, "invalid-token"
        return user, None
    # BUG: no token still upgrades, as anon.
    return "anon", None


class Fixture:
    def __init__(self) -> None:
        self.balances: dict[str, int] = {}
        self.connections: set[ServerConnection] = set()
        # A deliberately injectable SQL backend for the "login" frame. This
        # seeds the injection class (catalog #9) so an HTTP injection tool can
        # be driven through `wsprobe bridge` at a frame field end to end.
        import sqlite3

        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        self._db.execute("CREATE TABLE users (username TEXT, password TEXT, secret TEXT)")
        self._db.executemany(
            "INSERT INTO users VALUES (?, ?, ?)",
            [("alice", "wonderland", "flag-alice"), ("bob", "builder", "flag-bob")],
        )
        self._db.commit()

    def process_request(self, connection: ServerConnection, request):
        identity, reason = _resolve_identity(request.path, request.headers)
        if reason is not None:
            # NOTE: no Origin check anywhere here. That is the CSWSH bug.
            return connection.respond(401, "unauthorized\n")
        connection.wsprobe_identity = identity  # type: ignore[attr-defined]
        return None

    async def handler(self, connection: ServerConnection) -> None:
        identity = getattr(connection, "wsprobe_identity", "anon")
        self.connections.add(connection)
        try:
            async for raw in connection:
                try:
                    frame = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                await self._dispatch(connection, identity, frame)
        finally:
            self.connections.discard(connection)

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
            # BUG: object ownership is read from the frame, never re-checked
            # against the connection identity.
            owner = frame.get("owner")
            await reply({"type": "note", "owner": owner, "content": NOTES.get(owner)})
            return

        if mtype == "post":
            text = frame.get("text", "")
            room = frame.get("room", "lobby")
            await reply({"type": "post.ok", "room": room})
            # BUG: the text is fanned out to every other client unvalidated.
            push = json.dumps({"type": "message", "room": room, "from": identity, "text": text})
            for peer in list(self.connections):
                if peer is not connection:
                    await peer.send(push)
            return

        if mtype == "subscribe":
            # BUG: no message-level authorization; anon can subscribe to admin.
            await reply({"type": "subscribed", "topic": frame.get("topic")})
            return

        if mtype == "login":
            # BUG: the username is concatenated straight into the SQL, so a
            # frame field is a first-class SQL injection sink. The reply is a
            # boolean oracle (welcome vs denied), so a boolean-based injection
            # through the bridge flips it.
            username = frame.get("username", "")
            password = frame.get("password", "")
            query = (
                "SELECT username FROM users WHERE username = '"
                + str(username)
                + "' AND password = '"
                + str(password)
                + "'"
            )
            try:
                row = self._db.execute(query).fetchone()  # nosemgrep: injectable-by-design test fixture
                if row:
                    await reply({"type": "login.ok", "user": row[0]})
                else:
                    await reply({"type": "login.denied"})
            except Exception as exc:
                await reply({"type": "login.error", "error": str(exc)})
            return

        if mtype == "claim":
            # BUG: no idempotency. Every claim grants again, so a replayed
            # claim frame applies twice.
            self.balances[identity] = self.balances.get(identity, 0) + 10
            await reply({"type": "claim.ok", "item": frame.get("item"), "balance": self.balances[identity]})
            return

        await reply({"type": "error", "error": f"unknown type {mtype!r}"})


@asynccontextmanager
async def run_fixture(host: str = "127.0.0.1", port: int = 0):
    """Start the fixture and yield (host, port). port=0 asks the OS for a free
    port; the assigned port is read back from the listening socket."""
    fx = Fixture()
    async with serve(fx.handler, host, port, process_request=fx.process_request) as server:
        sock = list(server.sockets)[0]
        bound_port = sock.getsockname()[1]
        yield host, bound_port


async def _main(host: str, port: int) -> None:
    async with run_fixture(host, port) as (h, p):
        print(f"fixture listening on ws://{h}:{p}/socket", flush=True)
        await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="synthetic vulnerable WebSocket fixture")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8799)
    args = parser.parse_args()
    try:
        asyncio.run(_main(args.host, args.port))
    except KeyboardInterrupt:
        pass
