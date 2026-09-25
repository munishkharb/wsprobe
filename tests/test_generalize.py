"""End-to-end tests for the app-agnostic features: text framing, the
Socket.IO/Engine.IO codec and connect handshake, the ordered and ack
correlation modes, cookie token carriage, and the login-frame template.

Each test drives a small purpose-built server written inline with the same
`websockets` library the tool uses, so the flow is exercised over a real
socket, not mocked. None of these servers is a vulnerable target; they exist
only to prove the transport plumbing.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest
from websockets.asyncio.server import serve

from wsprobe import ConnectionManager
from wsprobe.codec import codec_for
from wsprobe.profile import (
    Auth,
    Channel,
    Correlation,
    Framing,
    Handshake,
    MessageMap,
    Profile,
    TokenLocation,
)


# --- codec units -------------------------------------------------------------

def test_text_codec_roundtrip():
    c = codec_for(Framing.text)
    assert c.encode("raw string") == "raw string"
    assert c.encode({"a": 1}) == '{"a":1}'
    assert c.decode("plain") == "plain"
    assert c.decode('{"a":1}') == {"a": 1}


def test_socketio_codec_event_and_ack():
    c = codec_for(Framing.socketio)
    assert c.encode({"event": "whoami", "data": {"x": 1}, "cid": 7}) == '427["whoami",{"x":1}]'
    assert c.encode({"event": "hi", "data": None}) == '42["hi",null]'
    assert c.decode("0" + json.dumps({"sid": "a"}))["type"] == "engineio.open"
    assert c.decode("2")["type"] == "engineio.ping"
    ev = c.decode('42["news",{"n":5}]')
    assert ev["event"] == "news" and ev["data"] == {"n": 5}
    ack = c.decode('439[{"ok":true}]')
    assert ack["cid"] == 9 and ack["data"] == {"ok": True}


# --- ordered correlation over a real socket ----------------------------------

@asynccontextmanager
async def _serve(handler):
    async with serve(handler, "127.0.0.1", 0) as server:
        port = list(server.sockets)[0].getsockname()[1]
        yield "127.0.0.1", port


def _profile(host, port, framing=Framing.json, correlation=Correlation.echo,
             token_location=TokenLocation.query, login=None, login_frame=None):
    return Profile(
        name="t",
        channels=[Channel(
            name="default",
            handshake=Handshake(url=f"ws://{host}:{port}/socket", framing=framing),
            auth=Auth(token_location=token_location, token_param="token",
                      login=login or __import__("wsprobe.profile", fromlist=["LoginStep"]).LoginStep.none,
                      login_frame=login_frame),
            messages=MessageMap(type_field="type", correlation_keys=["cid"], correlation=correlation),
        )],
    )


async def test_ordered_correlation_pairs_without_echoed_id():
    """A server that never echoes a correlation id, answering strictly in order.
    Echo mode would time out here; ordered mode pairs the replies."""
    async def handler(ws):
        async for raw in ws:
            frame = json.loads(raw)
            # Reply carries NO cid: the ordered mode must still pair it.
            await ws.send(json.dumps({"type": "reply", "for": frame.get("type")}))

    async with _serve(handler) as (host, port):
        prof = _profile(host, port, correlation=Correlation.ordered)
        mgr = ConnectionManager(prof, token="x")
        async with mgr.dial() as conn:
            r1 = await conn.request({"type": "first"})
            r2 = await conn.request({"type": "second"})
        assert r1["for"] == "first"
        assert r2["for"] == "second"


async def test_ack_correlation_over_socketio():
    """A minimal Socket.IO/Engine.IO v4 server: open, connect, then ack each
    event with its ack id. Proves the connect handshake, ping/pong, and ack
    correlation end to end."""
    async def handler(ws):
        await ws.send("0" + json.dumps({"sid": "s", "pingInterval": 25000, "pingTimeout": 20000}))
        async for raw in ws:
            if raw == "40":
                await ws.send("40" + json.dumps({"sid": "s2"}))
                continue
            if raw == "3":  # a pong from the client, ignore
                continue
            if raw.startswith("42"):
                # 42<ackid>["event",data] -> ack 43<ackid>[{"echo":data}]
                body = raw[2:]
                i = 0
                while i < len(body) and body[i].isdigit():
                    i += 1
                ackid, payload = body[:i], json.loads(body[i:])
                data = payload[1] if len(payload) > 1 else None
                await ws.send(f"43{ackid}" + json.dumps([{"echo": data}]))

    async with _serve(handler) as (host, port):
        prof = _profile(host, port, framing=Framing.socketio, correlation=Correlation.ack)
        mgr = ConnectionManager(prof, token="x")
        async with mgr.dial() as conn:
            reply = await conn.request({"event": "getRecord", "data": {"id": 7}})
        assert reply["type"] == "socketio.ack"
        assert reply["data"]["echo"] == {"id": 7}


async def test_cookie_token_carriage():
    """The token rides a Cookie header when token_location is cookie."""
    seen = {}

    async def handler(ws):
        seen["cookie"] = ws.request.headers.get("Cookie")
        async for raw in ws:
            await ws.send(json.dumps({"type": "ok", **json.loads(raw)}))

    async with _serve(handler) as (host, port):
        prof = _profile(host, port, token_location=TokenLocation.cookie)
        mgr = ConnectionManager(prof, token="sekret-sid")
        async with mgr.dial() as conn:
            await conn.request({"type": "ping"})
        assert seen["cookie"] == "token=sekret-sid"


async def test_login_frame_template_substitutes_token():
    """A login-frame template with §token§ is filled with the real token as the
    first frame on the socket."""
    from wsprobe.profile import LoginStep

    seen = {}

    async def handler(ws):
        first = json.loads(await ws.recv())
        seen["login"] = first
        async for raw in ws:
            await ws.send(json.dumps({"type": "ok", **json.loads(raw)}))

    async with _serve(handler) as (host, port):
        prof = _profile(
            host, port,
            token_location=TokenLocation.login_frame,
            login=LoginStep.none,
            login_frame={"type": "auth", "params": {"jwt": "§token§"}},
        )
        mgr = ConnectionManager(prof, token="the-jwt")
        async with mgr.dial() as conn:
            await conn.request({"type": "ping"})
        assert seen["login"] == {"type": "auth", "params": {"jwt": "the-jwt"}}
