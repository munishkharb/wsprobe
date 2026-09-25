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


# --- HTTP-to-WebSocket bridge ------------------------------------------------

def test_substitute_fuzz_reaches_nested_fields():
    from wsprobe.bridge import FUZZ, substitute_fuzz

    tmpl = {"type": "search", "q": FUZZ, "meta": {"raw": FUZZ}, "tags": [FUZZ]}
    out = substitute_fuzz(tmpl, "x' OR 1=1--")
    assert out == {
        "type": "search",
        "q": "x' OR 1=1--",
        "meta": {"raw": "x' OR 1=1--"},
        "tags": ["x' OR 1=1--"],
    }


def test_bridge_carries_http_body_into_a_frame_field():
    """An HTTP POST body is substituted into a §FUZZ§ frame field, sent on a
    real authenticated socket, and the reply comes back as the HTTP body. The
    listener is bound to loopback only."""
    import http.client
    import threading as _threading

    from websockets.asyncio.server import serve as _serve

    from wsprobe import serve_bridge
    from wsprobe.bridge import FUZZ

    # A background asyncio loop hosting a tiny echo WebSocket server.
    holder: dict = {}
    loop = asyncio.new_event_loop()

    async def _start():
        async def handler(ws):
            async for raw in ws:
                frame = json.loads(raw)
                await ws.send(json.dumps({"type": "result", "saw": frame.get("q")}))

        srv = await _serve(handler, "127.0.0.1", 0)
        holder["port"] = list(srv.sockets)[0].getsockname()[1]

    loop.run_until_complete(_start())
    ws_thread = _threading.Thread(target=loop.run_forever, daemon=True)
    ws_thread.start()

    prof = _profile("127.0.0.1", holder["port"], correlation=Correlation.ordered)
    mgr = ConnectionManager(prof, token="x")
    httpd = serve_bridge(mgr, {"type": "search", "q": FUZZ}, port=0)
    assert httpd.server_address[0] == "127.0.0.1"  # loopback only
    bridge_port = httpd.server_address[1]
    http_thread = _threading.Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()

    try:
        conn = http.client.HTTPConnection("127.0.0.1", bridge_port, timeout=5)
        conn.request("POST", "/", body="admin' OR '1'='1")
        resp = conn.getresponse()
        assert resp.status == 200
        payload = json.loads(resp.read())
        # The HTTP body reached the frame's q field and the reply came back.
        assert payload["saw"] == "admin' OR '1'='1"
    finally:
        httpd.shutdown()
        loop.call_soon_threadsafe(loop.stop)


# --- handshake URL query preservation (regression) ---------------------------

async def test_handshake_url_query_is_preserved():
    """A query string embedded in the handshake URL (e.g. Socket.IO's
    ?EIO=4&transport=websocket) must survive the URI rebuild. Regression for a
    bug where _build_uri replaced the whole query and a Socket.IO upgrade 400ed."""
    seen = {}

    async def handler(ws):
        seen["query"] = urlsplit(ws.request.path).query
        async for raw in ws:
            await ws.send(json.dumps({"type": "ok"}))

    from urllib.parse import urlsplit

    async with _serve(handler) as (host, port):
        prof = Profile(name="t", channels=[Channel(
            name="default",
            handshake=Handshake(url=f"ws://{host}:{port}/socket?EIO=4&transport=websocket"),
            messages=MessageMap(type_field="type", correlation=Correlation.ordered),
        )])
        mgr = ConnectionManager(prof, token="x")
        async with mgr.dial() as conn:
            await conn.request({"type": "ping"})
        assert "EIO=4" in seen["query"]
        assert "transport=websocket" in seen["query"]
        assert "token=x" in seen["query"]  # the token still lands in the query


# --- bridge carries an injection payload to a SQL sink (regression) ----------

def test_bridge_delivers_injection_to_a_sql_sink():
    """End-to-end proof of the bridge's purpose: an HTTP request through the
    bridge reaches the fixture's injectable login frame, and a SQL tautology in
    the injected field flips the boolean oracle (denied -> ok). This is the
    integration an HTTP injection tool relies on."""
    import http.client
    import threading as _threading
    from urllib.parse import quote

    from wsprobe import serve_bridge
    from wsprobe.bridge import FUZZ

    from .fixture import run_fixture

    holder: dict = {}
    loop = asyncio.new_event_loop()

    async def _start():
        import contextlib

        cm = run_fixture()
        holder["cm"] = cm
        host, port = await cm.__aenter__()
        holder["addr"] = (host, port)

    loop.run_until_complete(_start())
    _threading.Thread(target=loop.run_forever, daemon=True).start()

    host, port = holder["addr"]
    prof = Profile(name="sqli", channels=[Channel(
        name="default",
        handshake=Handshake(url=f"ws://{host}:{port}/socket"),
        messages=MessageMap(type_field="type", correlation_keys=["cid"]),
    )])
    mgr = ConnectionManager(prof)  # anon upgrade, like the real bridge run
    httpd = serve_bridge(mgr, {"type": "login", "username": FUZZ, "password": "nope"}, port=0)
    bp = httpd.server_address[1]
    _threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def _get(fuzz: str) -> dict:
        c = http.client.HTTPConnection("127.0.0.1", bp, timeout=5)
        c.request("GET", f"/?fuzz={quote(fuzz)}")
        return json.loads(c.getresponse().read())

    try:
        assert _get("nobody")["type"] == "login.denied"      # honest failure
        injected = _get("x' OR '1'='1' -- ")                 # tautology through the bridge
        assert injected["type"] == "login.ok"                # the sink was reached and flipped
    finally:
        httpd.shutdown()
        loop.call_soon_threadsafe(loop.stop)


# --- capture redacts the configured token field (audit H3) --------------------

def test_capture_redacts_custom_token_param(tmp_path):
    """A login-frame carrying the token under a profile-configured field name the
    static pattern does not match (e.g. 'jwt') is still redacted in the capture."""
    from wsprobe.capture import CaptureWriter, FrameRecord, SEND, read_capture

    w = CaptureWriter(tmp_path / "c.ndjson", extra_redact_keys=["jwt"])
    with w:
        w.write(FrameRecord(SEND, {"type": "auth", "params": {"jwt": "SECRET-JWT"}, "user": "alice"}))
    rec = read_capture(tmp_path / "c.ndjson")[0]
    assert rec.frame["params"]["jwt"] == "[redacted]"
    assert rec.frame["user"] == "alice"


# --- ordered-mode timeout does not desync the socket (audit medium) -----------

async def test_ordered_timeout_does_not_mispair_next_request():
    """A slow reply that arrives after its request timed out must be dropped as
    stale, not handed to the next request. Regression for the ordered-mode
    off-by-one desync."""
    import asyncio as _a

    async def handler(ws):
        first = True
        async for raw in ws:
            msg = json.loads(raw)
            if first:
                first = False
                await _a.sleep(0.5)  # late: past the caller's timeout
                await ws.send(json.dumps({"reply_to": msg["n"]}))
            else:
                await ws.send(json.dumps({"reply_to": msg["n"]}))

    async with _serve(handler) as (host, port):
        prof = _profile(host, port, correlation=Correlation.ordered)
        mgr = ConnectionManager(prof, token="x")
        async with mgr.dial() as conn:
            try:
                await conn.request({"n": 1}, timeout=0.2)
                assert False, "first request should have timed out"
            except _a.TimeoutError:
                pass
            await _a.sleep(0.5)  # let the stale reply for n=1 arrive and be dropped
            r2 = await conn.request({"n": 2}, timeout=2.0)
        assert r2["reply_to"] == 2  # got its own reply, not the stale n=1
