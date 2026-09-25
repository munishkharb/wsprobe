"""The authenticated connection manager: the first-class Python API.

A ConnectionManager owns one identity against one channel. It acquires a token
per the profile's refresh policy, places the token where the profile says,
opens the socket, and runs a background reader that correlates each reply to
its request and routes server-initiated frames to a push queue. The `request`
coroutine returns the correlated reply; `send` is fire-and-forget; `pushes`
yields unsolicited frames.

The CLI verbs are thin wrappers over this object, which keeps the two honest.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import urllib.request
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator, Awaitable, Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import websockets

from collections import deque

from .capture import RECV, SEND, CaptureWriter, FrameRecord
from .codec import ack_id as _codec_ack_id
from .codec import codec_for
from .profile import (
    Auth,
    Channel,
    Correlation,
    Framing,
    LoginStep,
    Profile,
    RefreshPolicy,
    TokenLocation,
)

TokenProvider = Callable[[], "str | Awaitable[str]"]


class ConnectionError(RuntimeError):
    pass


def _extract(body: object, path: Optional[str]) -> str:
    if path is None:
        if isinstance(body, str):
            return body
        raise ConnectionError("token_extract is required when the login response is not a bare string")
    cur = body
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise ConnectionError(f"token_extract path {path!r} did not resolve")
        cur = cur[part]
    if not isinstance(cur, str):
        raise ConnectionError(f"token_extract path {path!r} did not resolve to a string")
    return cur


_TOKEN_PLACEHOLDER = "§token§"


def _substitute_token(template: object, token_param: str, token: str) -> object:
    """Deep-copy a login-frame template, replacing the placeholder string
    §token§ anywhere it appears. If the template used no placeholder at all,
    token_param is set at the top level as a fallback."""
    substituted = False

    def walk(node: object) -> object:
        nonlocal substituted
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, str) and _TOKEN_PLACEHOLDER in node:
            substituted = True
            return node.replace(_TOKEN_PLACEHOLDER, token)
        return node

    out = walk(template)
    if isinstance(out, dict) and not substituted:
        out[token_param] = token
    return out


class _TokenSource:
    """Fetches and, per policy, caches a token for one identity."""

    def __init__(self, auth: Auth, provider: Optional[TokenProvider], override: Optional[str]) -> None:
        self._auth = auth
        self._provider = provider
        self._override = override
        self._cached: Optional[str] = None
        self._cached_at: float = 0.0
        self.fetches = 0

    async def token(self) -> Optional[str]:
        if self._auth.login is LoginStep.none and self._provider is None and self._override is None:
            return None
        policy = self._auth.refresh
        now = asyncio.get_event_loop().time()
        if policy is RefreshPolicy.reuse and self._cached is not None:
            return self._cached
        if policy is RefreshPolicy.ttl and self._cached is not None:
            if now - self._cached_at < (self._auth.ttl_seconds or 0):
                return self._cached
        tok = await self._acquire()
        self._cached = tok
        self._cached_at = now
        return tok

    async def _acquire(self) -> str:
        self.fetches += 1
        if self._override is not None:
            return self._override
        if self._provider is not None:
            result = self._provider()
            if asyncio.iscoroutine(result):
                return await result
            return str(result)
        return await self._login()

    async def _login(self) -> str:
        auth = self._auth
        if auth.login is LoginStep.token_file:
            from pathlib import Path

            return _extract(Path(auth.token_file).read_text().strip(), auth.token_extract) if auth.token_extract else Path(auth.token_file).read_text().strip()
        if auth.login is LoginStep.command:
            # List-form argv, no shell; auth.command comes from the loaded connection
            # profile, not from untrusted network or user input.
            proc = await asyncio.create_subprocess_exec(  # nosemgrep: opengrep.rules.python.lang.security.audit.dangerous-asyncio-create-exec-audit
                *auth.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, err = await proc.communicate()
            if proc.returncode != 0:
                raise ConnectionError(f"login command failed: {err.decode('utf-8', 'replace').strip()}")
            text = out.decode("utf-8", "replace").strip()
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = text
            return _extract(parsed, auth.token_extract)
        if auth.login is LoginStep.http:
            return await asyncio.to_thread(self._http_login)
        raise ConnectionError(f"no login source for login step {auth.login.value}")

    def _http_login(self) -> str:
        h = self._auth.http
        data = json.dumps(h.body).encode() if h.body else None
        req = urllib.request.Request(h.url, data=data, method=h.method)
        req.add_header("content-type", "application/json")
        for k, v in h.headers.items():
            req.add_header(k, v)
        # URL is built from the loaded connection profile's validated http.url, not from
        # user input, so the file:// scheme risk urllib carries does not apply here.
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosemgrep: opengrep.rules.python.lang.security.audit.dynamic-urllib-use-detected
            body = resp.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = body
        return _extract(parsed, self._auth.token_extract)


@dataclass
class DialOptions:
    """Per-dial overrides used by the handshake matrix to bend one field at a
    time without editing the profile."""

    drop_token: bool = False
    origin: Optional[str] = None
    origin_set: bool = False
    extra_query: dict[str, str] = field(default_factory=dict)
    override_token: Optional[str] = None


class Connection:
    """A live socket with request/reply correlation over the profile's
    correlation keys."""

    # Decoded frame "type" values that are transport setup, never an application
    # reply: they are surfaced as pushes but never consumed by a pending request.
    _SETUP_TYPES = frozenset(
        {"engineio.open", "engineio.close", "socketio.connect", "socketio.empty"}
    )

    def __init__(
        self,
        ws,
        channel: Channel,
        capture: Optional[CaptureWriter],
        correlation: Optional[Correlation] = None,
    ) -> None:
        self._ws = ws
        self._channel = channel
        self._codec = codec_for(channel.handshake.framing)
        self._capture = capture
        self._correlation = correlation or channel.messages.correlation
        self._is_socketio = channel.handshake.framing is Framing.socketio
        # echo mode: key -> future. ack mode: ack id -> future. ordered: a FIFO.
        self._pending: dict[object, asyncio.Future] = {}
        self._ordered: deque[asyncio.Future] = deque()
        self._ordered_skip = 0  # stale replies to drop after ordered-request timeouts
        self._pushes: asyncio.Queue = asyncio.Queue()
        self._reader = asyncio.create_task(self._read_loop())
        self._cid = 0

    def _corr_key(self, frame: object) -> Optional[str]:
        if not isinstance(frame, dict):
            return None
        keys = self._channel.messages.correlation_keys
        parts = [str(frame.get(k)) for k in keys if k in frame]
        return "|".join(parts) if parts else None

    def _is_heartbeat(self, frame: object) -> bool:
        if not isinstance(frame, dict):
            return False
        tf = self._channel.messages.type_field
        if str(frame.get(tf)) in set(self._channel.heartbeat.types):
            return True
        # Engine.IO keepalive is transport-level and always dropped.
        return str(frame.get("type")) in {"engineio.ping", "engineio.pong"}

    def _is_setup(self, frame: object) -> bool:
        return isinstance(frame, dict) and str(frame.get("type")) in self._SETUP_TYPES

    async def _read_loop(self) -> None:
        try:
            async for raw in self._ws:
                try:
                    frame = self._codec.decode(raw)
                except Exception:
                    frame = {"_raw": raw if isinstance(raw, str) else raw.decode("utf-8", "replace")}
                if self._capture is not None:
                    self._capture.write(FrameRecord(RECV, frame, self._channel.name))
                # Answer an Engine.IO ping with a pong so the socket stays open.
                if self._is_socketio and isinstance(frame, dict) and frame.get("type") == "engineio.ping":
                    try:
                        await self._ws.send("3")
                    except Exception:
                        pass
                    continue
                if self._is_heartbeat(frame):
                    continue
                if self._is_setup(frame):
                    await self._pushes.put(frame)
                    continue
                if self._resolve(frame):
                    continue
                await self._pushes.put(frame)
        except websockets.ConnectionClosed:
            pass

    def _resolve(self, frame: object) -> bool:
        """Pair an incoming application frame to a pending request per the
        correlation mode. Returns True if it was consumed as a reply."""
        if self._correlation is Correlation.ordered:
            # A request that timed out leaves its reply still in flight. Drop
            # exactly that many arriving frames as stale, so a late reply never
            # mispairs with a newer request and desyncs the rest of the socket.
            if self._ordered_skip > 0:
                self._ordered_skip -= 1
                return True
            while self._ordered:
                fut = self._ordered.popleft()
                if not fut.done():
                    fut.set_result(frame)
                    return True
            return False
        if self._correlation is Correlation.ack:
            aid = _codec_ack_id(self._codec, frame)
            fut = self._pending.pop(aid, None) if aid is not None else None
            if fut is not None and not fut.done():
                fut.set_result(frame)
                return True
            return False
        # echo (default)
        key = self._corr_key(frame)
        fut = self._pending.pop(key, None) if key is not None else None
        if fut is not None and not fut.done():
            fut.set_result(frame)
            return True
        return False

    async def send(self, frame: object) -> None:
        if self._capture is not None:
            self._capture.write(FrameRecord(SEND, frame, self._channel.name))
        await self._ws.send(self._codec.encode(frame))

    async def request(self, frame: object, timeout: float = 5.0) -> object:
        """Send a frame and return its correlated reply, paired per the
        channel's correlation mode.

        echo: the first correlation key is stamped with an auto-incrementing id
        if the frame carries none, and the reply is matched on that key.
        ordered: the next application frame the server sends is the reply.
        ack: an ack id is stamped and the codec pairs the acknowledgement.
        """
        frame = dict(frame) if isinstance(frame, dict) else frame
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()

        if self._correlation is Correlation.ordered:
            self._ordered.append(fut)
            await self.send(frame)
            try:
                return await asyncio.wait_for(fut, timeout)
            except asyncio.TimeoutError:
                # The reply may still arrive later; ensure it is dropped as stale
                # rather than handed to the next request.
                if fut in self._ordered:
                    self._ordered.remove(fut)
                self._ordered_skip += 1
                raise
            finally:
                if fut in self._ordered:
                    self._ordered.remove(fut)

        if self._correlation is Correlation.ack:
            self._cid += 1
            aid = self._cid
            if isinstance(frame, dict):
                frame.setdefault("cid", aid)
            self._pending[aid] = fut
            await self.send(frame)
            try:
                return await asyncio.wait_for(fut, timeout)
            finally:
                self._pending.pop(aid, None)

        # echo (default)
        if isinstance(frame, dict):
            keys = self._channel.messages.correlation_keys
            if keys and not any(k in frame for k in keys):
                self._cid += 1
                frame[keys[0]] = self._cid
        key = self._corr_key(frame)
        if key is not None:
            self._pending[key] = fut
        await self.send(frame)
        if key is None:
            raise ConnectionError("frame carries no correlation value; use send() for uncorrelated frames")
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(key, None)

    async def next_push(self, timeout: float = 5.0) -> object:
        return await asyncio.wait_for(self._pushes.get(), timeout)

    async def pushes(self) -> AsyncIterator[object]:
        while True:
            yield await self._pushes.get()

    async def close(self) -> None:
        self._reader.cancel()
        try:
            await self._ws.close()
        except Exception:
            pass


class ConnectionManager:
    """Owns one identity against one channel and dials fresh sockets from it."""

    def __init__(
        self,
        profile: Profile,
        channel: Optional[str] = None,
        token_provider: Optional[TokenProvider] = None,
        token: Optional[str] = None,
        identity: Optional[str] = None,
        capture_path: Optional[str] = None,
        tls_verify: bool = True,
    ) -> None:
        self.profile = profile
        self.channel = profile.channel(channel)
        self.identity = identity
        self._tls_verify = tls_verify
        self._capture_path = capture_path
        self._source = _TokenSource(self.channel.auth, token_provider, token)

    @property
    def token_fetches(self) -> int:
        return self._source.fetches

    def _build_uri(self, token: Optional[str], opts: DialOptions) -> tuple[str, dict, list[str]]:
        hs = self.channel.handshake
        auth = self.channel.auth
        parsed = urlparse(hs.url)
        # Seed from any query string already in the handshake URL (e.g. a
        # Socket.IO ?EIO=4&transport=websocket), so it is preserved rather than
        # dropped when the URL is rebuilt, then layer the profile's query and
        # any per-dial extras on top.
        query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        query.update(hs.query)
        query.update(opts.extra_query)
        headers = dict(hs.headers)
        subprotocols: list[str] = [hs.subprotocol] if hs.subprotocol else []

        use_token = None if opts.drop_token else (opts.override_token or token)
        if use_token is not None:
            loc = auth.token_location
            if loc is TokenLocation.query:
                query[auth.token_param] = use_token
            elif loc is TokenLocation.header:
                headers[auth.token_param] = use_token
            elif loc is TokenLocation.subprotocol:
                subprotocols.append(f"{auth.token_param}.{use_token}")
            elif loc is TokenLocation.cookie:
                cookie = f"{auth.token_param}={use_token}"
                existing = headers.get("Cookie")
                headers["Cookie"] = f"{existing}; {cookie}" if existing else cookie
        new = parsed._replace(query=urlencode(query))
        return urlunparse(new), headers, subprotocols

    def _ssl_arg(self, uri: str):
        if not uri.startswith("wss://"):
            return None
        if self._tls_verify:
            return None
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _open(self, opts: DialOptions, capture: Optional[CaptureWriter]) -> Connection:
        token = None if opts.drop_token else (opts.override_token or await self._source.token())
        uri, headers, subprotocols = self._build_uri(token, opts)
        kwargs: dict = {"additional_headers": headers}
        if subprotocols:
            kwargs["subprotocols"] = subprotocols
        if opts.origin_set:
            kwargs["origin"] = opts.origin
        elif self.channel.handshake.origin is not None:
            kwargs["origin"] = self.channel.handshake.origin
        ssl_ctx = self._ssl_arg(uri)
        if ssl_ctx is not None:
            kwargs["ssl"] = ssl_ctx

        ws = await websockets.connect(uri, **kwargs)
        conn = Connection(ws, self.channel, capture)

        if self.channel.handshake.framing is Framing.socketio:
            await self._socketio_setup(conn, None if opts.drop_token else token)
        elif self.channel.auth.token_location is TokenLocation.login_frame and token is not None and not opts.drop_token:
            await conn.send(self._login_frame(token))

        return conn

    def _login_frame(self, token: str) -> dict:
        """Build the login handshake frame. Uses the profile's login_frame
        template when set (token placed at token_param, and any '§token§'
        string substituted), else the minimal {type: login, token_param: token}."""
        auth = self.channel.auth
        tf = self.channel.messages.type_field
        if auth.login_frame is not None:
            return _substitute_token(auth.login_frame, auth.token_param, token)
        return {tf: "login", auth.token_param: token}

    async def _socketio_setup(self, conn: "Connection", token: Optional[str]) -> None:
        """Drive the Engine.IO/Socket.IO v4 connect handshake on websocket
        transport: consume the server's `0{...}` open, then send the Socket.IO
        `40` connect (carrying auth when a token rides the connect packet), and
        consume the server's connect acknowledgement."""
        auth = self.channel.auth
        # The server sends the Engine.IO open frame first; drain it if it lands.
        try:
            await conn.next_push(timeout=3.0)
        except asyncio.TimeoutError:
            pass
        if token is not None and auth.token_location is TokenLocation.login_frame:
            payload = json.dumps({auth.token_param: token}, separators=(",", ":"))
            await conn._ws.send(f"40{payload}")
        else:
            await conn._ws.send("40")
        # Drain the Socket.IO connect acknowledgement.
        try:
            await conn.next_push(timeout=3.0)
        except asyncio.TimeoutError:
            pass

    @asynccontextmanager
    async def dial(self, opts: Optional[DialOptions] = None) -> AsyncIterator[Connection]:
        """Open one authenticated socket. Token freshness follows the profile
        refresh policy, so per-dial mints a new token here."""
        opts = opts or DialOptions()
        capture = None
        writer = None
        if self._capture_path is not None:
            # Redact the profile's configured token field too, whatever it is
            # named, so a login-frame or custom token_param is not written in
            # cleartext to the capture.
            writer = CaptureWriter(self._capture_path, extra_redact_keys=[self.channel.auth.token_param])
            capture = writer.__enter__()
        conn = await self._open(opts, capture)
        try:
            yield conn
        finally:
            await conn.close()
            if writer is not None:
                writer.__exit__(None, None, None)

    async def try_dial(self, opts: Optional[DialOptions] = None) -> tuple[bool, Optional[str]]:
        """Attempt only the upgrade. Returns (upgraded, error_tag). Used by the
        handshake matrix, which cares whether the socket opened at all."""
        opts = opts or DialOptions()
        try:
            conn = await self._open(opts, None)
        except websockets.InvalidStatus as exc:
            return False, f"http-{exc.response.status_code}"
        except websockets.InvalidHandshake as exc:
            return False, f"handshake-{type(exc).__name__}"
        except (OSError, asyncio.TimeoutError) as exc:
            return False, f"transport-{type(exc).__name__}"
        await conn.close()
        return True, None
