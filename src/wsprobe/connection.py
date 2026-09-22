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
from urllib.parse import urlencode, urlparse, urlunparse

import websockets

from .capture import RECV, SEND, CaptureWriter, FrameRecord
from .codec import codec_for
from .profile import (
    Auth,
    Channel,
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
            proc = await asyncio.create_subprocess_exec(
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
        with urllib.request.urlopen(req, timeout=15) as resp:
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

    def __init__(self, ws, channel: Channel, capture: Optional[CaptureWriter]) -> None:
        self._ws = ws
        self._channel = channel
        self._codec = codec_for(channel.handshake.framing)
        self._capture = capture
        self._pending: dict[str, asyncio.Future] = {}
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
        return str(frame.get(tf)) in set(self._channel.heartbeat.types)

    async def _read_loop(self) -> None:
        try:
            async for raw in self._ws:
                try:
                    frame = self._codec.decode(raw)
                except Exception:
                    frame = {"_raw": raw if isinstance(raw, str) else raw.decode("utf-8", "replace")}
                if self._capture is not None:
                    self._capture.write(FrameRecord(RECV, frame, self._channel.name))
                if self._is_heartbeat(frame):
                    continue
                key = self._corr_key(frame)
                fut = self._pending.pop(key, None) if key is not None else None
                if fut is not None and not fut.done():
                    fut.set_result(frame)
                else:
                    await self._pushes.put(frame)
        except websockets.ConnectionClosed:
            pass

    async def send(self, frame: object) -> None:
        if self._capture is not None:
            self._capture.write(FrameRecord(SEND, frame, self._channel.name))
        await self._ws.send(self._codec.encode(frame))

    async def request(self, frame: object, timeout: float = 5.0) -> object:
        """Send a frame and return its correlated reply.

        If the frame carries no correlation value the manager stamps the first
        correlation key with an auto-incrementing id, so a caller does not have
        to track it by hand.
        """
        frame = dict(frame) if isinstance(frame, dict) else frame
        if isinstance(frame, dict):
            keys = self._channel.messages.correlation_keys
            if keys and not any(k in frame for k in keys):
                self._cid += 1
                frame[keys[0]] = self._cid
        key = self._corr_key(frame)
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
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
        query = dict(hs.query)
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

        if self.channel.auth.token_location is TokenLocation.login_frame and token is not None and not opts.drop_token:
            ws = await websockets.connect(uri, **kwargs)
            conn = Connection(ws, self.channel, capture)
            tf = self.channel.messages.type_field
            await conn.send({tf: "login", self.channel.auth.token_param: token})
            return conn

        ws = await websockets.connect(uri, **kwargs)
        return Connection(ws, self.channel, capture)

    @asynccontextmanager
    async def dial(self, opts: Optional[DialOptions] = None) -> AsyncIterator[Connection]:
        """Open one authenticated socket. Token freshness follows the profile
        refresh policy, so per-dial mints a new token here."""
        opts = opts or DialOptions()
        capture = None
        writer = None
        if self._capture_path is not None:
            writer = CaptureWriter(self._capture_path)
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
