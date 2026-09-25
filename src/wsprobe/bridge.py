"""HTTP-to-WebSocket bridge.

A loopback HTTP listener that turns an ordinary HTTP request into one frame on
an authenticated WebSocket and returns the correlated reply as the HTTP body.
The point is reach: an HTTP-native tool (an injection tester, a fuzzer, a
request-replayer) that cannot speak WebSocket can now drive a single frame
field, while wsprobe owns the handshake, the token refresh, and the framing.

The injection point is a `§FUZZ§` placeholder in a frame template. Each incoming
HTTP request supplies the value that replaces it: the request body when there is
one, else the `fuzz` query parameter. The substituted frame is sent on a fresh
authenticated socket (token freshness follows the profile), and the reply is
written back as the HTTP response body.

Safety: the listener binds 127.0.0.1 only, and requests are paced one at a time
(a single in-flight frame), never bursted. It is a local test harness, not a
public proxy.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from .connection import ConnectionManager

FUZZ = "§FUZZ§"


def substitute_fuzz(template: object, value: str) -> object:
    """Replace every §FUZZ§ occurrence in a frame template with value."""
    if isinstance(template, dict):
        return {k: substitute_fuzz(v, value) for k, v in template.items()}
    if isinstance(template, list):
        return [substitute_fuzz(v, value) for v in template]
    if isinstance(template, str):
        return template.replace(FUZZ, value)
    return template


class _Bridge:
    """Holds the shared connection manager and a lock that keeps one frame in
    flight at a time, so the bridge paces rather than bursts."""

    def __init__(self, manager: ConnectionManager, frame_template: object, timeout: float) -> None:
        self.manager = manager
        self.template = frame_template
        self.timeout = timeout
        self._lock = threading.Lock()

    def handle(self, value: str) -> object:
        with self._lock:
            return asyncio.run(self._send(value))

    async def _send(self, value: str) -> object:
        frame = substitute_fuzz(self.template, value)
        async with self.manager.dial() as conn:
            return await conn.request(frame, timeout=self.timeout)


def _make_handler(bridge: _Bridge):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep the console quiet
            pass

        def _value(self) -> str:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                return self.rfile.read(length).decode("utf-8", "replace")
            qs = parse_qs(urlsplit(self.path).query)
            return qs.get("fuzz", [""])[0]

        def _respond(self) -> None:
            try:
                reply = bridge.handle(self._value())
                body = json.dumps(reply).encode("utf-8")
                self.send_response(200)
            except Exception as exc:  # a timeout or a closed socket is a 502
                body = json.dumps({"error": repr(exc)}).encode("utf-8")
                self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _respond
        do_POST = _respond

    return Handler


def serve_bridge(
    manager: ConnectionManager,
    frame_template: object,
    *,
    host: str = "127.0.0.1",
    port: int = 8081,
    timeout: float = 5.0,
) -> HTTPServer:
    """Build and return a bound HTTPServer. The caller runs serve_forever().
    Binding is forced to loopback regardless of the host passed."""
    bridge = _Bridge(manager, frame_template, timeout)
    httpd = HTTPServer(("127.0.0.1", port), _make_handler(bridge))
    return httpd
