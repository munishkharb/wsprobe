"""Interactive authenticated client REPL.

Owns the handshake, presents a fresh token per dial, and lets the operator send
one frame per line and see the correlated reply. Every frame is recorded to an
NDJSON capture for later analysis. A line is either a JSON object, or a short
`type key=value ...` shorthand that builds one.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Optional

from .connection import Connection, ConnectionManager


def parse_line(line: str, type_field: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        return json.loads(line)
    parts = line.split()
    frame: dict = {type_field: parts[0]}
    for token in parts[1:]:
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        frame[key] = _coerce(value)
    return frame


def _coerce(value: str) -> object:
    for caster in (int, float):
        try:
            return caster(value)
        except ValueError:
            continue
    if value in {"true", "false"}:
        return value == "true"
    return value


async def run_repl(manager: ConnectionManager, *, instream=None, outstream=None) -> None:
    instream = instream or sys.stdin
    out = outstream or sys.stdout
    tf = manager.channel.messages.type_field
    async with manager.dial() as conn:
        out.write(f"wsprobe repl on channel {manager.channel.name!r}. one frame per line, Ctrl-D to exit.\n")
        out.flush()
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, instream.readline)
            if not line:
                break
            try:
                frame = parse_line(line, tf)
            except json.JSONDecodeError as exc:
                out.write(f"parse error: {exc}\n")
                out.flush()
                continue
            if frame is None:
                continue
            await _send_and_show(conn, frame, out)


async def _send_and_show(conn: Connection, frame: dict, out) -> None:
    try:
        reply = await conn.request(frame, timeout=5.0)
        out.write(json.dumps(reply) + "\n")
    except Exception as exc:  # a send with no correlation value, or a timeout
        try:
            await conn.send(frame)
            out.write("(sent, no correlated reply)\n")
        except Exception:
            out.write(f"error: {exc}\n")
    out.flush()
