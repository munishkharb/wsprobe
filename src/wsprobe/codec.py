"""Frame codecs sit behind the profile's framing declaration so the core stays
framing-agnostic. A codec turns an application frame (usually a dict) into the
bytes on the wire and back. JSON, plain text, and Socket.IO/Engine.IO are
implemented; length-prefixed and binary are registered stubs that raise until
their phase lands.

A codec may also carry its own ack correlation (Socket.IO does): `ack_id`
returns the acknowledgement id of a decoded frame, or None, so the connection
layer can pair a request to its reply below the message map.
"""

from __future__ import annotations

import json
import re
from typing import Optional, Protocol

from .profile import Framing


class Codec(Protocol):
    def encode(self, frame: object) -> str | bytes: ...
    def decode(self, raw: str | bytes) -> object: ...


def ack_id(codec: object, frame: object) -> Optional[int]:
    """The ack id a codec assigns to a frame, or None if it does not do acks."""
    fn = getattr(codec, "ack_id", None)
    return fn(frame) if callable(fn) else None


class JsonCodec:
    def encode(self, frame: object) -> str:
        return json.dumps(frame, separators=(",", ":"))

    def decode(self, raw: str | bytes) -> object:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return json.loads(raw)


class TextCodec:
    """A raw-string framing. The frame is a plain string on the wire. A dict
    frame is JSON-serialized so the same message-map machinery still applies
    when a target speaks JSON without declaring it; a scalar passes through.
    Decoding tries JSON first (so a JSON string becomes a dict for correlation
    and inventory), and falls back to the raw string."""

    def encode(self, frame: object) -> str:
        if isinstance(frame, str):
            return frame
        return json.dumps(frame, separators=(",", ":"))

    def decode(self, raw: str | bytes) -> object:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw


# Engine.IO packet type prefixes (the first digit of a text packet).
_EIO_OPEN = "0"
_EIO_CLOSE = "1"
_EIO_PING = "2"
_EIO_PONG = "3"
_EIO_MESSAGE = "4"
# Socket.IO packet type prefixes (the digit after the Engine.IO "4" message).
_SIO_CONNECT = "0"
_SIO_EVENT = "2"
_SIO_ACK = "3"

_SIO_EVENT_RE = re.compile(r"^(\d*)(\[.*\])$", re.S)


class SocketIOCodec:
    """Socket.IO over Engine.IO v4, text transport.

    An application frame is a dict {"event": <name>, "data": <payload>, and
    optionally "cid": <ack id>}. It encodes to an Engine.IO message carrying a
    Socket.IO EVENT packet: `42<ackid?>["<event>",<data>]`. A reply the server
    sends as a Socket.IO ACK (`43<ackid>[<data>]`) decodes back to a dict with
    the matching "cid", which is how the ack correlation mode pairs them.

    Engine.IO pings (`2`) are answered with a pong (`3`) by the connection
    reader; the handshake `0{...}` open and the Socket.IO `40` connect are
    surfaced as decoded frames so the caller sees them.
    """

    def __init__(self, namespace: str = "/") -> None:
        self._ns = "" if namespace == "/" else namespace

    def encode(self, frame: object) -> str:
        if isinstance(frame, str):
            return frame
        if not isinstance(frame, dict):
            raise ValueError("SocketIOCodec expects a dict frame")
        event = frame.get("event", "message")
        data = frame.get("data", {k: v for k, v in frame.items() if k not in {"event", "data", "cid"}})
        ackid = frame.get("cid")
        body = json.dumps([event, data], separators=(",", ":"))
        prefix = f"{_EIO_MESSAGE}{_SIO_EVENT}"
        if ackid is not None:
            return f"{prefix}{ackid}{body}"
        return f"{prefix}{body}"

    def decode(self, raw: str | bytes) -> object:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        if not raw:
            return {"type": "empty"}
        eio = raw[0]
        if eio == _EIO_OPEN:
            try:
                return {"type": "engineio.open", "data": json.loads(raw[1:])}
            except (json.JSONDecodeError, ValueError):
                return {"type": "engineio.open", "raw": raw[1:]}
        if eio == _EIO_PING:
            return {"type": "engineio.ping"}
        if eio == _EIO_PONG:
            return {"type": "engineio.pong"}
        if eio == _EIO_CLOSE:
            return {"type": "engineio.close"}
        if eio != _EIO_MESSAGE:
            return {"type": "engineio.unknown", "raw": raw}
        return self._decode_sio(raw[1:])

    def _decode_sio(self, body: str) -> object:
        if not body:
            return {"type": "socketio.empty"}
        sio = body[0]
        rest = body[1:]
        if sio == _SIO_CONNECT:
            try:
                return {"type": "socketio.connect", "data": json.loads(rest) if rest else None}
            except (json.JSONDecodeError, ValueError):
                return {"type": "socketio.connect", "raw": rest}
        if sio in (_SIO_EVENT, _SIO_ACK):
            m = _SIO_EVENT_RE.match(rest)
            if not m:
                return {"type": "socketio.malformed", "raw": body}
            ackid = int(m.group(1)) if m.group(1) else None
            payload = json.loads(m.group(2))
            if sio == _SIO_EVENT:
                event = payload[0] if payload else None
                data = payload[1] if len(payload) > 1 else None
                out = {"type": "socketio.event", "event": event, "data": data}
            else:
                out = {"type": "socketio.ack", "data": payload[0] if len(payload) == 1 else payload}
            if ackid is not None:
                out["cid"] = ackid
            return out
        return {"type": "socketio.other", "raw": body}

    def ack_id(self, frame: object) -> Optional[int]:
        if isinstance(frame, dict) and isinstance(frame.get("cid"), int):
            return frame["cid"]
        return None


class _Unimplemented:
    def __init__(self, framing: Framing) -> None:
        self._framing = framing

    def encode(self, frame: object) -> str:
        raise NotImplementedError(f"framing {self._framing.value!r} arrives in a later phase")

    def decode(self, raw: str | bytes) -> object:
        raise NotImplementedError(f"framing {self._framing.value!r} arrives in a later phase")


def codec_for(framing: Framing) -> Codec:
    if framing is Framing.json:
        return JsonCodec()
    if framing is Framing.text:
        return TextCodec()
    if framing is Framing.socketio:
        return SocketIOCodec()
    return _Unimplemented(framing)
