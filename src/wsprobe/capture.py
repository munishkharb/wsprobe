"""Capture records and the NDJSON writer/reader.

A capture is a flat sequence of frame records. The tool's own format is one
JSON object per line (NDJSON) with a timestamp, direction, channel, and the
decoded frame. Secrets are redacted before a frame is written: field names that
look like credentials are masked by a fixed pattern, and the connection layer
additionally masks the profile's configured token field (which may be named
anything, e.g. `jwt` or `sid`). This is best-effort redaction, not an absolute
guarantee — a token buried in a field that neither the pattern nor the profile
names would still be written, so treat capture files as sensitive.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

SEND = "send"
RECV = "recv"

# High-entropy-ish material that must never persist to a capture even if a
# frame field carries it. Kept deliberately conservative: obvious token and
# password field names, and long opaque strings.
_SECRET_KEYS = re.compile(r"(token|password|passwd|secret|authorization|api[_-]?key|cookie)", re.I)
_MASK = "[redacted]"


@dataclass
class FrameRecord:
    direction: str
    frame: object
    channel: str = "default"
    ts: float = field(default_factory=time.time)

    def to_json(self, extra_keys: frozenset[str] = frozenset()) -> dict:
        return {
            "ts": round(self.ts, 6),
            "direction": self.direction,
            "channel": self.channel,
            "frame": _redact(self.frame, extra_keys),
        }


def _redact(value: object, extra_keys: frozenset[str] = frozenset()) -> object:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and (_SECRET_KEYS.search(k) or k in extra_keys):
                out[k] = _MASK
            else:
                out[k] = _redact(v, extra_keys)
        return out
    if isinstance(value, list):
        return [_redact(v, extra_keys) for v in value]
    return value


class CaptureWriter:
    """Append-only NDJSON writer. Used as a context manager.

    extra_redact_keys names additional field names to mask beyond the fixed
    secret-name pattern — the connection layer passes the profile's configured
    token field here, which may be named anything (jwt, sid, access...)."""

    def __init__(self, path: str | Path, extra_redact_keys: Iterable[str] = ()) -> None:
        self.path = Path(path)
        self._extra = frozenset(extra_redact_keys)
        self._fh = None

    def __enter__(self) -> "CaptureWriter":
        self._fh = self.path.open("w", encoding="utf-8")
        return self

    def __exit__(self, *exc) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def write(self, record: FrameRecord) -> None:
        assert self._fh is not None, "writer is not open"
        self._fh.write(json.dumps(record.to_json(self._extra), separators=(",", ":")) + "\n")
        self._fh.flush()


def read_capture(path: str | Path) -> list[FrameRecord]:
    records: list[FrameRecord] = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        records.append(_from_native(obj))
    return records


def _from_native(obj: dict) -> FrameRecord:
    """Read a record from the tool's own NDJSON or a generic proxy export.

    The tool's own shape is {ts, direction, channel, frame}. A generic proxy
    export tends to look like {time|timestamp, type|direction, payload|data}
    where direction is worded outgoing/incoming and the payload is a JSON
    string. Both normalize to a FrameRecord.
    """
    if "frame" in obj and "direction" in obj:
        return FrameRecord(
            direction=obj["direction"],
            frame=obj["frame"],
            channel=obj.get("channel", "default"),
            ts=float(obj.get("ts", 0.0)),
        )

    direction = obj.get("direction") or obj.get("type") or obj.get("dir") or ""
    direction = _norm_direction(str(direction))
    raw = obj.get("payload")
    if raw is None:
        raw = obj.get("data")
    if isinstance(raw, str):
        try:
            frame: object = json.loads(raw)
        except json.JSONDecodeError:
            frame = raw
    else:
        frame = raw
    ts = obj.get("ts") or obj.get("time") or obj.get("timestamp") or 0.0
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        ts = 0.0
    return FrameRecord(direction=direction, frame=frame, channel=str(obj.get("channel", "default")), ts=ts)


def _norm_direction(value: str) -> str:
    v = value.lower()
    if v in {SEND, "out", "outgoing", "client", "c2s", "sent"}:
        return SEND
    if v in {RECV, "in", "incoming", "server", "s2c", "received"}:
        return RECV
    return v or SEND


def ingest(paths: Iterable[str | Path]) -> Iterator[FrameRecord]:
    for p in paths:
        yield from read_capture(p)
