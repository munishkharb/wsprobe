"""Capture discovery and correlation analyzer.

An offline mode that ingests captures from the tool's own NDJSON and from a
generic proxy or JSON export, drops heartbeats, inventories message types with
counts and direction, correlates requests to replies, and emits a draft profile
from what it saw. It opens no socket, so it is safe to run against evidence at
any time.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .capture import RECV, SEND, FrameRecord, read_capture
from .profile import (
    Auth,
    Channel,
    Handshake,
    Heartbeat,
    MessageMap,
    Profile,
    dump_profile,
)

# Field names that commonly name a message type or pair a request to a reply.
_TYPE_CANDIDATES = ["type", "event", "op", "action", "method", "cmd"]
_CORR_CANDIDATES = ["cid", "id", "reqId", "requestId", "seq", "correlationId", "nonce"]
# Heuristic keepalive type names, used only when the caller gives no heartbeat set.
_HEARTBEAT_HINTS = {"ping", "pong", "heartbeat", "hb", "keepalive", "2", "3"}


@dataclass
class TypeStat:
    name: str
    sent: int = 0
    recv: int = 0

    @property
    def total(self) -> int:
        return self.sent + self.recv

    @property
    def direction(self) -> str:
        if self.sent and self.recv:
            return "both"
        if self.sent:
            return "send"
        return "recv"


@dataclass
class Correlation:
    key: str
    request: object
    reply: object


@dataclass
class Analysis:
    type_field: str
    correlation_keys: list[str]
    heartbeat_types: list[str]
    types: dict[str, TypeStat] = field(default_factory=dict)
    correlations: list[Correlation] = field(default_factory=list)
    dropped_heartbeats: int = 0
    total_frames: int = 0

    def inventory_lines(self) -> list[str]:
        rows = sorted(self.types.values(), key=lambda t: -t.total)
        return [f"{t.name:22} total={t.total:<4} sent={t.sent:<4} recv={t.recv:<4} dir={t.direction}" for t in rows]


def _guess_type_field(records: Iterable[FrameRecord]) -> str:
    votes: Counter = Counter()
    for r in records:
        if isinstance(r.frame, dict):
            for cand in _TYPE_CANDIDATES:
                if cand in r.frame and isinstance(r.frame[cand], (str, int)):
                    votes[cand] += 1
    if votes:
        return votes.most_common(1)[0][0]
    return "type"


def _guess_correlation_keys(records: Iterable[FrameRecord], type_field: str) -> list[str]:
    votes: Counter = Counter()
    for r in records:
        if isinstance(r.frame, dict):
            for cand in _CORR_CANDIDATES:
                if cand == type_field:
                    continue
                if cand in r.frame:
                    votes[cand] += 1
    return [k for k, _ in votes.most_common(2)] or ["cid"]


def analyze(
    records: list[FrameRecord],
    *,
    type_field: Optional[str] = None,
    correlation_keys: Optional[list[str]] = None,
    heartbeat_types: Optional[list[str]] = None,
) -> Analysis:
    type_field = type_field or _guess_type_field(records)
    correlation_keys = correlation_keys or _guess_correlation_keys(records, type_field)

    if heartbeat_types is None:
        observed = {
            str(r.frame.get(type_field))
            for r in records
            if isinstance(r.frame, dict) and str(r.frame.get(type_field)).lower() in _HEARTBEAT_HINTS
        }
        heartbeat_types = sorted(observed)

    analysis = Analysis(
        type_field=type_field,
        correlation_keys=correlation_keys,
        heartbeat_types=heartbeat_types,
    )
    hb = set(heartbeat_types)
    pending: dict[str, FrameRecord] = {}

    for r in records:
        analysis.total_frames += 1
        if not isinstance(r.frame, dict):
            continue
        tname = str(r.frame.get(type_field, "<untyped>"))
        if tname in hb:
            analysis.dropped_heartbeats += 1
            continue

        stat = analysis.types.setdefault(tname, TypeStat(tname))
        if r.direction == SEND:
            stat.sent += 1
        elif r.direction == RECV:
            stat.recv += 1

        parts = [str(r.frame.get(k)) for k in correlation_keys if k in r.frame]
        key = "|".join(parts) if parts else None
        if key is None:
            continue
        if r.direction == SEND:
            pending[key] = r
        elif r.direction == RECV and key in pending:
            analysis.correlations.append(Correlation(key=key, request=pending.pop(key).frame, reply=r.frame))

    return analysis


def draft_profile(analysis: Analysis, *, name: str = "drafted-target", url: str = "wss://ws.example.test/socket") -> Profile:
    """Emit a draft profile from a capture analysis. The handshake is a stub
    the operator fills in; the message map and heartbeat suppression come from
    what the capture actually showed."""
    opcode_names = {t: t for t in sorted(analysis.types)}
    channel = Channel(
        name="default",
        handshake=Handshake(url=url),
        auth=Auth(),
        messages=MessageMap(
            type_field=analysis.type_field,
            correlation_keys=list(analysis.correlation_keys),
            opcode_names=opcode_names,
        ),
        heartbeat=Heartbeat(types=list(analysis.heartbeat_types)),
    )
    return Profile(name=name, channels=[channel])


def emit_draft_profile(
    capture_paths: list[str | Path],
    out_path: str | Path,
    *,
    name: str = "drafted-target",
    url: str = "wss://ws.example.test/socket",
    type_field: Optional[str] = None,
    correlation_keys: Optional[list[str]] = None,
    heartbeat_types: Optional[list[str]] = None,
) -> Profile:
    records: list[FrameRecord] = []
    for p in capture_paths:
        records.extend(read_capture(p))
    analysis = analyze(
        records,
        type_field=type_field,
        correlation_keys=correlation_keys,
        heartbeat_types=heartbeat_types,
    )
    profile = draft_profile(analysis, name=name, url=url)
    Path(out_path).write_text(dump_profile(profile))
    return profile
