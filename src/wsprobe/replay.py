"""Replay engine.

Re-drives a captured sequence of outbound frames on a freshly authenticated
socket, optionally mutating a field before resend. Because frames typically
carry no nonce, replay is a first-class probe for missing idempotency on
state-changing actions, and it doubles as a regression driver.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .capture import SEND, FrameRecord, read_capture
from .connection import ConnectionManager


@dataclass
class ReplayStep:
    sent: dict
    reply: object


@dataclass
class ReplayResult:
    steps: list[ReplayStep] = field(default_factory=list)

    def replies(self) -> list[object]:
        return [s.reply for s in self.steps]


def outbound_frames(records: list[FrameRecord], *, drop_types: Optional[set[str]] = None, type_field: str = "type") -> list[dict]:
    frames: list[dict] = []
    drop = drop_types or set()
    for r in records:
        if r.direction != SEND or not isinstance(r.frame, dict):
            continue
        if str(r.frame.get(type_field)) in drop:
            continue
        frames.append(dict(r.frame))
    return frames


async def replay(
    manager: ConnectionManager,
    frames: list[dict],
    *,
    mutate: Optional[Callable[[dict], dict]] = None,
    mutate_field: Optional[str] = None,
    mutate_value: Any = None,
    timeout: float = 5.0,
) -> ReplayResult:
    """Re-drive outbound frames on a fresh socket. A frame with no correlation
    value is sent fire-and-forget; a correlated frame waits for its reply."""
    result = ReplayResult()
    corr_keys = manager.channel.messages.correlation_keys
    async with manager.dial() as conn:
        for frame in frames:
            frame = dict(frame)
            if mutate is not None:
                frame = mutate(frame)
            if mutate_field is not None:
                frame[mutate_field] = mutate_value
            # A replayed correlation id would collide with the manager's own
            # counter; drop it so request() stamps a fresh one.
            for k in corr_keys:
                frame.pop(k, None)
            reply = await conn.request(frame, timeout=timeout)
            result.steps.append(ReplayStep(sent=frame, reply=reply))
    return result


async def replay_capture(
    manager: ConnectionManager,
    capture_path: str | Path,
    *,
    drop_types: Optional[set[str]] = None,
    mutate_field: Optional[str] = None,
    mutate_value: Any = None,
    timeout: float = 5.0,
) -> ReplayResult:
    records = read_capture(capture_path)
    tf = manager.channel.messages.type_field
    frames = outbound_frames(records, drop_types=drop_types or set(manager.channel.heartbeat.types), type_field=tf)
    return await replay(manager, frames, mutate_field=mutate_field, mutate_value=mutate_value, timeout=timeout)
