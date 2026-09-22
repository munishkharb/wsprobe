"""Authorization engines over the authenticated client.

Two-account diff: fire the same frame from two identities and compare the
replies. Identical replies to two identities is the signal that the server
never re-bound the principal per frame. Field sweep: drive one field over a
list of values on one identity and show the correlated replies, the IDOR and
enumeration engine.

Both report observations. A verdict of identical-across-identities is stated as
what it is (an observation the operator reproduces), not as "confirmed".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .connection import ConnectionManager

SAME = "same-across-identities"
DIFFERENT = "different-across-identities"
DENIED = "denied-for-second-identity"


@dataclass
class DiffResult:
    frame: dict
    reply_a: object
    reply_b: object
    reading: str
    identity_a: Optional[str] = None
    identity_b: Optional[str] = None

    def line(self) -> str:
        return f"[{self.reading}] {self.identity_a} vs {self.identity_b}: {self.frame}"


@dataclass
class SweepRow:
    value: Any
    frame: dict
    reply: object


@dataclass
class SweepResult:
    field: str
    rows: list[SweepRow] = field(default_factory=list)
    distinct_replies: int = 0


def _looks_denied(reply: object) -> bool:
    if not isinstance(reply, dict):
        return False
    if "error" in reply:
        return True
    tf = str(reply.get("type", ""))
    return tf.endswith(".denied") or tf.endswith(".error") or tf == "error"


def _reply_equal(a: object, b: object, ignore: set[str]) -> bool:
    def strip(x: object) -> object:
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if k not in ignore}
        if isinstance(x, list):
            return [strip(v) for v in x]
        return x

    return strip(a) == strip(b)


async def two_account_diff(
    manager_a: ConnectionManager,
    manager_b: ConnectionManager,
    frame: dict,
    *,
    ignore_keys: Optional[set[str]] = None,
    timeout: float = 5.0,
) -> DiffResult:
    """Send the same frame from two authenticated sockets and diff the replies.

    ignore_keys drops correlation ids and timestamps before the compare so a
    per-request id does not read as a difference.
    """
    ignore = ignore_keys or set(manager_a.channel.messages.correlation_keys) | {"ts", "cid"}
    async with manager_a.dial() as ca, manager_b.dial() as cb:
        reply_a = await ca.request(dict(frame), timeout=timeout)
        reply_b = await cb.request(dict(frame), timeout=timeout)

    if _looks_denied(reply_b) and not _looks_denied(reply_a):
        reading = DENIED
    elif _reply_equal(reply_a, reply_b, ignore):
        reading = SAME
    else:
        reading = DIFFERENT
    return DiffResult(
        frame=dict(frame),
        reply_a=reply_a,
        reply_b=reply_b,
        reading=reading,
        identity_a=manager_a.identity,
        identity_b=manager_b.identity,
    )


async def field_sweep(
    manager: ConnectionManager,
    frame: dict,
    field_name: str,
    values: list[Any],
    *,
    timeout: float = 5.0,
) -> SweepResult:
    """Sweep one field over a list of values on one identity and collect the
    correlated replies. The sweep paces itself one request at a time rather
    than bursting."""
    result = SweepResult(field=field_name)
    seen: list[object] = []
    ignore = set(manager.channel.messages.correlation_keys) | {"ts", "cid"}
    async with manager.dial() as conn:
        for value in values:
            probe = dict(frame)
            probe[field_name] = value
            reply = await conn.request(probe, timeout=timeout)
            result.rows.append(SweepRow(value=value, frame=probe, reply=reply))
            if not any(_reply_equal(reply, s, ignore) for s in seen):
                seen.append(reply)
    result.distinct_replies = len(seen)
    return result
