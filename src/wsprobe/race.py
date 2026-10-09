"""The race probe: fire N identical frames at once and count how many land.

A state-changing frame usually carries no nonce, so the window between a check
and its commit can let the same action apply more than once (a coupon claimed
twice, a balance deducted once but credited N times). This probe opens N
authenticated sockets, holds them all at a barrier, releases them together, and
reports how many of the N got a served (non-error) reply.

This MOVES REAL STATE on the target, so it is hard-capped and gated: the count
has a ceiling, and the CLI will not fire without an explicit confirmation. The
result is an observation - 'N of count were accepted' - never a verdict.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass, field

from .connection import ConnectionManager, DialOptions
from .matrix import CONTROL_PRESENT, INCONCLUSIVE, INSECURE_SHAPE

# The default number of concurrent frames, and the hard ceiling the operator
# must raise deliberately. Kept low so the probe is never a stray load test.
DEFAULT_COUNT = 10
DEFAULT_CEILING = 100


class RaceCapExceeded(ValueError):
    """Raised when the requested count is above the safety ceiling."""


@dataclass
class RaceResult:
    count: int
    accepted: int
    observed: str
    reading: str
    detail: dict = field(default_factory=dict)

    def line(self) -> str:
        return f"race   accepted={self.accepted}/{self.count}   observed={self.observed} [{self.reading}] {self.detail}"


def _served(reply: object) -> bool:
    return isinstance(reply, dict) and "error" not in reply


async def run_race(
    manager: ConnectionManager,
    frame: object,
    count: int = DEFAULT_COUNT,
    *,
    ceiling: int = DEFAULT_CEILING,
    timeout: float = 5.0,
) -> RaceResult:
    """Open `count` authenticated sockets, hold them at a barrier, fire the same
    frame simultaneously, and count the served replies.

    Each frame rides its own connection, so a per-connection token is minted per
    socket and the server sees N distinct clients of the same identity. Raises
    RaceCapExceeded if count is above the ceiling or below 2.
    """
    if count < 2:
        raise RaceCapExceeded(f"--count must be at least 2 to race; got {count}")
    if count > ceiling:
        raise RaceCapExceeded(f"--count {count} exceeds the safety ceiling {ceiling}; raise --max deliberately")

    async with AsyncExitStack() as stack:
        conns = [await stack.enter_async_context(manager.dial(DialOptions())) for _ in range(count)]
        barrier = asyncio.Barrier(count)

        async def fire(conn):
            await barrier.wait()
            return await conn.request(frame, timeout=timeout)

        results = await asyncio.gather(*[fire(c) for c in conns], return_exceptions=True)

    served = [r for r in results if not isinstance(r, BaseException) and _served(r)]
    errored = [r for r in results if isinstance(r, BaseException)]
    accepted = len(served)

    if accepted == 0:
        return RaceResult(
            count, accepted, "none-accepted", INCONCLUSIVE,
            {"note": "no frame was served; the probe could not establish the action",
             "errors": [type(e).__name__ for e in errored][:5]},
        )
    if accepted > 1:
        return RaceResult(
            count, accepted, "multiple-accepted", INSECURE_SHAPE,
            {"note": "more than one concurrent frame was accepted; a once-only action may have a race window",
             "sample_reply": served[0]},
        )
    return RaceResult(
        count, accepted, "single-accepted", CONTROL_PRESENT,
        {"note": "exactly one concurrent frame was accepted; the action appears serialized or guarded",
         "sample_reply": served[0]},
    )
