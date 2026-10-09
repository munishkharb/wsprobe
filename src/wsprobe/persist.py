"""The session-persistence probe: does an open socket outlive a revocation?

Identity on a WebSocket is usually decided once, at the handshake. Logout, a
password reset, token expiry or a role change update the HTTP session but do not
touch a socket that is already open. This probe holds one authenticated socket,
pauses for the operator to revoke the session out of band (or waits a scripted
interval), then re-sends the same privileged frame on the SAME socket and
reports whether it is still served.

Observation only, never a verdict: a still-served reply is the insecure shape to
reproduce, not a confirmed finding.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import websockets

from .connection import ConnectionManager, DialOptions
from .matrix import CONTROL_PRESENT, INCONCLUSIVE, INSECURE_SHAPE


@dataclass
class PersistResult:
    observed: str
    reading: str
    detail: dict = field(default_factory=dict)

    def line(self) -> str:
        return f"session-persistence   observed={self.observed:34} [{self.reading}] {self.detail}"


def _served(reply: object) -> bool:
    """A reply is 'served' when it is a frame the server acted on, not an error.
    Mirrors the matrix's no-auth-control reading."""
    return isinstance(reply, dict) and "error" not in reply


async def run_persist(
    manager: ConnectionManager,
    frame: object,
    *,
    settle: float = 0.0,
    prompt: bool = False,
    timeout: float = 5.0,
) -> PersistResult:
    """Open an authenticated socket, establish that the frame is served, pause
    for an out-of-band revocation, then re-send on the same socket.

    settle waits a fixed interval (scripted use); prompt pauses for the operator
    to revoke the session by hand and press Enter. The pre-revocation reply is
    the baseline: if the frame is not served even then, the probe is
    inconclusive rather than reporting a persistence result on a frame that
    never worked.
    """
    async with manager.dial(DialOptions()) as conn:
        try:
            before = await conn.request(frame, timeout=timeout)
        except Exception as exc:
            return PersistResult(
                "no-baseline", INCONCLUSIVE,
                {"note": "the frame was not served even before revocation", "error": type(exc).__name__},
            )
        if not _served(before):
            return PersistResult(
                "no-baseline", INCONCLUSIVE,
                {"note": "the frame returned an error before revocation; cannot probe persistence",
                 "reply_before": before},
            )

        if prompt:
            await asyncio.to_thread(
                input, "Revoke the session out of band (logout / reset / role drop / token expiry), then press Enter... "
            )
        elif settle > 0:
            await asyncio.sleep(settle)

        try:
            after = await conn.request(frame, timeout=timeout)
        except websockets.ConnectionClosed:
            return PersistResult(
                "closed-after-revocation", CONTROL_PRESENT,
                {"note": "the server closed the socket after the revocation", "reply_before": before},
            )
        except asyncio.TimeoutError:
            return PersistResult(
                "no-reply-after-revocation", CONTROL_PRESENT,
                {"note": "the re-sent frame drew no reply after the pause", "reply_before": before},
            )
        except Exception as exc:
            return PersistResult(
                "no-reply-after-revocation", INCONCLUSIVE,
                {"error": type(exc).__name__, "reply_before": before},
            )

    if _served(after):
        return PersistResult(
            "still-served-after-revocation", INSECURE_SHAPE,
            {"reply_before": before, "reply_after": after},
        )
    return PersistResult(
        "refused-after-revocation", CONTROL_PRESENT,
        {"reply_before": before, "reply_after": after},
    )
