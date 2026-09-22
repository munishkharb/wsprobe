"""The handshake security matrix.

Fires the handshake-layer checks from the attack catalog without needing a
seated application session. Every result is an Observation of what the server
did. The tool never prints "confirmed": that word is the operator's to use
after live reproduction. An Observation carries a machine tag, the evidence,
and a short reading of the shape (control-present, or an insecure shape worth
the operator's look).
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from typing import Optional

from .connection import ConnectionManager, DialOptions
from .profile import Profile, TokenLocation

# Reading tags. Note the deliberate absence of anything like "confirmed".
CONTROL_PRESENT = "control-present"
INSECURE_SHAPE = "insecure-shape"
INCONCLUSIVE = "inconclusive"

ORIGIN_STRIPPED = "<stripped>"

# Origin values an allowlist built on a naive substring or unanchored regex
# tends to wave through.
def _bypass_origins(target_host: str) -> list[str]:
    base = target_host or "target.example.test"
    return [
        f"https://{base}.attacker.test",
        f"https://attacker-{base}",
        f"https://{base}evil.test",
    ]


@dataclass
class Observation:
    check: str
    observed: str
    reading: str
    detail: dict = field(default_factory=dict)

    def line(self) -> str:
        return f"{self.check:26} observed={self.observed:34} [{self.reading}] {self.detail}"


async def run_matrix(
    manager: ConnectionManager,
    *,
    expired_token: Optional[str] = None,
    foreign_token: Optional[str] = None,
    identity_probe_type: str = "whoami",
    whoami_field: str = "user",
    expected_identity: Optional[str] = None,
    foreign_identity: Optional[str] = None,
) -> list[Observation]:
    """Run every handshake check against the manager's channel.

    expired_token and foreign_token are supplied by the operator (wsprobe does
    not mint them): a stale token and a bad-signature or wrong-issuer token.
    expected_identity/foreign_identity drive the cross-user-handshake check,
    which asks whether the server binds the connection to the token identity or
    to a URL-supplied identity parameter.
    """
    obs: list[Observation] = []
    host = manager.channel.handshake.url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]

    # 1. Unauthenticated upgrade: drop credentials, attempt the upgrade.
    up, err = await manager.try_dial(DialOptions(drop_token=True))
    obs.append(
        Observation(
            "unauth-upgrade",
            "upgraded-without-auth" if up else "rejected",
            INSECURE_SHAPE if up else CONTROL_PRESENT,
            {"upgraded": up, "error": err},
        )
    )

    # 2. Expired token, then foreign token: expect rejection at the upgrade.
    for tag, tok in (("expired-token", expired_token), ("foreign-token", foreign_token)):
        if tok is None:
            obs.append(Observation(tag, "not-supplied", INCONCLUSIVE, {"note": "operator did not supply a token"}))
            continue
        up, err = await manager.try_dial(DialOptions(override_token=tok))
        obs.append(
            Observation(
                tag,
                "upgraded-with-bad-token" if up else "rejected",
                INSECURE_SHAPE if up else CONTROL_PRESENT,
                {"upgraded": up, "error": err},
            )
        )

    # 3. CSWSH / Origin: replay the upgrade with untrusted Origins.
    origin_cases = [("origin-stripped", None, True), ("origin-null", "null", True)]
    origin_cases.append(("origin-sibling", f"https://evil.{host}", True))
    for cand in _bypass_origins(host):
        origin_cases.append((f"origin-bypass", cand, True))
    accepted_origins = []
    for tag, value, is_set in origin_cases:
        opts = DialOptions(origin=value, origin_set=is_set)
        up, err = await manager.try_dial(opts)
        if up:
            accepted_origins.append(value if value is not None else ORIGIN_STRIPPED)
        obs.append(
            Observation(
                tag,
                "upgraded-untrusted-origin" if up else "rejected",
                INSECURE_SHAPE if up else CONTROL_PRESENT,
                {"origin": value, "upgraded": up},
            )
        )

    # 4. No-auth control frames: open without authenticating, send a control
    #    frame, and see whether it is acted on.
    obs.append(await _no_auth_control(manager))

    # 5. Cross-user handshake: bind check between token identity and a
    #    URL-supplied identity parameter.
    if expected_identity is not None and foreign_identity is not None:
        obs.append(
            await _cross_user_handshake(
                manager, identity_probe_type, whoami_field, expected_identity, foreign_identity
            )
        )

    return obs


async def _no_auth_control(manager: ConnectionManager) -> Observation:
    tf = manager.channel.messages.type_field
    try:
        async with manager.dial(DialOptions(drop_token=True)) as conn:
            reply = await conn.request({tf: "subscribe", "topic": "admin"}, timeout=3.0)
            acted = isinstance(reply, dict) and "error" not in reply
            return Observation(
                "no-auth-control-frame",
                "acted-on-unauthenticated" if acted else "rejected",
                INSECURE_SHAPE if acted else CONTROL_PRESENT,
                {"reply": reply},
            )
    except Exception as exc:
        return Observation("no-auth-control-frame", "no-socket", INCONCLUSIVE, {"error": repr(exc)})


async def _cross_user_handshake(
    manager: ConnectionManager,
    probe_type: str,
    field_name: str,
    expected: str,
    foreign: str,
) -> Observation:
    tf = manager.channel.messages.type_field
    try:
        async with manager.dial(DialOptions(extra_query={"user": foreign})) as conn:
            reply = await conn.request({tf: probe_type}, timeout=3.0)
            bound = reply.get(field_name) if isinstance(reply, dict) else None
            honored = bound == foreign
            return Observation(
                "cross-user-handshake",
                "bound-url-identity" if honored else "bound-token-identity",
                INSECURE_SHAPE if honored else CONTROL_PRESENT,
                {"token_identity": expected, "url_identity": foreign, "server_bound": bound},
            )
    except Exception as exc:
        return Observation("cross-user-handshake", "no-socket", INCONCLUSIVE, {"error": repr(exc)})


def observations_to_dicts(obs: list[Observation]) -> list[dict]:
    return [asdict(o) for o in obs]


def run_matrix_sync(manager: ConnectionManager, **kwargs) -> list[Observation]:
    return asyncio.run(run_matrix(manager, **kwargs))
