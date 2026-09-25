"""The clean control run: every capability against a server with the controls
in place. The invariant is silence: zero insecure-shape observations, no
cross-user read, no double-applied claim."""

from __future__ import annotations

import pytest_asyncio

from wsprobe import ConnectionManager, field_sweep, run_matrix, two_account_diff
from wsprobe.authz import SAME
from wsprobe.matrix import INSECURE_SHAPE
from wsprobe.profile import Channel, Handshake, Profile

from .conftest import build_profile
from .control import ALLOWED_ORIGINS, run_control
from .fixture import NOTES, mint_expired_token, mint_foreign_token, mint_token


@pytest_asyncio.fixture
async def control_profile():
    async with run_control() as (host, port):
        base = build_profile(host, port)
        ch = base.channel()
        handshake = Handshake(url=ch.handshake.url, origin=next(iter(ALLOWED_ORIGINS)))
        yield Profile(name="clean-control", channels=[Channel(**{**ch.model_dump(), "handshake": handshake})])


def _mgr(profile, user):
    return ConnectionManager(profile, token=mint_token(user), identity=user)


async def test_control_matrix_reports_no_insecure_shape(control_profile):
    obs = await run_matrix(
        _mgr(control_profile, "alice"),
        expired_token=mint_expired_token("alice"),
        foreign_token=mint_foreign_token("alice"),
        expected_identity="alice",
        foreign_identity="bob",
    )
    insecure = [o for o in obs if o.reading == INSECURE_SHAPE]
    assert insecure == [], [o.line() for o in insecure]
    by = {o.check: o for o in obs}
    assert by["unauth-upgrade"].observed == "rejected"
    assert by["no-auth-control-frame"].observed == "upgrade-refused"
    assert by["cross-user-handshake"].detail["server_bound"] == "alice"


async def test_control_diff_does_not_leak_across_identities(control_profile):
    result = await two_account_diff(
        _mgr(control_profile, "alice"), _mgr(control_profile, "bob"), {"type": "read_note", "owner": "bob"}
    )
    assert result.reading != SAME
    assert result.reply_a.get("content") != NOTES["bob"]


async def test_control_sweep_reads_only_own_note(control_profile):
    result = await field_sweep(_mgr(control_profile, "alice"), {"type": "read_note"}, "owner", ["alice", "bob"])
    contents = {row.value: row.reply.get("content") for row in result.rows}
    assert contents["alice"] == NOTES["alice"]
    assert contents["bob"] is None


async def test_control_claim_is_idempotent(control_profile):
    mgr = _mgr(control_profile, "carol")
    async with mgr.dial() as conn:
        first = await conn.request({"type": "claim", "item": "coupon"})
        second = await conn.request({"type": "claim", "item": "coupon"})
    assert first["balance"] == second["balance"] == 10
