"""The race probe (`race`).

Fires N identical frames at once and counts how many the server accepts:

- The fixture has no idempotency guard on `claim`, so all N land and the probe
  reads `multiple-accepted` (insecure-shape) - a once-only action with a race
  window.
- A server that guards the action (the lock server below: first claim wins, the
  rest error) accepts exactly one, so the probe reads `single-accepted`
  (control-present).
- The count is capped: below 2 or above the ceiling is refused, and the CLI
  will not fire at all without --yes, because the probe moves real state.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

import pytest
from typer.testing import CliRunner
from websockets.asyncio.server import serve

from wsprobe.cli import app
from wsprobe.connection import ConnectionManager
from wsprobe.matrix import CONTROL_PRESENT, INSECURE_SHAPE
from wsprobe.race import RaceCapExceeded, run_race

from .conftest import build_profile
from .fixture import mint_token

CLAIM = {"type": "claim", "item": "coupon"}


@asynccontextmanager
async def run_lock_server(host: str = "127.0.0.1", port: int = 0):
    """First claim wins; every later claim errors. A correct per-action guard."""
    state = {"claimed": False}

    async def handler(conn):
        async for raw in conn:
            frame = json.loads(raw)
            if not state["claimed"]:
                state["claimed"] = True
                reply = {"type": "claim.ok", "balance": 10}
            else:
                reply = {"type": "error", "error": "already claimed"}
            if "cid" in frame:
                reply["cid"] = frame["cid"]
            await conn.send(json.dumps(reply))

    async with serve(handler, host, port) as server:
        yield host, list(server.sockets)[0].getsockname()[1]


async def test_no_guard_lets_multiple_through(server):
    host, port = server
    mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
    result = await run_race(mgr, dict(CLAIM), count=5)
    assert result.accepted == 5
    assert result.observed == "multiple-accepted"
    assert result.reading == INSECURE_SHAPE


async def test_lock_server_accepts_exactly_one():
    async with run_lock_server() as (host, port):
        mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
        result = await run_race(mgr, dict(CLAIM), count=5)
    assert result.accepted == 1
    assert result.observed == "single-accepted"
    assert result.reading == CONTROL_PRESENT


async def test_count_cap_and_floor_are_enforced(server):
    host, port = server
    mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
    with pytest.raises(RaceCapExceeded):
        await run_race(mgr, dict(CLAIM), count=1)
    with pytest.raises(RaceCapExceeded):
        await run_race(mgr, dict(CLAIM), count=50, ceiling=10)


async def test_race_never_says_confirmed(server):
    host, port = server
    mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
    result = await run_race(mgr, dict(CLAIM), count=3)
    assert "confirmed" not in result.observed.lower()
    assert "confirmed" not in result.reading.lower()


def _profile_and_token(tmp_path, live_server):
    from wsprobe.profile import dump_profile

    host, port = live_server
    prof = tmp_path / "profile.yaml"
    prof.write_text(dump_profile(build_profile(host, port)))
    tok = tmp_path / "a.tok"
    tok.write_text(mint_token("alice"))
    return str(prof), str(tok)


def test_cli_refuses_to_fire_without_yes(tmp_path, live_server):
    prof, tok = _profile_and_token(tmp_path, live_server)
    runner = CliRunner()
    result = runner.invoke(app, ["race", prof, "--frame", json.dumps(CLAIM), "--token-file", tok, "--count", "3"])
    assert result.exit_code == 1
    assert "Nothing sent" in result.output


def test_cli_fires_with_yes_and_emits_envelope(tmp_path, live_server):
    prof, tok = _profile_and_token(tmp_path, live_server)
    runner = CliRunner()
    result = runner.invoke(
        app, ["race", prof, "--frame", json.dumps(CLAIM), "--token-file", tok, "--count", "3", "--yes", "--json"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["schema"] == "wsprobe.race/v1"
    assert data["command"] == "race"
    assert data["count"] == 3
    assert "confirmed" not in result.output.lower()
