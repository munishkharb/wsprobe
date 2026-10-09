"""The session-persistence probe (`persist`).

Proven against live sockets, both directions:

- A server that trusts the pipe (the fixture) keeps serving a privileged frame
  after the pause, so the probe reads `still-served-after-revocation`
  (insecure-shape) - the socket outlived the revocation.
- A server that drops the socket after the first frame (the revoking server
  below, standing in for a logout/expiry landing mid-session) makes the re-sent
  frame fail, so the probe reads control-present.
- If the frame is not even served before the pause, the probe is inconclusive
  rather than reporting a persistence result on a frame that never worked.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

from typer.testing import CliRunner
from websockets.asyncio.server import serve

from wsprobe.cli import app
from wsprobe.connection import ConnectionManager
from wsprobe.matrix import CONTROL_PRESENT, INCONCLUSIVE, INSECURE_SHAPE
from wsprobe.persist import run_persist

from .conftest import build_profile
from .fixture import mint_token


@asynccontextmanager
async def run_revoking_server(host: str = "127.0.0.1", port: int = 0):
    """Serves exactly one frame per connection, then closes the socket - the
    shape of a session revoked after the first interaction."""

    async def handler(conn):
        try:
            raw = await conn.recv()
        except Exception:
            return
        frame = json.loads(raw)
        reply = {"type": "note", "owner": frame.get("owner")}
        if "cid" in frame:
            reply["cid"] = frame["cid"]
        await conn.send(json.dumps(reply))
        await conn.close()

    async with serve(handler, host, port) as server:
        yield host, list(server.sockets)[0].getsockname()[1]


FRAME = {"type": "read_note", "owner": "bob"}


async def test_socket_outlives_revocation_is_insecure_shape(server):
    host, port = server
    mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
    result = await run_persist(mgr, dict(FRAME), settle=0.0)
    assert result.observed == "still-served-after-revocation"
    assert result.reading == INSECURE_SHAPE
    assert result.detail["reply_after"]  # a real served reply came back


async def test_dropped_socket_reads_control_present():
    async with run_revoking_server() as (host, port):
        mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
        result = await run_persist(mgr, dict(FRAME), settle=0.0)
    assert result.reading == CONTROL_PRESENT
    assert result.observed in {"closed-after-revocation", "no-reply-after-revocation", "refused-after-revocation"}


async def test_unserved_baseline_is_inconclusive(server):
    """A frame the server errors on before the pause can't be a persistence
    probe - the probe says so rather than inventing a reading."""
    host, port = server
    mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
    result = await run_persist(mgr, {"type": "nonexistent-type"}, settle=0.0)
    assert result.observed == "no-baseline"
    assert result.reading == INCONCLUSIVE


async def test_persist_never_says_confirmed(server):
    host, port = server
    mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
    result = await run_persist(mgr, dict(FRAME), settle=0.0)
    assert "confirmed" not in result.observed.lower()
    assert "confirmed" not in result.reading.lower()


def test_persist_cli_json_envelope(tmp_path, live_server):
    from wsprobe.profile import dump_profile

    host, port = live_server
    runner = CliRunner()
    prof = tmp_path / "profile.yaml"
    prof.write_text(dump_profile(build_profile(host, port)))
    tok = tmp_path / "a.tok"
    tok.write_text(mint_token("alice"))

    result = runner.invoke(app, ["persist", str(prof), "--frame", json.dumps(FRAME), "--token-file", str(tok), "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["schema"] == "wsprobe.persist/v1"
    assert data["command"] == "persist"
    assert data["observed"] == "still-served-after-revocation"
    assert "confirmed" not in result.output.lower()
