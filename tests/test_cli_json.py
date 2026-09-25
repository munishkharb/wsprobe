"""CLI --json output, driven through the real typer app against the synthetic
fixture. Every observation command keeps its human table as the default; --json
emits the stable, documented envelope from wsprobe.jsonout. These are sync tests
because the CLI calls asyncio.run() itself (see the live_server fixture)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from wsprobe.cli import app
from wsprobe.jsonout import DIFF_SCHEMA, MATRIX_SCHEMA

from .conftest import build_profile
from .fixture import (
    NOTES,
    mint_expired_token,
    mint_foreign_token,
    mint_token,
)

runner = CliRunner()


def _write(tmp_path, name: str, text: str) -> str:
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def _profile_file(tmp_path, live_server) -> str:
    from wsprobe.profile import dump_profile

    host, port = live_server
    return _write(tmp_path, "profile.yaml", dump_profile(build_profile(host, port)))


# --- matrix ------------------------------------------------------------------

def test_matrix_json_is_valid_with_expected_keys(tmp_path, live_server):
    profile = _profile_file(tmp_path, live_server)
    tok = _write(tmp_path, "valid.tok", mint_token("alice"))
    exp = _write(tmp_path, "expired.tok", mint_expired_token("alice"))
    frn = _write(tmp_path, "foreign.tok", mint_foreign_token("alice"))

    result = runner.invoke(
        app,
        [
            "matrix", profile,
            "--token-file", tok,
            "--expired-token-file", exp,
            "--foreign-token-file", frn,
            "--expected-identity", "alice",
            "--foreign-identity", "bob",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output

    data = json.loads(result.output)  # valid JSON
    assert data["schema"] == MATRIX_SCHEMA
    assert data["command"] == "matrix"
    assert data["profile"] == "synthetic-fixture"
    assert data["channel"] == "default"
    assert isinstance(data["observations"], list) and data["observations"]

    row = data["observations"][0]
    assert set(row.keys()) == {"check", "observed", "reading", "detail"}

    by = {o["check"]: o for o in data["observations"]}
    assert by["unauth-upgrade"]["reading"] == "insecure-shape"
    assert by["cross-user-handshake"]["detail"]["server_bound"] == "bob"

    # The observation vocabulary never issues a verdict.
    assert "confirmed" not in result.output.lower()


def test_matrix_human_default_still_works(tmp_path, live_server):
    profile = _profile_file(tmp_path, live_server)
    tok = _write(tmp_path, "valid.tok", mint_token("alice"))

    result = runner.invoke(app, ["matrix", profile, "--token-file", tok])
    assert result.exit_code == 0, result.output
    # It is a table, not JSON.
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.output)
    assert "unauth-upgrade" in result.output
    assert "insecure-shape" in result.output


# --- diff --------------------------------------------------------------------

def test_diff_json_is_valid_with_expected_keys(tmp_path, live_server):
    profile = _profile_file(tmp_path, live_server)
    tok_a = _write(tmp_path, "a.tok", mint_token("alice"))
    tok_b = _write(tmp_path, "b.tok", mint_token("bob"))

    result = runner.invoke(
        app,
        [
            "diff", profile,
            "--frame", json.dumps({"type": "read_note", "owner": "bob"}),
            "--token-a", tok_a,
            "--token-b", tok_b,
            "--name-a", "alice",
            "--name-b", "bob",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output

    data = json.loads(result.output)
    assert data["schema"] == DIFF_SCHEMA
    assert data["command"] == "diff"
    assert data["profile"] == "synthetic-fixture"
    assert data["channel"] == "default"
    assert set(data.keys()) == {
        "schema", "command", "profile", "channel",
        "frame", "identity_a", "identity_b", "reading", "reply_a", "reply_b",
    }
    # Same frame from two identities returns bob's note both times: the BOLA
    # signal, reported as an observation, never as "confirmed".
    assert data["reading"] == "same-across-identities"
    assert data["reply_b"]["content"] == NOTES["bob"]
    assert "confirmed" not in result.output.lower()


def test_diff_human_default_still_works(tmp_path, live_server):
    profile = _profile_file(tmp_path, live_server)
    tok_a = _write(tmp_path, "a.tok", mint_token("alice"))
    tok_b = _write(tmp_path, "b.tok", mint_token("bob"))

    result = runner.invoke(
        app,
        [
            "diff", profile,
            "--frame", json.dumps({"type": "read_note", "owner": "bob"}),
            "--token-a", tok_a,
            "--token-b", tok_b,
        ],
    )
    assert result.exit_code == 0, result.output
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.output)
    assert "reading:" in result.output
