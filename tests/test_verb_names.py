"""Verb naming and back-compat. `matrix` became `handshake` and `sweep` became
`fuzz` for newcomer clarity; the old names stay as hidden aliases so scripts and
the Burp companion keep working. These tests prove the primary names run, the
aliases map to the SAME callback (identical output, not just "a command exists"),
and the aliases are hidden from help while the primary names are listed."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from wsprobe.cli import app

from .conftest import build_profile
from .fixture import mint_token

runner = CliRunner()


def _write(tmp_path, name: str, text: str) -> str:
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def _profile_file(tmp_path, live_server) -> str:
    from wsprobe.profile import dump_profile

    host, port = live_server
    return _write(tmp_path, "profile.yaml", dump_profile(build_profile(host, port)))


def test_handshake_and_matrix_alias_are_the_same_command(tmp_path, live_server):
    profile = _profile_file(tmp_path, live_server)
    tok = _write(tmp_path, "valid.tok", mint_token("alice"))
    args = [profile, "--token-file", tok, "--json"]

    primary = runner.invoke(app, ["handshake", *args])
    alias = runner.invoke(app, ["matrix", *args])

    assert primary.exit_code == 0, primary.output
    assert alias.exit_code == 0, alias.output
    # Same callback → byte-identical JSON envelope.
    assert primary.output == alias.output
    assert json.loads(primary.output)["command"] == "matrix"


def test_fuzz_and_sweep_alias_are_the_same_command(tmp_path, live_server):
    profile = _profile_file(tmp_path, live_server)
    tok = _write(tmp_path, "valid.tok", mint_token("alice"))
    args = [
        profile,
        "--frame", json.dumps({"type": "read_note", "owner": "bob"}),
        "--field", "owner",
        "--values", "alice,bob",
        "--token-file", tok,
        "--json",
    ]

    primary = runner.invoke(app, ["fuzz", *args])
    alias = runner.invoke(app, ["sweep", *args])

    assert primary.exit_code == 0, primary.output
    assert alias.exit_code == 0, alias.output
    assert primary.output == alias.output


def test_help_lists_primary_names_and_hides_aliases():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    assert "handshake" in result.output
    assert "fuzz" in result.output
    # The back-compat aliases are hidden from the top-level help.
    assert "matrix" not in result.output
    assert "sweep" not in result.output


def test_hidden_aliases_still_have_working_help():
    # Hidden from the list, but still a real, invokable command.
    for alias in ("matrix", "sweep"):
        result = runner.invoke(app, [alias, "--help"])
        assert result.exit_code == 0, result.output
