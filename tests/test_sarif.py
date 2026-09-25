"""SARIF output is validated against the official SARIF 2.1.0 JSON schema
(vendored at tests/data, from the OASIS sarif-spec repository), driven through
the real CLI against the fixture and the clean control."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from typer.testing import CliRunner

from wsprobe.cli import app
from wsprobe.profile import dump_profile

from .conftest import build_profile
from .fixture import mint_token

SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-2.1.0.schema.json").read_text())
runner = CliRunner()


def _run_matrix(tmp_path, live_server) -> dict:
    host, port = live_server
    prof = tmp_path / "p.yaml"
    prof.write_text(dump_profile(build_profile(host, port)))
    tok = tmp_path / "t.tok"
    tok.write_text(mint_token("alice"))
    out = tmp_path / "out.sarif"
    res = runner.invoke(app, [
        "matrix", str(prof), "--token-file", str(tok),
        "--expected-identity", "alice", "--foreign-identity", "bob", "--sarif", str(out),
    ])
    assert res.exit_code == 0, res.output
    return json.loads(out.read_text())


def test_matrix_sarif_validates_against_the_2_1_0_schema(tmp_path, live_server):
    log = _run_matrix(tmp_path, live_server)
    jsonschema.validate(log, SCHEMA)
    run = log["runs"][0]
    rule_ids = {r["ruleId"] for r in run["results"]}
    assert "wsprobe/unauth-upgrade" in rule_ids
    assert "wsprobe/cross-user-handshake" in rule_ids
    assert all(r["level"] == "warning" for r in run["results"])
    assert "confirmed" not in json.dumps(log).lower()
    # no token in the location URI
    assert all("token=" not in r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"])


def test_empty_sarif_is_still_valid():
    from wsprobe.sarif import sarif_log

    log = sarif_log(target_url="ws://127.0.0.1:1/socket")
    jsonschema.validate(log, SCHEMA)
    assert log["runs"][0]["results"] == []
