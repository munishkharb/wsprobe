"""The typer CLI: a thin wrapper over the Python API.

Every verb maps to an API call. Authorized use only: this tool is for systems
you own or are explicitly authorized to test. It ships no target and no default
host. Nothing runs until you write a profile for a system you are permitted to
test.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer

from . import analyzer, authz, matrix
from .connection import ConnectionManager
from .replay import replay_capture as _replay_capture
from .profile import load_profile
from .repl import run_repl
from .schema import write_schema

app = typer.Typer(add_completion=False, help="WebSocket security review toolkit. Authorized use only.")


def _read_token(path: Optional[str]) -> Optional[str]:
    return Path(path).read_text().strip() if path else None


def _manager(
    profile_path: str,
    channel: Optional[str],
    token_file: Optional[str],
    identity: Optional[str],
    capture: Optional[str] = None,
    tls_verify: bool = True,
) -> ConnectionManager:
    profile = load_profile(profile_path)
    return ConnectionManager(
        profile,
        channel=channel,
        token=_read_token(token_file),
        identity=identity,
        capture_path=capture,
        tls_verify=tls_verify,
    )


@app.command()
def schema(out: str = typer.Option("profile.schema.json", help="Where to write the JSON schema.")) -> None:
    """Export the profile JSON schema as a build artifact."""
    path = write_schema(out)
    typer.echo(f"wrote {path}")


@app.command()
def validate(profile: str, channel: Optional[str] = None) -> None:
    """Load and validate a profile."""
    p = load_profile(profile)
    typer.echo(f"ok: profile {p.name!r} with {len(p.channels)} channel(s): {[c.name for c in p.channels]}")


@app.command("matrix")
def matrix_cmd(
    profile: str,
    channel: Optional[str] = None,
    token_file: Optional[str] = typer.Option(None, help="A valid token, for the Origin and cross-user rows."),
    expired_token_file: Optional[str] = None,
    foreign_token_file: Optional[str] = None,
    expected_identity: Optional[str] = None,
    foreign_identity: Optional[str] = None,
    no_tls_verify: bool = typer.Option(False, "--no-tls-verify", help="Disable TLS verification for a proxied lab."),
    as_json: bool = typer.Option(False, "--json", help="Emit observations as JSON."),
) -> None:
    """Run the handshake security matrix and report observations."""
    mgr = _manager(profile, channel, token_file, "matrix", tls_verify=not no_tls_verify)
    obs = asyncio.run(
        matrix.run_matrix(
            mgr,
            expired_token=_read_token(expired_token_file),
            foreign_token=_read_token(foreign_token_file),
            expected_identity=expected_identity,
            foreign_identity=foreign_identity,
        )
    )
    if as_json:
        typer.echo(json.dumps(matrix.observations_to_dicts(obs), indent=2))
        return
    for o in obs:
        typer.echo(o.line())


@app.command()
def repl(
    profile: str,
    channel: Optional[str] = None,
    token_file: Optional[str] = None,
    capture: Optional[str] = typer.Option(None, help="Write an NDJSON capture of the session."),
) -> None:
    """Interactive authenticated client: one frame per line, correlated reply."""
    mgr = _manager(profile, channel, token_file, "repl", capture=capture)
    asyncio.run(run_repl(mgr))


@app.command()
def analyze(
    captures: list[str] = typer.Argument(..., help="One or more capture files (NDJSON or a proxy export)."),
    emit_profile: Optional[str] = typer.Option(None, help="Write a draft profile.yaml from the capture."),
    url: str = typer.Option("wss://ws.example.test/socket", help="Handshake URL stub for the draft profile."),
) -> None:
    """Inventory message types, correlate replies, and optionally emit a draft profile."""
    records: list = []
    from .capture import read_capture

    for c in captures:
        records.extend(read_capture(c))
    result = analyzer.analyze(records)
    typer.echo(f"frames={result.total_frames} heartbeats_dropped={result.dropped_heartbeats}")
    typer.echo(f"type_field={result.type_field!r} correlation_keys={result.correlation_keys}")
    typer.echo("message inventory:")
    for line in result.inventory_lines():
        typer.echo("  " + line)
    typer.echo(f"correlated request/reply pairs: {len(result.correlations)}")
    if emit_profile:
        analyzer.emit_draft_profile(captures, emit_profile, url=url)
        typer.echo(f"wrote draft profile {emit_profile}")


@app.command()
def diff(
    profile: str,
    frame: str = typer.Option(..., help="The frame to send from both identities, as JSON."),
    token_a: str = typer.Option(..., help="Token file for identity A."),
    token_b: str = typer.Option(..., help="Token file for identity B."),
    name_a: str = "A",
    name_b: str = "B",
    channel: Optional[str] = None,
) -> None:
    """Two-account authorization diff: same frame from two identities, diff the replies."""
    p = load_profile(profile)
    mgr_a = ConnectionManager(p, channel=channel, token=_read_token(token_a), identity=name_a)
    mgr_b = ConnectionManager(p, channel=channel, token=_read_token(token_b), identity=name_b)
    result = asyncio.run(authz.two_account_diff(mgr_a, mgr_b, json.loads(frame)))
    typer.echo(f"reading: {result.reading}")
    typer.echo(f"  {name_a} reply: {json.dumps(result.reply_a)}")
    typer.echo(f"  {name_b} reply: {json.dumps(result.reply_b)}")


@app.command()
def sweep(
    profile: str,
    frame: str = typer.Option(..., help="Base frame as JSON."),
    field: str = typer.Option(..., help="The field to sweep."),
    values: str = typer.Option(..., help="Comma-separated values."),
    token_file: Optional[str] = None,
    channel: Optional[str] = None,
) -> None:
    """Field sweep: drive one field over a list and show correlated replies."""
    mgr = _manager(profile, channel, token_file, "sweep")
    vals: list = [_maybe_int(v) for v in values.split(",")]
    result = asyncio.run(authz.field_sweep(mgr, json.loads(frame), field, vals))
    typer.echo(f"field={result.field} distinct_replies={result.distinct_replies}")
    for row in result.rows:
        typer.echo(f"  {field}={row.value!r} -> {json.dumps(row.reply)}")


@app.command()
def replay(
    profile: str,
    capture: str,
    token_file: Optional[str] = None,
    channel: Optional[str] = None,
    mutate_field: Optional[str] = None,
    mutate_value: Optional[str] = None,
) -> None:
    """Re-drive a captured outbound sequence on a fresh authenticated socket."""
    mgr = _manager(profile, channel, token_file, "replay")
    result = asyncio.run(
        _replay_capture(
            mgr,
            capture,
            mutate_field=mutate_field,
            mutate_value=_maybe_int(mutate_value) if mutate_value is not None else None,
        )
    )
    typer.echo(f"replayed {len(result.steps)} frame(s):")
    for step in result.steps:
        typer.echo(f"  sent {json.dumps(step.sent)} -> {json.dumps(step.reply)}")


def _maybe_int(value: str):
    try:
        return int(value)
    except (ValueError, TypeError):
        return value


if __name__ == "__main__":
    app()
