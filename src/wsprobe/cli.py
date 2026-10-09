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

from . import analyzer, authz, jsonout, matrix
from .connection import ConnectionManager
from .race import DEFAULT_CEILING, DEFAULT_COUNT, RaceCapExceeded, run_race
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


@app.command(rich_help_panel="Setup")
def schema(out: str = typer.Option("profile.schema.json", help="Where to write the JSON schema.")) -> None:
    """Write the profile JSON schema to a file, for editor autocomplete and CI checks."""
    path = write_schema(out)
    typer.echo(f"wrote {path}")


@app.command(rich_help_panel="Setup")
def validate(profile: str, channel: Optional[str] = None) -> None:
    """Check that a profile file loads and is well-formed before you test with it."""
    p = load_profile(profile)
    typer.echo(f"ok: profile {p.name!r} with {len(p.channels)} channel(s): {[c.name for c in p.channels]}")


@app.command("handshake", rich_help_panel="Handshake")
def handshake_cmd(
    profile: str,
    channel: Optional[str] = None,
    token_file: Optional[str] = typer.Option(None, help="A valid token, for the Origin and cross-user rows."),
    expired_token_file: Optional[str] = None,
    foreign_token_file: Optional[str] = None,
    expected_identity: Optional[str] = None,
    foreign_identity: Optional[str] = None,
    no_tls_verify: bool = typer.Option(False, "--no-tls-verify", help="Disable TLS verification for a proxied lab."),
    as_json: bool = typer.Option(False, "--json", help="Emit observations as JSON."),
    sarif: Optional[str] = typer.Option(None, "--sarif", help="Also write insecure-shape observations as SARIF 2.1.0 to this path."),
) -> None:
    """Test handshake authentication: try to connect with no token, an expired token,
    another user's token, and a forged Origin, and report what the server allowed.

    Example: wsprobe handshake profile.yaml --token-file valid.tok
    """
    p = load_profile(profile)
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
    if sarif:
        _write_sarif(sarif, mgr.channel.handshake.url, p.name, observations=obs)
    if as_json:
        payload = jsonout.matrix_payload(obs, profile=p.name, channel=mgr.channel.name)
        typer.echo(jsonout.dumps(payload))
        return
    for o in obs:
        typer.echo(o.line())


# Back-compat alias: `matrix` was the verb through v0.1.x. Hidden, still works.
app.command("matrix", hidden=True)(handshake_cmd)


@app.command(rich_help_panel="Session")
def repl(
    profile: str,
    channel: Optional[str] = None,
    token_file: Optional[str] = None,
    capture: Optional[str] = typer.Option(None, help="Write an NDJSON capture of the session."),
) -> None:
    """Open an interactive authenticated client: type one JSON frame per line and see
    the correlated reply. The hands-on way to explore an app's message language."""
    mgr = _manager(profile, channel, token_file, "repl", capture=capture)
    asyncio.run(run_repl(mgr))


@app.command(rich_help_panel="Recon")
def analyze(
    captures: list[str] = typer.Argument(..., help="One or more capture files (NDJSON or a proxy export)."),
    emit_profile: Optional[str] = typer.Option(None, help="Write a draft profile.yaml from the capture."),
    url: str = typer.Option("wss://ws.example.test/socket", help="Handshake URL stub for the draft profile."),
    as_json: bool = typer.Option(False, "--json", help="Emit the analysis as JSON."),
) -> None:
    """Read a captured session and inventory its message types, then optionally write a
    starter profile.yaml. Run this first to learn what an app's traffic looks like.

    Example: wsprobe analyze capture.ndjson --emit-profile profile.yaml
    """
    records: list = []
    from .capture import read_capture

    for c in captures:
        records.extend(read_capture(c))
    result = analyzer.analyze(records)
    if as_json:
        typer.echo(jsonout.dumps(jsonout.analyze_payload(result, sources=captures)))
        if emit_profile:
            analyzer.emit_draft_profile(captures, emit_profile, url=url)
        return
    typer.echo(f"frames={result.total_frames} heartbeats_dropped={result.dropped_heartbeats}")
    typer.echo(f"type_field={result.type_field!r} correlation_keys={result.correlation_keys}")
    typer.echo("message inventory:")
    for line in result.inventory_lines():
        typer.echo("  " + line)
    typer.echo(f"correlated request/reply pairs: {len(result.correlations)}")
    if emit_profile:
        analyzer.emit_draft_profile(captures, emit_profile, url=url)
        typer.echo(f"wrote draft profile {emit_profile}")


@app.command(rich_help_panel="Authorization")
def diff(
    profile: str,
    frame: str = typer.Option(..., help="The frame to send from both identities, as JSON."),
    token_a: str = typer.Option(..., help="Token file for identity A."),
    token_b: str = typer.Option(..., help="Token file for identity B."),
    name_a: str = "A",
    name_b: str = "B",
    channel: Optional[str] = None,
    as_json: bool = typer.Option(False, "--json", help="Emit the diff observation as JSON."),
    sarif: Optional[str] = typer.Option(None, "--sarif", help="Also write a same-across-identities reading as SARIF 2.1.0 to this path."),
) -> None:
    """Send the same frame as two different users and compare the replies, to find
    per-message authorization gaps (a low-privilege user getting a privileged reply).

    Example: wsprobe diff profile.yaml --frame '{"type":"getUser","id":1}' --token-a low.tok --token-b admin.tok
    """
    p = load_profile(profile)
    mgr_a = ConnectionManager(p, channel=channel, token=_read_token(token_a), identity=name_a)
    mgr_b = ConnectionManager(p, channel=channel, token=_read_token(token_b), identity=name_b)
    result = asyncio.run(authz.two_account_diff(mgr_a, mgr_b, json.loads(frame)))
    if sarif:
        _write_sarif(sarif, mgr_a.channel.handshake.url, p.name, diffs=[result])
    if as_json:
        payload = jsonout.diff_payload(result, profile=p.name, channel=mgr_a.channel.name)
        typer.echo(jsonout.dumps(payload))
        return
    typer.echo(f"reading: {result.reading}")
    typer.echo(f"  {name_a} reply: {json.dumps(result.reply_a)}")
    typer.echo(f"  {name_b} reply: {json.dumps(result.reply_b)}")


@app.command("fuzz", rich_help_panel="Authorization")
def fuzz_cmd(
    profile: str,
    frame: str = typer.Option(..., help="Base frame as JSON."),
    field: str = typer.Option(..., help="The field to change on each send."),
    values: str = typer.Option(..., help="Comma-separated values to try in that field."),
    token_file: Optional[str] = None,
    channel: Optional[str] = None,
    as_json: bool = typer.Option(False, "--json", help="Emit the observations as JSON."),
) -> None:
    """Send one frame repeatedly, changing a single field across a list of values, and
    show each reply. Use it for IDOR-style id walking or small value lists.

    Example: wsprobe fuzz profile.yaml --frame '{"type":"getDoc","id":0}' --field id --values 1,2,3,4
    """
    p = load_profile(profile)
    mgr = _manager(profile, channel, token_file, "fuzz")
    vals: list = [_maybe_int(v) for v in values.split(",")]
    result = asyncio.run(authz.field_sweep(mgr, json.loads(frame), field, vals))
    if as_json:
        payload = jsonout.sweep_payload(result, profile=p.name, channel=mgr.channel.name)
        typer.echo(jsonout.dumps(payload))
        return
    typer.echo(f"field={result.field} distinct_replies={result.distinct_replies}")
    for row in result.rows:
        typer.echo(f"  {field}={row.value!r} -> {json.dumps(row.reply)}")


# Back-compat alias: `sweep` was the verb through v0.1.x. Hidden, still works.
app.command("sweep", hidden=True)(fuzz_cmd)


@app.command(rich_help_panel="Session")
def persist(
    profile: str,
    frame: str = typer.Option(..., help="A privileged frame to re-send after revocation, as JSON."),
    token_file: Optional[str] = None,
    channel: Optional[str] = None,
    settle: float = typer.Option(0.0, help="Seconds to wait for an out-of-band revocation (scripted mode)."),
    prompt: bool = typer.Option(False, "--prompt", help="Pause for you to revoke the session by hand, then press Enter."),
    as_json: bool = typer.Option(False, "--json", help="Emit the observation as JSON."),
) -> None:
    """Hold an authenticated socket open across a session revocation (logout,
    password reset, token expiry, role change) and report whether the same
    privileged frame is still served afterward. Revoke out of band during the
    pause with --prompt, or wait a scripted interval with --settle.

    Example: wsprobe persist profile.yaml --frame '{"type":"read_note","owner":"bob"}' --prompt
    """
    from .persist import run_persist

    p = load_profile(profile)
    mgr = _manager(profile, channel, token_file, "persist")
    result = asyncio.run(run_persist(mgr, json.loads(frame), settle=settle, prompt=prompt))
    if as_json:
        typer.echo(jsonout.dumps({
            "schema": "wsprobe.persist/v1",
            "command": "persist",
            "profile": p.name,
            "channel": mgr.channel.name,
            "observed": result.observed,
            "reading": result.reading,
            "detail": result.detail,
        }))
        return
    typer.echo(result.line())


@app.command(rich_help_panel="Concurrency")
def race(
    profile: str,
    frame: str = typer.Option(..., help="The state-changing frame to fire concurrently, as JSON."),
    count: int = typer.Option(DEFAULT_COUNT, help="How many identical frames to fire at once."),
    max_count: int = typer.Option(DEFAULT_CEILING, "--max", help="Safety ceiling; --count may not exceed it."),
    token_file: Optional[str] = None,
    channel: Optional[str] = None,
    yes: bool = typer.Option(False, "--yes", help="Confirm firing: this MOVES REAL STATE on the target."),
    as_json: bool = typer.Option(False, "--json", help="Emit the observation as JSON."),
) -> None:
    """Fire N identical frames at once, on N sockets held at a barrier, and
    report how many the server accepted. Finds the check-then-commit window on a
    once-only action (a coupon or payout claimed twice).

    This MOVES REAL STATE on the target, so it is capped and will not fire
    without --yes.

    Example: wsprobe race profile.yaml --frame '{"type":"claim","item":"coupon"}' --count 20 --yes
    """
    p = load_profile(profile)
    if not yes:
        typer.echo(f"race would fire {count} copies of this frame against {p.name!r}: this MOVES REAL STATE on the target.")
        typer.echo("Nothing sent. Re-run with --yes to fire.")
        raise typer.Exit(code=1)
    mgr = _manager(profile, channel, token_file, "race")
    try:
        result = asyncio.run(run_race(mgr, json.loads(frame), count, ceiling=max_count))
    except RaceCapExceeded as exc:
        typer.echo(f"refused: {exc}")
        raise typer.Exit(code=2)
    if as_json:
        typer.echo(jsonout.dumps({
            "schema": "wsprobe.race/v1",
            "command": "race",
            "profile": p.name,
            "channel": mgr.channel.name,
            "count": result.count,
            "accepted": result.accepted,
            "observed": result.observed,
            "reading": result.reading,
            "detail": result.detail,
        }))
        return
    typer.echo(result.line())


@app.command(rich_help_panel="Session")
def replay(
    profile: str,
    capture: str,
    token_file: Optional[str] = None,
    channel: Optional[str] = None,
    mutate_field: Optional[str] = None,
    mutate_value: Optional[str] = None,
) -> None:
    """Re-send a previously captured sequence of frames on a fresh authenticated socket,
    optionally changing one field. Use it to retry a flow or re-fire a state-changing frame."""
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


@app.command(rich_help_panel="Injection")
def bridge(
    profile: str,
    frame: str = typer.Option(..., help="Frame template as JSON, with a §FUZZ§ placeholder for the injected value."),
    token_file: Optional[str] = None,
    channel: Optional[str] = None,
    port: int = typer.Option(8081, help="Loopback port to listen on."),
    timeout: float = typer.Option(5.0, help="Per-frame reply timeout in seconds."),
) -> None:
    """Expose one frame field as a local HTTP endpoint so an HTTP tool (sqlmap, Burp
    Intruder) can drive it. wsprobe owns the authenticated socket and re-sends each
    value as a frame. Binds 127.0.0.1 only; paces one frame at a time.

    Example: wsprobe bridge profile.yaml --frame '{"type":"search","q":"§FUZZ§"}'
    """
    from .bridge import serve_bridge

    mgr = _manager(profile, channel, token_file, "bridge")
    httpd = serve_bridge(mgr, json.loads(frame), port=port, timeout=timeout)
    typer.echo(f"wsprobe bridge on http://127.0.0.1:{port} -> frame field via §FUZZ§ (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


def _write_sarif(path: str, url: str, profile_name: str, **kwargs) -> None:
    from .sarif import sarif_log

    Path(path).write_text(json.dumps(sarif_log(target_url=url, profile=profile_name, **kwargs), indent=2) + "\n")


def _maybe_int(value: str):
    try:
        return int(value)
    except (ValueError, TypeError):
        return value


if __name__ == "__main__":
    app()
