"""Deterministic end-to-end suite. Every capability is driven against the
synthetic vulnerable fixture, and each assertion checks a security-relevant
invariant, never a bare status code."""

from __future__ import annotations

import io
import json

import pytest

from wsprobe import (
    ConnectionManager,
    analyze,
    dump_profile,
    field_sweep,
    load_profile,
    profile_schema,
    run_matrix,
    two_account_diff,
    write_schema,
)
from wsprobe.authz import SAME
from wsprobe.capture import RECV, SEND, CaptureWriter, FrameRecord, read_capture
from wsprobe.matrix import CONTROL_PRESENT, INSECURE_SHAPE
from wsprobe.profile import Profile, RefreshPolicy
from wsprobe.replay import replay_capture
from wsprobe.repl import parse_line, run_repl

from .conftest import build_profile
from .fixture import NOTES, mint_expired_token, mint_foreign_token, mint_token


def _mgr(profile: Profile, user: str, **kw) -> ConnectionManager:
    return ConnectionManager(profile, token=mint_token(user), identity=user, **kw)


# --- profile and schema ------------------------------------------------------

def test_profile_yaml_roundtrips_and_validates(server):
    host, port = server
    text = dump_profile(build_profile(host, port))
    reloaded = Profile.model_validate(__import__("yaml").safe_load(text))
    assert reloaded.channel().handshake.url.startswith("ws://")
    assert reloaded.channel().messages.type_field == "type"


def test_schema_export(tmp_path):
    out = tmp_path / "profile.schema.json"
    write_schema(out)
    schema = json.loads(out.read_text())
    assert schema["$schema"].startswith("https://json-schema.org/")
    assert schema["title"] == "wsprobe profile"
    assert "channels" in schema["properties"]
    # The schema is generated from the same model the loader uses.
    assert schema == {**profile_schema()}


def test_invalid_profile_is_rejected():
    with pytest.raises(Exception):
        Profile.model_validate({"name": "x", "channels": []})
    with pytest.raises(Exception):
        Profile.model_validate(
            {"name": "x", "channels": [{"name": "c", "handshake": {"url": "http://nope"}}]}
        )


# --- handshake matrix --------------------------------------------------------

async def test_matrix_flags_handshake_bugs(profile):
    mgr = ConnectionManager(profile, token=mint_token("alice"), identity="matrix")
    obs = await run_matrix(
        mgr,
        expired_token=mint_expired_token("alice"),
        foreign_token=mint_foreign_token("alice"),
        expected_identity="alice",
        foreign_identity="bob",
    )
    by = {o.check: o for o in obs}

    # Insecure shapes the fixture seeds.
    assert by["unauth-upgrade"].reading == INSECURE_SHAPE
    assert by["unauth-upgrade"].observed == "upgraded-without-auth"
    assert by["no-auth-control-frame"].reading == INSECURE_SHAPE
    assert by["cross-user-handshake"].reading == INSECURE_SHAPE
    assert by["cross-user-handshake"].detail["server_bound"] == "bob"

    # The one control the fixture has: it rejects a bad token when no URL
    # identity overrides it.
    assert by["expired-token"].reading == CONTROL_PRESENT
    assert by["foreign-token"].reading == CONTROL_PRESENT

    # Every Origin variant is waved through: no Origin validation.
    origin_rows = [o for o in obs if o.check.startswith("origin")]
    assert origin_rows and all(o.reading == INSECURE_SHAPE for o in origin_rows)

    # The word "confirmed" appears nowhere in the matrix output.
    assert not any("confirmed" in o.observed.lower() or "confirmed" in o.reading.lower() for o in obs)


# --- two-account authorization diff (BOLA) -----------------------------------

async def test_two_account_diff_surfaces_cross_user_read(profile):
    alice = _mgr(profile, "alice")
    bob = _mgr(profile, "bob")
    # The same frame, owner=bob, fired from both identities.
    result = await two_account_diff(alice, bob, {"type": "read_note", "owner": "bob"})

    # The security invariant: bob's private content came back on alice's socket.
    assert result.reply_a["content"] == NOTES["bob"]
    # Identical replies to two identities is the BOLA signal.
    assert result.reading == SAME


# --- field sweep (IDOR) ------------------------------------------------------

async def test_field_sweep_reads_across_owners(profile):
    alice = _mgr(profile, "alice")
    result = await field_sweep(alice, {"type": "read_note"}, "owner", ["alice", "bob"])
    contents = {row.value: row.reply["content"] for row in result.rows}
    # alice's own socket reads both notes: an object-id sweep with no per-object
    # ownership check.
    assert contents["alice"] == NOTES["alice"]
    assert contents["bob"] == NOTES["bob"]
    assert result.distinct_replies == 2


# --- capture analyzer + draft profile ----------------------------------------

async def test_capture_analyzer_emits_valid_draft_profile(profile, tmp_path):
    # Drive the client and record its own capture.
    cap = tmp_path / "session.ndjson"
    mgr = ConnectionManager(profile, token=mint_token("alice"), identity="alice", capture_path=str(cap))
    async with mgr.dial() as conn:
        await conn.request({"type": "whoami"})
        await conn.request({"type": "read_note", "owner": "alice"})
        await conn.send({"type": "ping"})
        await conn.request({"type": "claim", "item": "coupon"})

    records = read_capture(cap)
    assert records, "capture recorded nothing"

    analysis = analyze(records, heartbeat_types=["ping", "pong"])
    assert analysis.dropped_heartbeats >= 1
    assert "whoami" in analysis.types
    assert "note" in analysis.types
    assert analysis.types["note"].direction == "recv"
    assert len(analysis.correlations) >= 2

    out = tmp_path / "draft.yaml"
    from wsprobe.analyzer import emit_draft_profile

    emit_draft_profile([str(cap)], out, heartbeat_types=["ping", "pong"])
    drafted = load_profile(out)  # loads and validates
    assert drafted.channel().messages.type_field == "type"
    assert "ping" in drafted.channel().heartbeat.types


def test_analyzer_ingests_generic_proxy_export(tmp_path):
    # A generic proxy/JSON export shape: outgoing/incoming with a JSON payload
    # string, plus a heartbeat to drop.
    export = [
        {"time": 1.0, "direction": "outgoing", "payload": json.dumps({"type": "get", "cid": 1, "id": 7})},
        {"time": 1.1, "direction": "incoming", "payload": json.dumps({"type": "record", "cid": 1, "id": 7})},
        {"time": 1.2, "direction": "incoming", "payload": json.dumps({"type": "ping"})},
    ]
    path = tmp_path / "proxy.ndjson"
    path.write_text("\n".join(json.dumps(e) for e in export))
    records = read_capture(path)
    assert records[0].direction == SEND
    assert records[1].direction == RECV
    analysis = analyze(records, heartbeat_types=["ping"])
    assert analysis.dropped_heartbeats == 1
    assert len(analysis.correlations) == 1
    assert analysis.correlations[0].reply["type"] == "record"


def test_capture_writer_redacts_secrets(tmp_path):
    path = tmp_path / "c.ndjson"
    with CaptureWriter(path) as w:
        w.write(FrameRecord(SEND, {"type": "login", "token": "super-secret-value", "user": "alice"}))
    line = json.loads(path.read_text().strip())
    assert line["frame"]["token"] == "[redacted]"
    assert line["frame"]["user"] == "alice"


# --- replay (missing idempotency) --------------------------------------------

async def test_replay_reapplies_state_change(profile, tmp_path):
    # Record a capture with a single claim frame.
    cap = tmp_path / "claim.ndjson"
    rec = ConnectionManager(profile, token=mint_token("carol"), identity="carol", capture_path=str(cap))
    async with rec.dial() as conn:
        first = await conn.request({"type": "claim", "item": "coupon"})
    assert first["balance"] == 10

    # Replay the captured claim on a fresh socket for the same identity.
    replayer = ConnectionManager(profile, token=mint_token("carol"), identity="carol")
    r1 = await replay_capture(replayer, cap)
    r2 = await replay_capture(replayer, cap)
    # No nonce, no idempotency: the same claim applied again and again.
    assert r1.steps[-1].reply["balance"] == 20
    assert r2.steps[-1].reply["balance"] == 30


# --- injection / stored-XSS fan-out ------------------------------------------

async def test_field_reflected_to_other_clients(profile):
    alice = _mgr(profile, "alice")
    bob = _mgr(profile, "bob")
    payload = "<script>steal(document.cookie)</script>"
    async with alice.dial() as ca, bob.dial() as cb:
        await ca.request({"type": "post", "room": "lobby", "text": payload})
        pushed = await cb.next_push(timeout=3.0)
    # The payload reached the other client verbatim: unvalidated fan-out.
    assert pushed["type"] == "message"
    assert pushed["text"] == payload


# --- interactive REPL --------------------------------------------------------

def test_repl_line_parsing():
    assert parse_line('{"type":"whoami","cid":1}', "type") == {"type": "whoami", "cid": 1}
    assert parse_line("read_note owner=bob", "type") == {"type": "read_note", "owner": "bob"}
    assert parse_line("claim item=coupon n=3", "type") == {"type": "claim", "item": "coupon", "n": 3}
    assert parse_line("   ", "type") is None


async def test_repl_drives_socket(profile):
    mgr = _mgr(profile, "alice")
    instream = io.StringIO("whoami\nread_note owner=bob\n")
    out = io.StringIO()
    await run_repl(mgr, instream=instream, outstream=out)
    lines = [ln for ln in out.getvalue().splitlines() if ln.startswith("{")]
    replies = [json.loads(ln) for ln in lines]
    assert any(r.get("user") == "alice" for r in replies)
    # BOLA again through the interactive surface: bob's note on alice's socket.
    assert any(r.get("content") == NOTES["bob"] for r in replies)


# --- token refresh policy ----------------------------------------------------

async def test_refresh_policy_per_dial_vs_reuse(server):
    host, port = server
    calls = {"n": 0}

    def provider() -> str:
        calls["n"] += 1
        return mint_token("alice")

    per_dial = ConnectionManager(build_profile(host, port, RefreshPolicy.per_dial), token_provider=provider)
    async with per_dial.dial():
        pass
    async with per_dial.dial():
        pass
    assert calls["n"] == 2  # a fresh token per dial

    calls["n"] = 0
    reuse = ConnectionManager(build_profile(host, port, RefreshPolicy.reuse), token_provider=provider)
    async with reuse.dial():
        pass
    async with reuse.dial():
        pass
    assert calls["n"] == 1  # harvested once, held across dials


# --- unauthenticated upgrade binds anon --------------------------------------

async def test_unauth_upgrade_binds_anon(profile):
    anon = ConnectionManager(profile)  # no token at all
    async with anon.dial() as conn:
        reply = await conn.request({"type": "whoami"})
    assert reply["user"] == "anon"
