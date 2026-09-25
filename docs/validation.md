# wsprobe validation

Proof that wsprobe catches what it claims to, on real targets run locally under
authorization, and stays quiet on a server that does the right thing.

Each target has its **ground truth** (the findings expected, written from the
target's design and its observed handshake, before interpreting a wsprobe run)
and a **result** table: caught, missed, or false positive, with the exact
command and the output file under `runs/`.

Method note: wsprobe reports *observations* of insecure shapes, never a
"confirmed" verdict. "Caught" below means wsprobe reported the insecure shape
the ground truth predicted; the operator still reproduces before reporting.

Targets:

| Tag | Target | Framing | How it runs |
|-----|--------|---------|-------------|
| T-FX | Repo synthetic fixture (`tests/fixture.py`) | json | `uv run pytest` |
| T-CTL | Clean control (`tests/control.py`) | json | `uv run pytest` |
| T-JS | OWASP Juice Shop (`bkimminich/juice-shop`) | socketio | docker, :3000 |
| T-DVWS | OWASP DVWS (upstream, MIT) | text | docker |

---

## T-FX — synthetic fixture

One clean bug per attack class, so every capability has something to catch. This
is the deterministic suite, `uv run pytest` (34 passed).

Ground truth (seeded bugs) and result:

| # | Expected finding | wsprobe check | Caught? | Evidence |
|---|------------------|---------------|---------|----------|
| 1 | Unauthenticated upgrade accepted | matrix unauth-upgrade | ✅ | `test_matrix_flags_handshake_bugs` |
| 2 | No Origin validation | matrix origin-* | ✅ | same |
| 3 | Identity from `?user=` overrides token | matrix cross-user-handshake | ✅ | same (`server_bound == bob`) |
| 4 | No message-level authz (anon subscribe admin) | matrix no-auth-control-frame | ✅ | same |
| 5 | BOLA: note ownership read from frame | two-account diff | ✅ | `test_two_account_diff_surfaces_cross_user_read` |
| 6 | IDOR: sweep reads across owners | field sweep | ✅ | `test_field_sweep_reads_across_owners` |
| 7 | Unvalidated fan-out (stored XSS shape) | push capture | ✅ | `test_field_reflected_to_other_clients` |
| 8 | Replay: no idempotency on claim | replay | ✅ | `test_replay_reapplies_state_change` |

Control present the fixture keeps: expired and foreign tokens are rejected at the
upgrade → matrix reads `control-present` (no false alarm).

---

## T-CTL — clean control (zero findings expected)

Same service as the fixture with every control in place (token required and
verified, identity from token only, Origin allowlist, per-frame ownership
re-check, idempotent claim, privileged topics refused). The invariant is
silence.

| Expected | wsprobe check | Result | Evidence |
|----------|---------------|--------|----------|
| Zero insecure-shape observations | full matrix | ✅ 0 insecure | `test_control_matrix_reports_no_insecure_shape` |
| No cross-user read | two-account diff | ✅ not same | `test_control_diff_does_not_leak_across_identities` |
| Sweep reads only own note | field sweep | ✅ | `test_control_sweep_reads_only_own_note` |
| Claim idempotent | replay/claim | ✅ | `test_control_claim_is_idempotent` |

No false positives on a correct server.

---

## T-JS — OWASP Juice Shop (Socket.IO)

`docker run -d --name juice -p 3000:3000 bkimminich/juice-shop`

Observed handshake (`runs/juice-handshake.txt`, `runs/juice-connect.txt`):

```
0{"sid":"...","pingInterval":25000,"pingTimeout":5000}
40{"sid":"..."}
42["server started"]
2            (Engine.IO ping)
```

Ground truth: Juice Shop's Socket.IO endpoint is an **unauthenticated
notification channel** with permissive CORS. So the expected true observations
are an unauthenticated upgrade and no Origin restriction. These are low-severity
on a public notification channel — a real demonstration that wsprobe reports the
*shape* and leaves severity to the operator, not a high-impact bug.

Command: `uv run wsprobe matrix runs/juice.yaml --json` → `runs/juice-matrix.json`

| Expected | wsprobe observed | reading | Caught? |
|----------|------------------|---------|---------|
| Upgrade with no token accepted | `unauth-upgrade: upgraded-without-auth` | insecure-shape | ✅ |
| No Origin check (stripped/null/sibling/bypass all accepted) | `origin-*: upgraded-untrusted-origin` | insecure-shape | ✅ |
| No token supplied for expired/foreign rows | `not-supplied` | inconclusive | ✅ (honest) |
| No identity probe / control frame declared | `no-probe` | inconclusive | ✅ (honest) |

False positives: none. The insecure shapes reported are true of the channel;
their low severity is the operator's call.

**Bug this run caught in wsprobe itself:** the first matrix run reported
`unauth-upgrade: rejected (http-400)` — wrong, since the socket connects fine
without auth. Cause: `_build_uri` discarded a query string embedded in the
handshake URL (`?EIO=4&transport=websocket`). Fixed to merge the URL's own
query; regression test `test_handshake_url_query_is_preserved`.

---

## T-DVWS — OWASP Damn Vulnerable Web Sockets (pending operator injection runs)

Upstream `interference-security/DVWS` (MIT), built from its Dockerfile; ws on
`:8080`. wsprobe's own handshake checks run against it directly; the injection
classes (SQLi, command injection, XSS fan-out) are DVWS's core and are driven by
an HTTP injection tool through `wsprobe bridge`, operator-run.

Observed (`runs/dvws-probe.txt`): each route is a distinct Ratchet socket that
upgrades with no token and replies with a plain string (text framing, one reply
per message → ordered correlation). The route config sets `allowedOrigins '*'`.

### Handshake layer (wsprobe direct)

`uv run wsprobe matrix runs/dvws.yaml --channel authenticate-user --json` →
`runs/dvws-matrix.json`

| Expected | wsprobe observed | reading | Caught? |
|----------|------------------|---------|---------|
| Upgrade with no token accepted | `unauth-upgrade: upgraded-without-auth` | insecure-shape | ✅ |
| No Origin check (`allowedOrigins '*'`) | `origin-*: upgraded-untrusted-origin` | insecure-shape | ✅ |

### Injection layer (bridge + HTTP tool, operator-run)

wsprobe carries the frame; an HTTP injection tool does the detection. DVWS
replies are plain strings, so a blank/error string is the oracle.

```
# Terminal A
uv run wsprobe bridge runs/dvws.yaml --channel authenticate-user --frame '"§FUZZ§"' --port 8081
# Terminal B
sqlmap -u 'http://127.0.0.1:8081/?fuzz=admin' --batch --level 3 -o runs/sqlmap-dvws.log
```

Status: handshake layer ✅ caught. Injection run **pending** operator execution;
results to `runs/sqlmap-dvws.log`, then a row here.
