# wsprobe

A WebSocket security review toolkit. It opens its own authenticated socket and
covers one protocol surface end to end for a single review: understand a
capture and draft the target profile, test the handshake, test authorization
across identities, sweep frame fields, replay state-changing frames.

The bet is depth over breadth. A WebSocket connection begins as an ordinary
HTTP GET and, at `101 Switching Protocols`, stops being HTTP and becomes a raw
two-way socket for the life of the app. The one checkpoint HTTP walks on every
request is walked exactly once here, at the upgrade, so the interesting defects
live after it: a frame that reads as another user because the server never
re-derived the principal, a control frame accepted with no per-message check, a
state-changing frame replayed because it carries no nonce. HTTP tooling reasons
about a unit (the request) that no longer exists after the upgrade. wsprobe owns
the handshake, speaks the app's message language, holds connection state, and
drives its own sockets.

## Authorized use only

This tool is for testing systems you own or are explicitly authorized to test.
It ships no target and no default host. There is nothing to point it at until
you write a profile for a system you are permitted to test.

## Install

```
uv venv --python 3.12
uv pip install -e '.[dev]'
```

## The profile

A profile is the single piece of target-specific knowledge the engine needs: a
declarative, validated document describing the handshake, how a token is
acquired and kept fresh, the message vocabulary, and the keepalive pattern to
suppress. Profiles are YAML, validated by a pydantic model. The model's JSON
schema is published at `profile.schema.json`:

```
wsprobe schema
```

A profile can be hand-written or drafted from a capture (`wsprobe analyze
--emit-profile`), then refined. One profile drives every capability, so the
same tooling that discovers the message language also drives the authorization
diff and the replay.

### Refresh policy

The refresh policy is load-bearing. Many targets mint a single-use token per
connection, so re-authenticating mid-run revokes the token a live socket is
holding. `per-dial` mints one token per new dial, `reuse` harvests one and
holds it, `ttl` caches until an age limit.

## Capabilities

| Verb | What it does |
|------|--------------|
| `wsprobe schema` | Export the profile JSON schema as a build artifact. |
| `wsprobe validate` | Load and validate a profile. |
| `wsprobe matrix` | Handshake security matrix: unauthenticated upgrade, expired and foreign token, CSWSH/Origin variants, no-auth control frames, cross-user handshake binding. |
| `wsprobe repl` | Interactive authenticated client: one frame per line, correlated reply, recorded to a capture. |
| `wsprobe analyze` | Ingest captures, drop heartbeats, inventory message types, correlate request and reply, and emit a draft profile. Opens no socket. |
| `wsprobe diff` | Two-account authorization diff: the same frame from two identities, replies compared. |
| `wsprobe sweep` | Field sweep: one field over a list of values on one identity, correlated replies. |
| `wsprobe replay` | Re-drive a captured outbound sequence on a fresh authenticated socket, optional field mutation. |
| `wsprobe bridge` | Loopback HTTP-to-WebSocket bridge: an HTTP tool (injection tester, fuzzer) drives one frame field via a `§FUZZ§` placeholder while wsprobe owns the handshake and token refresh. Binds `127.0.0.1` only. |

## Observations, not verdicts

The handshake matrix and the two-account diff report the observed behavior of
the server. The tool never prints "confirmed". That word is reserved for the
operator, after live reproduction. An observation of an insecure shape (an
upgrade accepted with no credentials, two identities receiving the same private
reply) is a lead to reproduce, not a finding the tool has closed.

## JSON output

The observation verbs default to a human table. Pass `--json` to `matrix`,
`diff`, `sweep`, or `analyze` for a stable, documented structure a script or the
Burp companion panel can parse instead. Each payload carries a `schema` tag of
the form `wsprobe.<command>/v1` and a `command` field, so a reader dispatches on
`schema` and trusts the keys under it. The reading vocabulary is the same one the
tables use, and the word "confirmed" never appears there either. The single
source of the shapes is `src/wsprobe/jsonout.py`.

```
wsprobe matrix profile.yaml --token-file valid.tok --json
```

```json
{
  "schema": "wsprobe.matrix/v1",
  "command": "matrix",
  "profile": "drafted-target",
  "channel": "default",
  "observations": [
    {"check": "unauth-upgrade", "observed": "upgraded-without-auth",
     "reading": "insecure-shape", "detail": {"upgraded": true, "error": null}}
  ]
}
```

`diff` emits `frame`, `identity_a`/`identity_b`, `reading`, and `reply_a`/`reply_b`;
`sweep` emits `field`, `distinct_replies`, and `rows`; `analyze` emits the frame
`inventory` and `correlations`. See `src/wsprobe/jsonout.py` for the full field
list of each.

## The Python API is the real surface

Every capability runs from a first-class Python API; the CLI verbs are thin
wrappers over it. The core objects are the profile loader and an async
connection manager whose `request` returns a correlated reply:

```python
import asyncio
from wsprobe import ConnectionManager, load_profile, two_account_diff

async def main():
    profile = load_profile("target.yaml")
    a = ConnectionManager(profile, token="<token-A>", identity="A")
    b = ConnectionManager(profile, token="<token-B>", identity="B")
    result = await two_account_diff(a, b, {"type": "read_note", "owner": "B"})
    print(result.reading, result.reply_a)

asyncio.run(main())
```

## Proof: the synthetic vulnerable fixture

A security tool that cannot be demonstrated end to end is a claim, not a tool.
The repo ships a small synthetic vulnerable WebSocket server (`tests/fixture.py`)
that seeds one clear bug per class: identity bound only at the handshake and not
re-checked per frame, an upgrade accepted with no token, no Origin validation, a
message field reflected to other clients unvalidated, and a state-changing claim
with no idempotency guard. The test suite drives every capability against it:

```
uv run pytest -v
```

The fixture is synthetic and self-contained. No engagement data, no live
target, no target-specific logic in the tool.

## Development

Run `pre-commit install` once per clone. On every commit this then runs,
against staged files:

- **betterleaks**: secrets scan (redacted output), blocks the commit on a hit.
- **opengrep**: SAST over Python, against a pinned rule pack vendored at
  `.opengrep/rules` (no registry fetch at commit time), blocks the commit on
  a finding.
- the standard pre-commit-hooks set: end-of-file-fixer, trailing-whitespace,
  check-merge-conflict, detect-private-key.

Both scanners run as already-installed binaries (`brew install betterleaks`;
opengrep via its install script) rather than something pre-commit builds for
you. Run everything on demand with `pre-commit run --all-files`.

## Security of the tool itself

Tokens are secrets: never written to a capture file, never printed, redacted
from any frame the analyzer persists. The sweep and replay engines pace
requests rather than bursting. TLS verification is on by default, with an
explicit flag to disable it for a proxied lab. The only verb that opens a
listening socket is `wsprobe bridge`, and it binds `127.0.0.1` only and paces
one frame at a time; every other verb opens outbound sockets only.

## License

MIT. See `LICENSE`.

## Credits

`websockets` (BSD-3-Clause), `pydantic` (MIT), `typer` (MIT), `PyYAML` (MIT),
`pytest` (MIT), invoked as libraries. Methodology is distilled from public
sources on WebSocket security testing. This is an original, clean-room
implementation: no third-party code beyond the declared libraries.
