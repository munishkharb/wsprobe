#!/usr/bin/env bash
# Scripted wsprobe demo against the shipped synthetic fixture, for the asciinema
# recording. Self-contained: starts the fixture, runs a sequence of verbs, tears
# down. Reproducible from a clean clone, no external target.
set -euo pipefail
cd "$(dirname "$0")/.."

# typed-prompt helper: show the command like a prompt, pause, run it.
p() { printf '\n\033[1;32m$\033[0m %s\n' "$*"; sleep 1.2; eval "$*"; sleep 1.6; }

PORT=8799
uv run python -m tests.fixture --port "$PORT" >/tmp/wsprobe-demo-fixture.log 2>&1 &
FX=$!
trap 'kill $FX 2>/dev/null || true' EXIT
sleep 2

clear
printf '\033[1;36m wsprobe — a WebSocket security review toolkit \033[0m\n'
printf ' Driving its own authenticated socket against a synthetic vulnerable target.\n'
sleep 2

cat > /tmp/wsprobe-demo.yaml <<YAML
name: demo-target
channels:
  - name: default
    handshake:
      url: ws://127.0.0.1:$PORT/socket
      framing: json
    auth:
      login: none
    messages:
      type_field: type
      correlation_keys: [cid]
    heartbeat:
      types: [ping, pong]
    probes:
      control_frame: {type: subscribe, topic: admin}
      identity_probe: {type: whoami}
      identity_param: user
      identity_field: user
YAML

p "uv run wsprobe validate /tmp/wsprobe-demo.yaml"
p "uv run wsprobe matrix /tmp/wsprobe-demo.yaml --expected-identity alice --foreign-identity bob"
p "printf '%s' \"\$(uv run python -c 'from tests.fixture import mint_token;print(mint_token(\"alice\"))')\" > /tmp/a.tok"
p "printf '%s' \"\$(uv run python -c 'from tests.fixture import mint_token;print(mint_token(\"bob\"))')\" > /tmp/b.tok"
p "uv run wsprobe diff /tmp/wsprobe-demo.yaml --frame '{\"type\":\"read_note\",\"owner\":\"bob\"}' --token-a /tmp/a.tok --token-b /tmp/b.tok --name-a alice --name-b bob"
p "uv run wsprobe sweep /tmp/wsprobe-demo.yaml --frame '{\"type\":\"read_note\"}' --field owner --values alice,bob --token-file /tmp/a.tok"

printf '\n\033[1;36m Observations, never verdicts. Reproduce before you report. \033[0m\n'
sleep 2.5
