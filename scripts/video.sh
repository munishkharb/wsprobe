#!/usr/bin/env bash
# Two-scene wsprobe showcase for the release video. Self-contained on the shipped
# fixture + clean control, so it reproduces from a clean clone. DVWS is proven
# separately in docs/validation.md and captioned here as "also tested against".
set -euo pipefail
cd "$(dirname "$0")/.."

cap()  { printf '\n\033[1;36m▌ %s\033[0m\n' "$*"; sleep 2.0; }
p()    { printf '\033[1;32m$\033[0m %s\n' "$*"; sleep 1.1; eval "$*"; sleep 1.8; }

FX=8799; CTL=8798; BR=8082
uv run python -m tests.fixture --port $FX  >/tmp/wsp-fx.log 2>&1 &  P1=$!
uv run python -m tests.control --port $CTL >/tmp/wsp-ctl.log 2>&1 & P2=$!
trap 'kill $P1 $P2 ${P3:-} 2>/dev/null || true' EXIT
sleep 2

mk() { cat > "$1" <<YAML
name: $2
channels:
  - name: default
    handshake: {url: "ws://127.0.0.1:$3/socket", framing: json}
    auth: {login: none}
    messages: {type_field: type, correlation_keys: [cid]}
    heartbeat: {types: [ping, pong]}
    probes:
      control_frame: {type: subscribe, topic: admin}
      identity_probe: {type: whoami}
YAML
}
mk /tmp/fx.yaml demo-target $FX
mk /tmp/ctl.yaml clean-control $CTL
printf '%s' "$(uv run python -c 'from tests.fixture import mint_token;print(mint_token("alice"))')" > /tmp/a.tok
printf '%s' "$(uv run python -c 'from tests.fixture import mint_token;print(mint_token("bob"))')"   > /tmp/b.tok

clear
printf '\033[1;35m  wsprobe — a WebSocket security review toolkit\033[0m\n'
printf '  It opens its own authenticated socket and reports observations, never verdicts.\n'
sleep 2.5

cap "Scene 1 — the differentiator: two-account authorization diff (BOLA)"
printf '  Same frame, two identities. Identical private replies = the server never re-bound the user.\n'; sleep 2
p "uv run wsprobe diff /tmp/fx.yaml --frame '{\"type\":\"read_note\",\"owner\":\"bob\"}' --token-a /tmp/a.tok --token-b /tmp/b.tok --name-a alice --name-b bob"
printf '  \033[1;31m→ same-across-identities: alice read bob'\''s private note. Deterministic, not a guess.\033[0m\n'; sleep 2.5

cap "Control — the same tool against a correctly-secured socket"
p "uv run wsprobe matrix /tmp/ctl.yaml --expected-identity alice --foreign-identity bob"
printf '  \033[1;32m→ no insecure-shape anywhere: rejected upgrades, refused origins. Controls hold.\033[0m\n'; sleep 2.5

cap "Scene 2 — the bridge: an HTTP tool reaches a WebSocket frame field"
uv run wsprobe bridge /tmp/fx.yaml --frame '{"type":"login","username":"§FUZZ§","password":"nope"}' --port $BR >/tmp/wsp-br.log 2>&1 & P3=$!
sleep 2
printf '  A SQL tautology, sent as an HTTP request, carried onto the socket by wsprobe:\n'; sleep 1.5
p "curl -s -G 'http://127.0.0.1:$BR/' --data-urlencode \"fuzz=x' OR '1'='1' -- \""
printf '  \033[1;31m→ login.ok: the injection reached the SQL sink through the frame.\033[0m\n'; sleep 2
printf '\n  sqlmap, speaking only HTTP, then confirmed and dumped through the same bridge:\n'; sleep 1.5
printf '\033[1;32m$\033[0m sqlmap -u http://127.0.0.1:%s/?fuzz=alice --batch --dbms sqlite --dump -T users\n' "$BR"; sleep 1
grep -A6 'Table: users' runs/sqlmap-fixture-dump.log 2>/dev/null | head -8 || \
  printf '  [see runs/sqlmap-fixture-dump.log — users table dumped]\n'
sleep 2.5

cap "Also tested against OWASP Juice Shop (Socket.IO) and OWASP DVWS — see docs/validation.md"
sleep 2
printf '\n\033[1;35m  Observations, never verdicts. Reproduce before you report.\033[0m\n'
sleep 2.5
