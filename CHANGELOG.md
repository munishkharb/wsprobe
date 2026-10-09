# Changelog

wsprobe is developed privately and published here in releases. Each entry says what changed and why.

## v0.1.1 (2026-10-09)

- README: the matrix's Origin cases are listed, sweep and replay are in the quickstart, and the pacing and capture-masking behaviour is documented.
- The pre-commit config is valid again (an empty hook block had broken it for anyone installing the hooks).

## v0.1.0 (2026-09-26)

- First release: a WebSocket review toolkit driven by one target profile (`profile.schema.json`).
- Commands: `matrix` (handshake security checks), `repl`, `analyze`, `diff` (two-account authorization diff), `sweep`, `replay`, and `bridge` (lets an HTTP injection tool drive one frame field).
- Validated against a seeded lab target and a clean control (`docs/validation.md`).
