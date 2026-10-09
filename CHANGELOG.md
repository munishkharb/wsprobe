# Changelog

wsprobe is developed privately and published here in releases. Each entry says what changed and why.

## v0.2.0 (2026-10-10)

- Verbs renamed for clarity: `matrix` is now `handshake`, `sweep` is now `fuzz`. The old names keep working as hidden aliases, so existing scripts do not break. Every verb's `--help` now carries a plain one-line description and an example, grouped into panels.
- `handshake` judges CSWSH by the credential model. With cookie (ambient) auth and no Origin validation it reports `cswsh-preconditions-met`; with a header, query or subprotocol bearer, which a cross-origin browser cannot replay, it reports the weaker not-browser-CSWSH shape instead of over-claiming.
- New `persist`: holds an authenticated socket open across a session revocation (logout, password reset, token expiry, role change) and reports whether a privileged frame is still served afterward.
- New `race`: fires N identical frames at once and reports how many the server accepted, the check-then-commit window on a once-only action. It is count-capped and will not fire without `--yes`, because it moves real state.
- Burp companion: drives every verb (handshake, diff, fuzz, persist, race) from the Run menu, shows the `bridge` command to run in a terminal, and exports observed frames as a wsprobe NDJSON capture (**Write capture.ndjson**) so the offline capabilities run from Burp-seen traffic. Credential-looking fields are redacted on write.
- Burp companion UI: a redesigned suite tab built for a small screen - a toolbar, an observed-frame table with a reversible hide-heartbeats filter, Burp's native Pretty/Raw/Hex editor for the selected frame, an interactive WebSocket console (its own socket, with a Send gated behind an explicit arm), and a Results pane. Nothing is stacked or fixed-height, so panels do not get cut off; the modern build (Kotlin 2.2 / Gradle 9) bundles the runtime dependencies so the JAR loads in Burp.
- Build modernized to Kotlin 2.2 and Gradle 9; the extension now builds with `./gradlew build` on any JDK 17 or newer.

## v0.1.1 (2026-10-09)

- README: the matrix's Origin cases are listed, sweep and replay are in the quickstart, and the pacing and capture-masking behaviour is documented.
- The pre-commit config is valid again (an empty hook block had broken it for anyone installing the hooks).

## v0.1.0 (2026-09-26)

- First release: a WebSocket review toolkit driven by one target profile (`profile.schema.json`).
- Commands: `matrix` (handshake security checks), `repl`, `analyze`, `diff` (two-account authorization diff), `sweep`, `replay`, and `bridge` (lets an HTTP injection tool drive one frame field).
- Validated against a seeded lab target and a clean control (`docs/validation.md`).
