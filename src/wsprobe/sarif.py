"""SARIF 2.1.0 output for the observation commands.

SARIF lets a matrix or diff run land in any viewer or pipeline that already
reads static-analysis results. Only insecure-shape observations (and a
same-across-identities diff) become results, at level "warning": they are leads
for the operator to reproduce, not verdicts, and the word "confirmed" never
appears. Control-present and inconclusive rows are left out rather than
reported as passes.

The location of every result is the channel's handshake URL, which carries no
token (tokens are placed at dial time and never written here).
"""

from __future__ import annotations

from typing import Iterable, Optional

from . import __version__
from .authz import SAME, DiffResult
from .matrix import INSECURE_SHAPE, Observation

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/munishkharb/wsprobe"

_RULE_TEXT = {
    "unauth-upgrade": "The WebSocket upgrade completed with no credentials.",
    "expired-token": "The WebSocket upgrade completed with an expired token.",
    "foreign-token": "The WebSocket upgrade completed with a token from another issuer.",
    "origin-stripped": "The WebSocket upgrade completed with no Origin header.",
    "origin-null": "The WebSocket upgrade completed with Origin: null.",
    "origin-sibling": "The WebSocket upgrade completed with a sibling-subdomain Origin.",
    "origin-bypass": "The WebSocket upgrade completed with an allowlist-bypass Origin.",
    "no-auth-control-frame": "An unauthenticated socket had a control frame acted on.",
    "cross-user-handshake": "The connection bound to a URL-supplied identity instead of the token's.",
    "same-across-identities": "The same frame returned the same reply to two identities.",
}


def _rule_id(check: str) -> str:
    return f"wsprobe/{check}"


def _rule(check: str) -> dict:
    return {
        "id": _rule_id(check),
        "name": check,
        "shortDescription": {"text": _RULE_TEXT.get(check, check)},
        "helpUri": _INFO_URI,
        "defaultConfiguration": {"level": "warning"},
    }


def _location(url: str) -> list[dict]:
    return [{"physicalLocation": {"artifactLocation": {"uri": url}}}]


def sarif_log(
    *,
    target_url: str,
    observations: Iterable[Observation] = (),
    diffs: Iterable[DiffResult] = (),
    profile: Optional[str] = None,
) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for o in observations:
        if o.reading != INSECURE_SHAPE:
            continue
        rules.setdefault(o.check, _rule(o.check))
        results.append({
            "ruleId": _rule_id(o.check),
            "level": "warning",
            "message": {"text": f"Observed {o.observed}. A lead to reproduce by hand, not a verdict."},
            "locations": _location(target_url),
            "properties": {"observed": o.observed, "reading": o.reading, "detail": o.detail},
        })

    for d in diffs:
        if d.reading != SAME:
            continue
        rules.setdefault(SAME, _rule(SAME))
        results.append({
            "ruleId": _rule_id(SAME),
            "level": "warning",
            "message": {
                "text": f"{d.identity_a} and {d.identity_b} received the same reply to the same frame. "
                "A lead to reproduce by hand, not a verdict."
            },
            "locations": _location(target_url),
            "properties": {"frame": d.frame, "reading": d.reading},
        })

    run: dict = {
        "tool": {
            "driver": {
                "name": "wsprobe",
                "version": __version__,
                "informationUri": _INFO_URI,
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }
    if profile is not None:
        run["properties"] = {"profile": profile}
    return {"$schema": SARIF_SCHEMA_URI, "version": "2.1.0", "runs": [run]}
