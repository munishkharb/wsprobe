"""Stable JSON output for the observation commands.

The human tables are the default surface. This module is the other one: a
single, documented, versioned JSON shape an external caller (the Burp companion
panel, or any script) can parse without scraping a table. It is the one place
the JSON contract lives, so the shape stays stable as the internals move.

Contract, one envelope per command. Every payload carries a `schema` tag of the
form `wsprobe.<command>/v1` and a `command` field, so a reader can dispatch on
`schema` and trust the keys under it.

matrix  (schema "wsprobe.matrix/v1")
    {
      "schema": "wsprobe.matrix/v1",
      "command": "matrix",
      "profile": "<profile name>",
      "channel": "<channel name>",
      "observations": [
        {"check": "unauth-upgrade",
         "observed": "upgraded-without-auth",
         "reading": "insecure-shape",
         "detail": { ... }},
        ...
      ]
    }

diff  (schema "wsprobe.diff/v1")
    {
      "schema": "wsprobe.diff/v1",
      "command": "diff",
      "profile": "<profile name>",
      "channel": "<channel name>",
      "frame": { ... the frame sent from both identities ... },
      "identity_a": "A",
      "identity_b": "B",
      "reading": "same-across-identities",
      "reply_a": { ... },
      "reply_b": { ... }
    }

sweep  (schema "wsprobe.sweep/v1")
    {
      "schema": "wsprobe.sweep/v1",
      "command": "sweep",
      "profile": "<profile name>",
      "channel": "<channel name>",
      "field": "<swept field>",
      "distinct_replies": 2,
      "rows": [
        {"value": "alice", "frame": { ... }, "reply": { ... }},
        ...
      ]
    }

analyze  (schema "wsprobe.analyze/v1")
    {
      "schema": "wsprobe.analyze/v1",
      "command": "analyze",
      "sources": ["session.ndjson", ...],
      "total_frames": 10,
      "dropped_heartbeats": 2,
      "type_field": "type",
      "correlation_keys": ["cid"],
      "heartbeat_types": ["ping", "pong"],
      "inventory": [
        {"name": "whoami", "total": 2, "sent": 1, "recv": 1, "direction": "both"},
        ...
      ],
      "correlations": [
        {"key": "1", "request": { ... }, "reply": { ... }},
        ...
      ]
    }

Reading tags are the same observation vocabulary the human tables use
(control-present, insecure-shape, inconclusive, same-across-identities, ...).
As everywhere in wsprobe, the word "confirmed" never appears: these are
observations the operator reproduces, not verdicts the tool issues.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Iterable

from .analyzer import Analysis
from .authz import DiffResult, SweepResult
from .matrix import Observation

# Bump the version suffix only for a breaking change to a shape below.
MATRIX_SCHEMA = "wsprobe.matrix/v1"
DIFF_SCHEMA = "wsprobe.diff/v1"
SWEEP_SCHEMA = "wsprobe.sweep/v1"
ANALYZE_SCHEMA = "wsprobe.analyze/v1"


def matrix_payload(observations: Iterable[Observation], *, profile: str, channel: str) -> dict:
    return {
        "schema": MATRIX_SCHEMA,
        "command": "matrix",
        "profile": profile,
        "channel": channel,
        "observations": [asdict(o) for o in observations],
    }


def diff_payload(result: DiffResult, *, profile: str, channel: str) -> dict:
    return {
        "schema": DIFF_SCHEMA,
        "command": "diff",
        "profile": profile,
        "channel": channel,
        "frame": result.frame,
        "identity_a": result.identity_a,
        "identity_b": result.identity_b,
        "reading": result.reading,
        "reply_a": result.reply_a,
        "reply_b": result.reply_b,
    }


def sweep_payload(result: SweepResult, *, profile: str, channel: str) -> dict:
    return {
        "schema": SWEEP_SCHEMA,
        "command": "sweep",
        "profile": profile,
        "channel": channel,
        "field": result.field,
        "distinct_replies": result.distinct_replies,
        "rows": [{"value": row.value, "frame": row.frame, "reply": row.reply} for row in result.rows],
    }


def analyze_payload(analysis: Analysis, *, sources: Iterable[str]) -> dict:
    inventory = [
        {"name": t.name, "total": t.total, "sent": t.sent, "recv": t.recv, "direction": t.direction}
        for t in sorted(analysis.types.values(), key=lambda t: -t.total)
    ]
    correlations = [
        {"key": c.key, "request": c.request, "reply": c.reply} for c in analysis.correlations
    ]
    return {
        "schema": ANALYZE_SCHEMA,
        "command": "analyze",
        "sources": list(sources),
        "total_frames": analysis.total_frames,
        "dropped_heartbeats": analysis.dropped_heartbeats,
        "type_field": analysis.type_field,
        "correlation_keys": list(analysis.correlation_keys),
        "heartbeat_types": list(analysis.heartbeat_types),
        "inventory": inventory,
        "correlations": correlations,
    }


def dumps(payload: dict) -> str:
    """Serialize a payload to a stable, indented JSON string."""
    return json.dumps(payload, indent=2)
