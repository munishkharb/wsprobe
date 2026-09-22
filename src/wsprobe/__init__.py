"""wsprobe: a WebSocket security review toolkit.

The Python API is the real surface. The core objects are the profile loader and
the async connection manager whose request returns a correlated reply; every
capability is a thin front end over that shared core.
"""

from __future__ import annotations

from .analyzer import Analysis, analyze, draft_profile, emit_draft_profile
from .authz import DiffResult, SweepResult, field_sweep, two_account_diff
from .connection import Connection, ConnectionManager, DialOptions
from .matrix import Observation, run_matrix, run_matrix_sync
from .profile import Profile, dump_profile, load_profile
from .replay import ReplayResult, replay, replay_capture
from .schema import profile_schema, write_schema

__version__ = "0.1.0"

__all__ = [
    "Analysis",
    "analyze",
    "draft_profile",
    "emit_draft_profile",
    "DiffResult",
    "SweepResult",
    "field_sweep",
    "two_account_diff",
    "Connection",
    "ConnectionManager",
    "DialOptions",
    "Observation",
    "run_matrix",
    "run_matrix_sync",
    "Profile",
    "load_profile",
    "dump_profile",
    "ReplayResult",
    "replay",
    "replay_capture",
    "profile_schema",
    "write_schema",
    "__version__",
]
