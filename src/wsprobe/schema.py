"""Export the profile JSON schema as a build artifact.

The schema is the contract a separate capture-emitter companion builds against,
so it is kept clean and stable and lives at the repo root as profile.schema.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from .profile import Profile

_TITLE = "wsprobe profile"
_ID = "https://wsprobe.example.test/schemas/profile.schema.json"


def profile_schema() -> dict:
    schema = Profile.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = _ID
    schema["title"] = _TITLE
    return schema


def write_schema(path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(profile_schema(), indent=2, sort_keys=True) + "\n")
    return path
