"""Frame codecs sit behind the profile's framing declaration so the core stays
framing-agnostic. JSON is implemented at P0; the other framings named in the
profile model are registered stubs that raise until their phase lands.
"""

from __future__ import annotations

import json
from typing import Protocol

from .profile import Framing


class Codec(Protocol):
    def encode(self, frame: object) -> str | bytes: ...
    def decode(self, raw: str | bytes) -> object: ...


class JsonCodec:
    def encode(self, frame: object) -> str:
        return json.dumps(frame, separators=(",", ":"))

    def decode(self, raw: str | bytes) -> object:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return json.loads(raw)


class _Unimplemented:
    def __init__(self, framing: Framing) -> None:
        self._framing = framing

    def encode(self, frame: object) -> str:
        raise NotImplementedError(f"framing {self._framing.value!r} arrives in a later phase")

    def decode(self, raw: str | bytes) -> object:
        raise NotImplementedError(f"framing {self._framing.value!r} arrives in a later phase")


def codec_for(framing: Framing) -> Codec:
    if framing is Framing.json:
        return JsonCodec()
    return _Unimplemented(framing)
