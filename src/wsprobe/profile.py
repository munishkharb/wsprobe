"""Profile model: the single piece of target-specific knowledge the engine needs.

A profile is a declarative, validated document describing how to open a socket
and how to speak the target's message language. It is authored by hand or
drafted by the capture analyzer, then refined. The JSON schema for this model
is published as profile.schema.json and is the contract a companion capture
emitter builds against.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class Framing(str, Enum):
    json = "json"
    socketio = "socketio"
    length_prefixed = "length-prefixed"
    binary = "binary"


class TokenLocation(str, Enum):
    query = "query"
    header = "header"
    subprotocol = "subprotocol"
    login_frame = "login-frame"


class LoginStep(str, Enum):
    none = "none"
    http = "http"
    command = "command"
    token_file = "token-file"


class RefreshPolicy(str, Enum):
    per_dial = "per-dial"
    reuse = "reuse"
    ttl = "ttl"


class Handshake(BaseModel):
    """How to open the socket. Where the token goes is on Auth, since the
    engine has to fetch a token before it can place it here."""

    model_config = {"extra": "forbid"}

    url: str = Field(description="Upgrade URL, ws:// or wss://.")
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    origin: str | None = None
    subprotocol: str | None = None
    framing: Framing = Framing.json

    @field_validator("url")
    @classmethod
    def _scheme(cls, v: str) -> str:
        if not (v.startswith("ws://") or v.startswith("wss://")):
            raise ValueError("handshake.url must start with ws:// or wss://")
        return v


class HttpLogin(BaseModel):
    model_config = {"extra": "forbid"}

    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, object] = Field(default_factory=dict)


class Auth(BaseModel):
    """How a valid token is acquired, placed, and kept fresh.

    The refresh policy is load-bearing: many targets mint a single-use token
    per connection, so re-authenticating mid-run revokes the token a live
    socket is holding. per-dial mints one token per new dial; reuse harvests
    one and holds it; ttl caches until an age limit.
    """

    model_config = {"extra": "forbid"}

    login: LoginStep = LoginStep.none
    token_location: TokenLocation = TokenLocation.query
    token_param: str = Field(
        default="token",
        description="Query key, header name, subprotocol prefix, or login-frame field.",
    )
    token_extract: str | None = Field(
        default=None,
        description="Dot path into a login response JSON body, e.g. data.token.",
    )
    refresh: RefreshPolicy = RefreshPolicy.per_dial
    ttl_seconds: float | None = None

    token_file: str | None = None
    command: list[str] | None = None
    http: HttpLogin | None = None

    @model_validator(mode="after")
    def _source_present(self) -> "Auth":
        need = {
            LoginStep.token_file: self.token_file,
            LoginStep.command: self.command,
            LoginStep.http: self.http,
        }
        if self.login in need and need[self.login] is None:
            raise ValueError(f"auth.login={self.login.value} requires its matching source field")
        if self.refresh is RefreshPolicy.ttl and self.ttl_seconds is None:
            raise ValueError("auth.refresh=ttl requires ttl_seconds")
        return self


class MessageMap(BaseModel):
    """The message vocabulary: the field that names a type, the keys that pair
    a request to its reply, and optional human names for opcodes."""

    model_config = {"extra": "forbid"}

    type_field: str = "type"
    correlation_keys: list[str] = Field(default_factory=lambda: ["cid"])
    opcode_names: dict[str, str] = Field(default_factory=dict)


class Heartbeat(BaseModel):
    """The keepalive pattern to drop, so correlation and discovery stay
    readable on a busy socket."""

    model_config = {"extra": "forbid"}

    types: list[str] = Field(default_factory=list)
    payloads: list[str] = Field(default_factory=list)


class Channel(BaseModel):
    """One authoritative socket. A target that runs several distinct sockets
    declares one channel each."""

    model_config = {"extra": "forbid"}

    name: str
    handshake: Handshake
    auth: Auth = Field(default_factory=Auth)
    messages: MessageMap = Field(default_factory=MessageMap)
    heartbeat: Heartbeat = Field(default_factory=Heartbeat)


class Profile(BaseModel):
    """A portable, reusable description of one target's WebSocket surface."""

    model_config = {"extra": "forbid"}

    name: str
    channels: list[Channel] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_names(self) -> "Profile":
        names = [c.name for c in self.channels]
        if len(names) != len(set(names)):
            raise ValueError("channel names must be unique")
        return self

    def channel(self, name: str | None = None) -> Channel:
        if name is None:
            return self.channels[0]
        for c in self.channels:
            if c.name == name:
                return c
        raise KeyError(f"no channel named {name!r}")


def load_profile(path: str | Path) -> Profile:
    text = Path(path).read_text()
    data = yaml.safe_load(text)
    return Profile.model_validate(data)


def dump_profile(profile: Profile) -> str:
    data = profile.model_dump(mode="json", exclude_none=True, exclude_defaults=True)
    return yaml.safe_dump(data, sort_keys=False)
