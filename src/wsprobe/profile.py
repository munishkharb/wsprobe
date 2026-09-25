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
    text = "text"
    socketio = "socketio"
    length_prefixed = "length-prefixed"
    binary = "binary"


class TokenLocation(str, Enum):
    query = "query"
    header = "header"
    subprotocol = "subprotocol"
    cookie = "cookie"
    login_frame = "login-frame"


class Correlation(str, Enum):
    """How a reply is paired to its request.

    echo: the server echoes the correlation key(s) back on the reply (the
    default, and the only mode a correlation-id-echoing server needs).
    ordered: the socket answers in order, so the next non-heartbeat frame is
    the reply. This is what most real servers actually do.
    ack: the framing carries its own acknowledgement id (Socket.IO acks), so
    the codec pairs request to reply below the message map.
    """

    echo = "echo"
    ordered = "ordered"
    ack = "ack"


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
        description="Query key, header/cookie name, subprotocol prefix, or login-frame field.",
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

    login_frame: dict[str, object] | None = Field(
        default=None,
        description=(
            "Template for a login-frame handshake. The token is placed at "
            "token_param; any '§token§' string in the template is also replaced. "
            "When unset, login-frame carriage sends {type_field: 'login', "
            "token_param: <token>}."
        ),
    )

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
    correlation: Correlation = Correlation.echo
    opcode_names: dict[str, str] = Field(default_factory=dict)


class Heartbeat(BaseModel):
    """The keepalive pattern to drop, so correlation and discovery stay
    readable on a busy socket."""

    model_config = {"extra": "forbid"}

    types: list[str] = Field(default_factory=list)
    payloads: list[str] = Field(default_factory=list)


class Probes(BaseModel):
    """Target-specific frames the handshake matrix needs, so no fixture-shaped
    frame is baked into the engine. Each is optional; a check whose probe is
    unset is reported as inconclusive instead of run against a wrong guess."""

    model_config = {"extra": "forbid"}

    control_frame: dict[str, object] | None = Field(
        default=None,
        description="A privileged/subscribe frame to send unauthenticated, e.g. "
        '{"type": "subscribe", "topic": "admin"}. Unset skips the no-auth control check.',
    )
    identity_param: str = Field(
        default="user",
        description="The URL/query parameter tested for identity override in the "
        "cross-user-handshake check.",
    )
    identity_probe: dict[str, object] | None = Field(
        default=None,
        description='The frame that asks the server who it thinks you are, e.g. '
        '{"type": "whoami"}. Unset skips the cross-user-handshake check.',
    )
    identity_field: str = Field(
        default="user",
        description="The reply field carrying the bound identity in the identity-probe reply.",
    )


class Channel(BaseModel):
    """One authoritative socket. A target that runs several distinct sockets
    declares one channel each."""

    model_config = {"extra": "forbid"}

    name: str
    handshake: Handshake
    auth: Auth = Field(default_factory=Auth)
    messages: MessageMap = Field(default_factory=MessageMap)
    heartbeat: Heartbeat = Field(default_factory=Heartbeat)
    probes: Probes = Field(default_factory=Probes)


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
