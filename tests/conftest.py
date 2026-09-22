"""Shared fixtures. Paths and the target URL are built at runtime so nothing in
the tree hard-codes a host or an absolute path."""

from __future__ import annotations

import pytest
import pytest_asyncio

from wsprobe.profile import (
    Auth,
    Channel,
    Handshake,
    Heartbeat,
    MessageMap,
    Profile,
    RefreshPolicy,
    TokenLocation,
)

from .fixture import run_fixture


@pytest_asyncio.fixture
async def server():
    async with run_fixture() as (host, port):
        yield host, port


def build_profile(host: str, port: int, refresh: RefreshPolicy = RefreshPolicy.per_dial) -> Profile:
    return Profile(
        name="synthetic-fixture",
        channels=[
            Channel(
                name="default",
                handshake=Handshake(url=f"ws://{host}:{port}/socket"),
                auth=Auth(
                    token_location=TokenLocation.query,
                    token_param="token",
                    refresh=refresh,
                ),
                messages=MessageMap(type_field="type", correlation_keys=["cid"]),
                heartbeat=Heartbeat(types=["ping", "pong"]),
            )
        ],
    )


def profile_yaml(host: str, port: int) -> str:
    from wsprobe.profile import dump_profile

    return dump_profile(build_profile(host, port))


@pytest.fixture
def profile(server) -> Profile:
    host, port = server
    return build_profile(host, port)
