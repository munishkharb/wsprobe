"""Shared fixtures. Paths and the target URL are built at runtime so nothing in
the tree hard-codes a host or an absolute path."""

from __future__ import annotations

import asyncio
import threading

import pytest
import pytest_asyncio

from wsprobe.profile import (
    Auth,
    Channel,
    Handshake,
    Heartbeat,
    MessageMap,
    Probes,
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
                probes=Probes(
                    control_frame={"type": "subscribe", "topic": "admin"},
                    identity_probe={"type": "whoami"},
                    identity_param="user",
                    identity_field="user",
                ),
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


@pytest.fixture
def live_server():
    """A synchronous view of the fixture server for CLI tests.

    The CLI verbs call asyncio.run() internally, so they must run in a thread
    with no event loop already turning. This runs the async fixture on its own
    loop in a background thread and yields (host, port) to a plain sync test;
    the client the CLI opens reaches it over TCP like any other socket.
    """
    holder: dict = {}
    ready = threading.Event()
    loop = asyncio.new_event_loop()

    async def _main() -> None:
        async with run_fixture() as (host, port):
            holder["addr"] = (host, port)
            holder["stop"] = asyncio.Event()
            ready.set()
            await holder["stop"].wait()

    def _run() -> None:
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_main())
        finally:
            loop.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    if not ready.wait(timeout=5):
        raise RuntimeError("fixture server did not start")
    try:
        yield holder["addr"]
    finally:
        loop.call_soon_threadsafe(holder["stop"].set)
        thread.join(timeout=5)
