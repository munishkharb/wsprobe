"""Cookie-based handshake auth and the CSWSH precondition.

Two things are proven here with a live fixture, not asserted on faith:

1. A token placed in a cookie actually authenticates (the carriage works
   against a server that reads the token from the Cookie header).
2. The handshake matrix reads `token_location` when it judges CSWSH. CSWSH is
   only browser-exploitable when the credential is ambient (a cookie the
   victim's browser attaches to a cross-origin handshake). So against the same
   origin-blind fixture, cookie auth yields `cswsh-preconditions-met`
   (insecure-shape) while a query-param bearer yields
   `origin-not-validated-non-ambient-auth` (inconclusive, not browser-CSWSH).

The fixture never validates Origin, so the only variable between the two cases
is where the credential rides. That is exactly the distinction the feature adds.
"""

from __future__ import annotations

import pytest

from wsprobe.connection import ConnectionManager, DialOptions
from wsprobe.matrix import INCONCLUSIVE, INSECURE_SHAPE, run_matrix
from wsprobe.profile import TokenLocation

from .conftest import build_profile
from .fixture import mint_token

pytestmark = pytest.mark.asyncio


def _cookie_profile(host, port):
    prof = build_profile(host, port)
    prof.channels[0].auth.token_location = TokenLocation.cookie
    prof.channels[0].auth.token_param = "token"
    return prof


def _cswsh_row(obs):
    rows = [o for o in obs if o.check == "cswsh"]
    assert len(rows) == 1, f"expected exactly one cswsh row, got {[o.check for o in obs]}"
    return rows[0]


async def test_cookie_token_actually_authenticates(server):
    """Carriage proof: the token in a cookie reaches the server and binds the
    identity, so whoami returns the authenticated user, not anon."""
    host, port = server
    mgr = ConnectionManager(_cookie_profile(host, port), token=mint_token("alice"), identity="alice")
    async with mgr.dial(DialOptions()) as conn:
        reply = await conn.request({"type": "whoami"}, timeout=3.0)
    assert reply["user"] == "alice"


async def test_cookie_auth_meets_cswsh_preconditions(server):
    """Ambient credential + no Origin validation = the CSWSH shape."""
    host, port = server
    mgr = ConnectionManager(_cookie_profile(host, port), token=mint_token("alice"), identity="alice")
    row = _cswsh_row(await run_matrix(mgr))
    assert row.observed == "cswsh-preconditions-met"
    assert row.reading == INSECURE_SHAPE
    assert row.detail["ambient_auth"] is True
    assert row.detail["token_location"] == "cookie"
    assert row.detail["accepted_origins"]  # at least one untrusted origin got in


async def test_query_bearer_is_not_browser_cswsh(server):
    """Same origin-blind server, but a query-param bearer cannot be replayed by
    a cross-origin browser, so it is reported as not-browser-CSWSH, never as the
    CSWSH insecure shape. This is the contrast that proves the row isn't a
    rubber stamp on 'origin accepted'."""
    host, port = server
    mgr = ConnectionManager(build_profile(host, port), token=mint_token("alice"), identity="alice")
    row = _cswsh_row(await run_matrix(mgr))
    assert row.observed == "origin-not-validated-non-ambient-auth"
    assert row.reading == INCONCLUSIVE
    assert row.detail["ambient_auth"] is False
    assert row.detail["token_location"] == "query"


async def test_cswsh_row_never_says_confirmed(server):
    host, port = server
    mgr = ConnectionManager(_cookie_profile(host, port), token=mint_token("alice"), identity="alice")
    for o in await run_matrix(mgr):
        assert "confirmed" not in o.observed.lower()
        assert "confirmed" not in o.reading.lower()
