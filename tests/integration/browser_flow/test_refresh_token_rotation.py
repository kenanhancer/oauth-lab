"""Refresh token rotation + replay defence — `/token grant_type=refresh_token`.

Full end-to-end through the browser flow and the rotation chain:

    1. Auth code exchange → issues access_token #1 + refresh_token #1
    2. refresh_token #1 → access_token #2 + refresh_token #2 (rotation)
    3. refresh_token #2 → access_token #3 + refresh_token #3
    4. Reuse refresh_token #1 (already consumed) →
           - request fails with invalid_grant
           - RFC 9700 § 2.2.2: entire family is revoked
    5. refresh_token #3 (still active before step 4) is also now invalid

Location: `tests/integration/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from httpx import AsyncClient

from oauth_lab.container import Container
from oauth_lab.domain.model.authorization_code import AuthorizationCode
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.pkce import PKCEChallenge
from oauth_lab.domain.model.scope import Scope, ScopeSet
from tests.conftest import (
    DEMO_PUBLIC_CLIENT_ID,
    DEMO_PUBLIC_CLIENT_REDIRECT_URI,
)

_PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
_PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.fixture
async def initial_token_pair(http_client: AsyncClient, container: Container) -> dict[str, str]:
    """Pre-seed a code, run the consent → exchange dance, return the token pair."""

    # Pre-seed an auth code (skips /login + /consent UI for setup speed).
    now = datetime.now(tz=UTC)
    code = AuthorizationCode(
        value="seed-code-for-rotation",
        client_id=ClientId(DEMO_PUBLIC_CLIENT_ID),
        user_sub="user-alice",
        redirect_uri=DEMO_PUBLIC_CLIENT_REDIRECT_URI,
        scope=ScopeSet(frozenset({Scope("read")})),
        pkce_challenge=PKCEChallenge(value=_PKCE_CHALLENGE),
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
    )
    await container.auth_codes.save(code)

    resp = await http_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": DEMO_PUBLIC_CLIENT_ID,
            "code": code.value,
            "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
            "code_verifier": _PKCE_VERIFIER,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return {"access_token": body["access_token"], "refresh_token": body["refresh_token"]}


class TestAuthorizationCodeIssuesRefreshToken:
    async def test_refresh_token_present_in_response(
        self, initial_token_pair: dict[str, str]
    ) -> None:
        # Client `demo-spa` has `refresh_token` in allowed_grant_types →
        # the AuthorizationCodeGrant must also issue a refresh_token.
        assert isinstance(initial_token_pair["refresh_token"], str)
        assert len(initial_token_pair["refresh_token"]) >= 16


class TestRefreshTokenRotation:
    async def test_happy_path_rotates_and_returns_new_pair(
        self,
        http_client: AsyncClient,
        initial_token_pair: dict[str, str],
    ) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "refresh_token": initial_token_pair["refresh_token"],
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert isinstance(body["access_token"], str)
        assert isinstance(body["refresh_token"], str)
        # New tokens, different values
        assert body["access_token"] != initial_token_pair["access_token"]
        assert body["refresh_token"] != initial_token_pair["refresh_token"]

    async def test_chain_of_rotations(
        self,
        http_client: AsyncClient,
        initial_token_pair: dict[str, str],
    ) -> None:
        current_rt = initial_token_pair["refresh_token"]
        seen: set[str] = {current_rt}
        for _ in range(3):
            resp = await http_client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": DEMO_PUBLIC_CLIENT_ID,
                    "refresh_token": current_rt,
                },
            )
            assert resp.status_code == 200
            current_rt = resp.json()["refresh_token"]
            assert current_rt not in seen
            seen.add(current_rt)


class TestRefreshTokenReplayDefence:
    async def test_replay_old_token_revokes_family(
        self,
        http_client: AsyncClient,
        initial_token_pair: dict[str, str],
    ) -> None:
        # First rotation succeeds — old token is now consumed.
        first = await http_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "refresh_token": initial_token_pair["refresh_token"],
            },
        )
        assert first.status_code == 200
        rt_after_first = first.json()["refresh_token"]

        # REPLAY: re-using the original token must fail and revoke chain.
        replay = await http_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "refresh_token": initial_token_pair["refresh_token"],
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"

        # The latest-issued token (rt_after_first) is now also invalid —
        # the whole family was revoked.
        cascaded = await http_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "refresh_token": rt_after_first,
            },
        )
        assert cascaded.status_code == 400
        assert cascaded.json()["error"] == "invalid_grant"


class TestRefreshTokenEdgeCases:
    async def test_unknown_token_invalid_grant(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "refresh_token": "this-token-never-existed",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_missing_token_invalid_request(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_wrong_client(
        self,
        http_client: AsyncClient,
        initial_token_pair: dict[str, str],
    ) -> None:
        # The token was issued to demo-spa; try to redeem with the
        # confidential demo-client (which also doesn't support refresh).
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": initial_token_pair["refresh_token"],
            },
            headers={
                "Authorization": "Basic "
                + __import__("base64")
                .b64encode(b"demo-client:demo-secret")
                .decode("ascii")
            },
        )
        # demo-client is NOT allowed to use refresh_token (unauthorized_client)
        assert resp.status_code == 400
        assert resp.json()["error"] == "unauthorized_client"


# Suppress the unused-import warning on `urlencode` / `urlparse` / `parse_qs`
# (kept for future tests reading state from redirect callbacks).
_ = (urlencode, urlparse, parse_qs)
