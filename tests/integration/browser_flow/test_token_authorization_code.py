"""Browser flow — exchanging an authorization code at `POST /token`.

Skips the UI half: pre-seeds an authorization code directly in the repo
and exercises only the `/token` exchange. Phase 5 will add the
`/authorize` → consent → callback path that *produces* such a code via
real HTTP.

Verifies the security-critical behaviours:
- happy-path exchange returns a Bearer token
- code is single-use (replay → invalid_grant)
- wrong PKCE verifier → invalid_grant
- wrong client → invalid_grant
- redirect_uri mismatch → invalid_grant
- expired code → invalid_grant
- missing code or code_verifier → invalid_request

Location: `tests/integration/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient

from oauth_lab.container import Container
from oauth_lab.domain.model.authorization_code import AuthorizationCode
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.pkce import PKCEChallenge
from oauth_lab.domain.model.scope import Scope, ScopeSet
from tests.conftest import DEMO_PUBLIC_CLIENT_ID, DEMO_PUBLIC_CLIENT_REDIRECT_URI

# RFC 7636 Appendix B test vectors
_PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
_PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _make_code(
    *,
    value: str = "test-auth-code-abc123",
    client_id: str = DEMO_PUBLIC_CLIENT_ID,
    redirect_uri: str = DEMO_PUBLIC_CLIENT_REDIRECT_URI,
    pkce_challenge: str = _PKCE_CHALLENGE,
    scope: str = "read",
    expires_in: timedelta = timedelta(seconds=60),
) -> AuthorizationCode:
    now = datetime.now(tz=UTC)
    return AuthorizationCode(
        value=value,
        client_id=ClientId(client_id),
        user_sub="user-alice",
        redirect_uri=redirect_uri,
        scope=ScopeSet(frozenset(Scope(s) for s in scope.split())),
        pkce_challenge=PKCEChallenge(value=pkce_challenge),
        issued_at=now,
        expires_at=now + expires_in,
    )


@pytest.fixture
async def seeded_code(container: Container) -> AuthorizationCode:
    code = _make_code()
    await container.auth_codes.save(code)
    return code


class TestPostTokenAuthorizationCode:
    async def test_happy_path_exchanges_code_for_bearer_token(
        self,
        http_client: AsyncClient,
        seeded_code: AuthorizationCode,
    ) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": seeded_code.value,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 3600
        assert body["scope"] == "read"
        assert isinstance(body["access_token"], str)
        # Phase 6: demo-spa supports refresh_token grant → refresh token issued.
        assert isinstance(body["refresh_token"], str)
        assert len(body["refresh_token"]) >= 16
        assert resp.headers.get("cache-control") == "no-store"

    async def test_code_cannot_be_replayed(
        self,
        http_client: AsyncClient,
        seeded_code: AuthorizationCode,
    ) -> None:
        first = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": seeded_code.value,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert first.status_code == 200, first.text

        replay = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": seeded_code.value,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"

    async def test_wrong_pkce_verifier_fails(
        self,
        http_client: AsyncClient,
        seeded_code: AuthorizationCode,
    ) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": seeded_code.value,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": "x" * 43,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_redirect_uri_mismatch_fails(
        self,
        http_client: AsyncClient,
        seeded_code: AuthorizationCode,
    ) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": seeded_code.value,
                "redirect_uri": "http://evil.example.com/callback",
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_missing_code_returns_invalid_request(
        self,
        http_client: AsyncClient,
    ) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_missing_code_verifier_returns_invalid_request(
        self,
        http_client: AsyncClient,
        seeded_code: AuthorizationCode,
    ) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": seeded_code.value,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_unknown_code_returns_invalid_grant(
        self,
        http_client: AsyncClient,
    ) -> None:
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": "this-code-was-never-issued",
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_expired_code_fails(
        self,
        http_client: AsyncClient,
        container: Container,
    ) -> None:
        expired = _make_code(
            value="expired-code",
            expires_in=timedelta(seconds=-1),                              # already expired
        )
        await container.auth_codes.save(expired)
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": expired.value,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"
