"""OIDC layer — id_token issuance + /userinfo endpoint.

End-to-end: client requests `scope=openid email profile`, exchanges an
authorization code, receives an `id_token` and an access token. Then
calls `/userinfo` with the access token and gets the OIDC standard
claims back.

Location: `tests/integration/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from oauth_lab.config import Settings
from oauth_lab.container import build_container
from oauth_lab.domain.model.authorization_code import AuthorizationCode
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.pkce import PKCEChallenge
from oauth_lab.domain.model.scope import Scope, ScopeSet
from oauth_lab.main import create_app
from tests.conftest import (
    DEMO_PUBLIC_CLIENT_ID,
    DEMO_PUBLIC_CLIENT_REDIRECT_URI,
)

_PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
_PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.fixture
async def oidc_app(demo_clients, demo_users) -> FastAPI:
    """A test app with JWT access tokens (so /userinfo can verify them)."""
    settings = Settings(
        database_url="memory://",
        token_format="jwt",  # /userinfo verifies JWTs
        session_secret_key="test-secret-stable",
    )
    container = await build_container(
        settings,
        clients_override=demo_clients,
        users_override=demo_users,
    )
    app = create_app(settings=container.settings)
    app.state.container = container
    return app


@pytest.fixture
async def oidc_client(oidc_app: FastAPI):
    transport = ASGITransport(app=oidc_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _seed_openid_code(
    oidc_app: FastAPI,
    *,
    nonce: str | None = None,
    scope: str = "openid email profile",
) -> str:
    container = oidc_app.state.container
    now = datetime.now(tz=UTC)
    code = AuthorizationCode(
        value="seed-openid-code",
        client_id=ClientId(DEMO_PUBLIC_CLIENT_ID),
        user_sub="user-alice",
        redirect_uri=DEMO_PUBLIC_CLIENT_REDIRECT_URI,
        scope=ScopeSet(frozenset(Scope(s) for s in scope.split())),
        pkce_challenge=PKCEChallenge(value=_PKCE_CHALLENGE),
        issued_at=now,
        expires_at=now + timedelta(seconds=60),
        nonce=nonce,
    )
    await container.auth_codes.save(code)
    return code.value


class TestIdTokenIssuance:
    async def test_openid_scope_yields_id_token(
        self, oidc_app: FastAPI, oidc_client: AsyncClient
    ) -> None:
        code = await _seed_openid_code(oidc_app)
        resp = await oidc_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": code,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "id_token" in body
        assert body["id_token"].count(".") == 2                                  # JWT shape

    async def test_id_token_claims(
        self, oidc_app: FastAPI, oidc_client: AsyncClient
    ) -> None:
        code = await _seed_openid_code(oidc_app, nonce="some-nonce-xyz")
        resp = await oidc_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": code,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        body = resp.json()

        container = oidc_app.state.container
        claims = jwt.decode(
            body["id_token"],
            container.jwks.public_pem(),
            algorithms=["RS256"],
            audience=DEMO_PUBLIC_CLIENT_ID,
        )
        assert claims["iss"] == container.settings.issuer
        assert claims["sub"] == "user-alice"
        assert claims["aud"] == DEMO_PUBLIC_CLIENT_ID
        assert claims["nonce"] == "some-nonce-xyz"                                # propagated
        assert "exp" in claims and "iat" in claims
        assert "at_hash" in claims                                                # OIDC §3.1.3.6

    async def test_no_openid_scope_no_id_token(
        self, oidc_app: FastAPI, oidc_client: AsyncClient
    ) -> None:
        code = await _seed_openid_code(oidc_app, scope="read")                    # no `openid`
        resp = await oidc_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": code,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "id_token" not in body


class TestUserInfoEndpoint:
    async def test_userinfo_returns_claims(
        self, oidc_app: FastAPI, oidc_client: AsyncClient
    ) -> None:
        code = await _seed_openid_code(oidc_app)
        token_resp = await oidc_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": code,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        access_token = token_resp.json()["access_token"]

        resp = await oidc_client.get(
            "/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["sub"] == "user-alice"
        assert body["preferred_username"] == "alice"
        assert body["email"] == "alice@example.com"
        assert body["email_verified"] is True

    async def test_userinfo_requires_bearer(self, oidc_client: AsyncClient) -> None:
        resp = await oidc_client.get("/userinfo")
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers

    async def test_userinfo_rejects_invalid_token(self, oidc_client: AsyncClient) -> None:
        resp = await oidc_client.get(
            "/userinfo", headers={"Authorization": "Bearer not.a.real.jwt"}
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"

    async def test_userinfo_omits_email_without_email_scope(
        self, oidc_app: FastAPI, oidc_client: AsyncClient
    ) -> None:
        # `openid` only → no email/profile claims.
        code = await _seed_openid_code(oidc_app, scope="openid")
        token_resp = await oidc_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": code,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        access_token = token_resp.json()["access_token"]

        resp = await oidc_client.get(
            "/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        body = resp.json()
        assert body["sub"] == "user-alice"
        assert "email" not in body
        assert "preferred_username" not in body
