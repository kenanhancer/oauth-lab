"""End-to-end token-exchange flow — RFC 8693.

Two-leg flow:

1. Demo client mints a `read write` JWT access token via
   `client_credentials`.
2. Same client exchanges that token at `/token` for a narrower
   `read` token via `token-exchange`.

This forces us into JWT mode (the subject_token validator only
understands JWTs we ourselves signed), so this test file builds its
own app with `token_format=jwt` rather than reusing the conftest's
opaque-mode fixture.

Location: `tests/integration/token_exchange_flow/`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import jwt
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, BasicAuth

from oauth_lab.adapter.outbound.persistence.memory.client_repository import (
    InMemoryClientRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.trusted_assertion_issuer_repository import (
    InMemoryTrustedAssertionIssuerRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.user_repository import InMemoryUserRepository
from oauth_lab.config import Settings
from oauth_lab.container import build_container
from oauth_lab.main import create_app
from tests.conftest import (
    DEMO_EXCHANGE_CLIENT_ID,
    DEMO_EXCHANGE_CLIENT_SECRET,
)

_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
_BASIC = BasicAuth(DEMO_EXCHANGE_CLIENT_ID, DEMO_EXCHANGE_CLIENT_SECRET)


@pytest.fixture
async def jwt_app(
    demo_clients: InMemoryClientRepository,
    demo_users: InMemoryUserRepository,
    trusted_issuers: InMemoryTrustedAssertionIssuerRepository,
) -> FastAPI:
    """Custom app fixture with `token_format=jwt`.

    The conftest default is opaque tokens, but token-exchange needs
    JWTs so the validator can verify them.
    """
    settings = Settings(
        database_url="memory://",
        token_format="jwt",
        session_secret_key="test-secret-stable-across-runs",
    )
    container = await build_container(
        settings,
        clients_override=demo_clients,
        users_override=demo_users,
        trusted_issuers_override=trusted_issuers,
    )
    fastapi_app = create_app(settings=container.settings)
    fastapi_app.state.container = container
    return fastapi_app


@pytest.fixture
async def jwt_client(jwt_app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=jwt_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _mint_initial_token(client: AsyncClient, *, scope: str = "read write") -> str:
    resp = await client.post(
        "/token",
        data={"grant_type": "client_credentials", "scope": scope},
        auth=_BASIC,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _decode_unsafe(token: str) -> dict:
    """Decode the token without verifying — for inspecting claims in tests."""
    return jwt.decode(token, options={"verify_signature": False})


class TestTokenExchangeHappyPath:
    async def test_downscope_read_write_to_read(self, jwt_client: AsyncClient) -> None:
        subject_token = await _mint_initial_token(jwt_client)

        resp = await jwt_client.post(
            "/token",
            data={
                "grant_type": _GRANT_TYPE,
                "subject_token": subject_token,
                "subject_token_type": _ACCESS_TOKEN_TYPE,
                "scope": "read",
            },
            auth=_BASIC,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["issued_token_type"] == _ACCESS_TOKEN_TYPE
        assert body["scope"] == "read"

        # Inspect the issued access token — it must carry the downscope
        claims = _decode_unsafe(body["access_token"])
        assert claims["scope"] == "read"
        assert claims["client_id"] == DEMO_EXCHANGE_CLIENT_ID

    async def test_audience_switch(self, jwt_client: AsyncClient) -> None:
        subject_token = await _mint_initial_token(jwt_client)

        resp = await jwt_client.post(
            "/token",
            data={
                "grant_type": _GRANT_TYPE,
                "subject_token": subject_token,
                "subject_token_type": _ACCESS_TOKEN_TYPE,
                "audience": "https://downstream.example.com",
                "scope": "read",
            },
            auth=_BASIC,
        )
        assert resp.status_code == 200, resp.text
        claims = _decode_unsafe(resp.json()["access_token"])
        assert claims["aud"] == "https://downstream.example.com"


class TestTokenExchangeErrorPaths:
    async def test_missing_subject_token_returns_invalid_request(
        self, jwt_client: AsyncClient
    ) -> None:
        resp = await jwt_client.post(
            "/token",
            data={
                "grant_type": _GRANT_TYPE,
                "subject_token_type": _ACCESS_TOKEN_TYPE,
            },
            auth=_BASIC,
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_missing_subject_token_type_returns_invalid_request(
        self, jwt_client: AsyncClient
    ) -> None:
        resp = await jwt_client.post(
            "/token",
            data={"grant_type": _GRANT_TYPE, "subject_token": "anything"},
            auth=_BASIC,
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_garbage_subject_token_returns_invalid_grant(
        self, jwt_client: AsyncClient
    ) -> None:
        resp = await jwt_client.post(
            "/token",
            data={
                "grant_type": _GRANT_TYPE,
                "subject_token": "not-a-jwt",
                "subject_token_type": _ACCESS_TOKEN_TYPE,
            },
            auth=_BASIC,
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_unsupported_subject_token_type_returns_invalid_request(
        self, jwt_client: AsyncClient
    ) -> None:
        resp = await jwt_client.post(
            "/token",
            data={
                "grant_type": _GRANT_TYPE,
                "subject_token": "anything",
                "subject_token_type": "urn:ietf:params:oauth:token-type:saml2",
            },
            auth=_BASIC,
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_client_without_token_exchange_rejected(
        self, jwt_client: AsyncClient
    ) -> None:
        # demo-client only has client_credentials, not token-exchange
        subject_token = await _mint_initial_token(jwt_client)
        resp = await jwt_client.post(
            "/token",
            data={
                "grant_type": _GRANT_TYPE,
                "subject_token": subject_token,
                "subject_token_type": _ACCESS_TOKEN_TYPE,
                "scope": "read",
            },
            auth=BasicAuth("demo-client", "demo-secret"),
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "unauthorized_client"
