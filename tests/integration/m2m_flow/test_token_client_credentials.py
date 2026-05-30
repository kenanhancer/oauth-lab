"""Machine-to-machine (M2M) token issuance — `client_credentials`, RFC 6749 §4.4.

Scenario actors: client application ↔ authorization server.
No user. No browser. No refresh token. The smallest end-to-end OAuth flow.

This file exercises `POST /token` through the full FastAPI stack — custom
token route, handler, use case, client-auth pipeline, grant strategy,
in-memory client repository, and the opaque token issuer.

Location: `tests/integration/m2m_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

import base64

from httpx import AsyncClient

from tests.conftest import DEMO_CLIENT_ID, DEMO_CLIENT_SECRET


def _basic(user: str, pw: str) -> str:
    raw = f"{user}:{pw}".encode()
    return "Basic " + base64.b64encode(raw).decode("ascii")


class TestPostTokenClientCredentials:
    async def test_happy_path_returns_access_token(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/token",
            headers={"Authorization": _basic(DEMO_CLIENT_ID, DEMO_CLIENT_SECRET)},
            data={"grant_type": "client_credentials", "scope": "read"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 3600
        assert body["scope"] == "read"
        assert isinstance(body["access_token"], str)
        assert len(body["access_token"]) >= 16
        # RFC 6749 §5.1 — no caching
        assert resp.headers.get("cache-control") == "no-store"

    async def test_wrong_secret_returns_invalid_client(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/token",
            headers={"Authorization": _basic(DEMO_CLIENT_ID, "wrong-password")},
            data={"grant_type": "client_credentials"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"
        assert "WWW-Authenticate" in resp.headers

    async def test_unknown_client(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/token",
            headers={"Authorization": _basic("does-not-exist", "x")},
            data={"grant_type": "client_credentials"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"

    async def test_unsupported_scope(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/token",
            headers={"Authorization": _basic(DEMO_CLIENT_ID, DEMO_CLIENT_SECRET)},
            data={"grant_type": "client_credentials", "scope": "delete-all"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_scope"

    async def test_unknown_grant_type(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/token",
            headers={"Authorization": _basic(DEMO_CLIENT_ID, DEMO_CLIENT_SECRET)},
            data={"grant_type": "password", "username": "x", "password": "y"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "unsupported_grant_type"

    async def test_no_auth_returns_invalid_client(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/token",
            data={"grant_type": "client_credentials"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"
