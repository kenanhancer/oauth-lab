"""JWKS endpoint + JWT access tokens.

Verifies that:
- `GET /jwks` returns an RFC 7517 JWKS document with our signing key
- When `token_format=jwt`, `POST /token` returns a JWT access token
- The JWT verifies against the JWKS-published public key
- The JWT carries the expected RFC 9068 claims (iss, sub, aud, exp, jti, ...)

Location: `tests/integration/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

import jwt
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from oauth_lab.config import Settings
from oauth_lab.container import build_container
from oauth_lab.main import create_app
from tests.conftest import (
    DEMO_CLIENT_ID,
    DEMO_CLIENT_SECRET,
)


class TestJwksEndpoint:
    async def test_jwks_returns_keys_array(self, http_client: AsyncClient) -> None:
        resp = await http_client.get("/jwks")
        assert resp.status_code == 200
        body = resp.json()
        assert "keys" in body
        assert isinstance(body["keys"], list)
        assert len(body["keys"]) >= 1

        jwk = body["keys"][0]
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert "kid" in jwk
        assert "n" in jwk  # modulus
        assert "e" in jwk  # exponent


class TestJwtAccessToken:
    """When `token_format=jwt`, `/token` returns a self-contained JWT.

    Uses a fresh container with `token_format=jwt` to verify the
    end-to-end shape.
    """

    @pytest.fixture
    async def jwt_app(self, demo_clients, demo_users) -> FastAPI:
        settings = Settings(
            database_url="memory://",
            token_format="jwt",
            session_secret_key="test-secret-stable-across-runs",
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
    async def jwt_client(self, jwt_app):
        transport = ASGITransport(app=jwt_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client

    async def test_jwt_access_token_is_signed_jwt(self, jwt_client: AsyncClient) -> None:
        # Use the M2M `client_credentials` flow for simplicity.
        import base64

        basic = "Basic " + base64.b64encode(
            f"{DEMO_CLIENT_ID}:{DEMO_CLIENT_SECRET}".encode()
        ).decode("ascii")

        resp = await jwt_client.post(
            "/token",
            headers={"Authorization": basic},
            data={"grant_type": "client_credentials", "scope": "read"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        # JWT has three dot-separated base64url parts.
        access_token = body["access_token"]
        assert access_token.count(".") == 2

        # Decode unverified header — should advertise our signing key + RFC 9068 `at+jwt` type.
        header = jwt.get_unverified_header(access_token)
        assert header["alg"] == "RS256"
        assert header["typ"] == "at+jwt"  # RFC 9068
        assert "kid" in header

    async def test_jwt_verifies_against_jwks(
        self, jwt_app: FastAPI, jwt_client: AsyncClient
    ) -> None:
        # Get a JWT.
        import base64

        basic = "Basic " + base64.b64encode(
            f"{DEMO_CLIENT_ID}:{DEMO_CLIENT_SECRET}".encode()
        ).decode("ascii")
        resp = await jwt_client.post(
            "/token",
            headers={"Authorization": basic},
            data={"grant_type": "client_credentials", "scope": "read"},
        )
        access_token = resp.json()["access_token"]

        # Get the JWKS.
        jwks_resp = await jwt_client.get("/jwks")
        jwks = jwks_resp.json()
        assert len(jwks["keys"]) == 1

        # Verify the JWT signature against the JWKS public key.
        from jwt import PyJWK

        kid = jwt.get_unverified_header(access_token)["kid"]
        matching = [k for k in jwks["keys"] if k["kid"] == kid]
        assert len(matching) == 1
        verifying_key = PyJWK.from_dict(matching[0]).key

        claims = jwt.decode(
            access_token,
            verifying_key,
            algorithms=["RS256"],
            audience="https://api.example.com",
            options={"require": ["iss", "sub", "exp", "iat"]},
        )
        assert claims["iss"] == jwt_app.state.container.settings.issuer
        assert claims["sub"] == DEMO_CLIENT_ID
        assert claims["client_id"] == DEMO_CLIENT_ID
        assert claims["scope"] == "read"
        assert "jti" in claims
