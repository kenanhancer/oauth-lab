"""End-to-end jwt-bearer flow — RFC 7523 §2.1.

A confidential client authenticates with HTTP Basic and presents a
signed JWT (`assertion`) from a trusted external issuer; the AS
mints an access token for the subject claimed in the assertion.

Location: `tests/integration/jwt_bearer_flow/` — folder name carries
the scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from httpx import AsyncClient, BasicAuth

from tests.conftest import (
    DEMO_JWT_BEARER_CLIENT_ID,
    DEMO_JWT_BEARER_CLIENT_SECRET,
    DEMO_TOKEN_AUDIENCE,
    DEMO_TRUSTED_ISSUER,
)

_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_SUBJECT = "user-alice"


def _sign(
    private_pem: bytes,
    *,
    iss: str = DEMO_TRUSTED_ISSUER,
    sub: str = _SUBJECT,
    aud: str = DEMO_TOKEN_AUDIENCE,
    exp_delta: timedelta = timedelta(minutes=5),
) -> str:
    now = datetime.now(tz=UTC)
    payload = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": int(now.timestamp()),
        "exp": int((now + exp_delta).timestamp()),
    }
    return jwt.encode(payload, private_pem, algorithm="RS256")


_BASIC = BasicAuth(DEMO_JWT_BEARER_CLIENT_ID, DEMO_JWT_BEARER_CLIENT_SECRET)


class TestJwtBearerHappyPath:
    async def test_token_endpoint_mints_access_token(
        self,
        http_client: AsyncClient,
        jwt_bearer_keypair: tuple[bytes, bytes],
    ) -> None:
        private_pem, _public = jwt_bearer_keypair
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": _GRANT_TYPE,
                "assertion": _sign(private_pem),
                "scope": "read",
            },
            auth=_BASIC,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert isinstance(body["access_token"], str)
        # RFC 7523 does not issue refresh tokens for jwt-bearer
        assert "refresh_token" not in body
        assert body["scope"] == "read"


class TestJwtBearerErrorPaths:
    async def test_missing_assertion_returns_invalid_request(
        self, http_client: AsyncClient
    ) -> None:
        resp = await http_client.post(
            "/token",
            data={"grant_type": _GRANT_TYPE},
            auth=_BASIC,
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    async def test_unknown_issuer_returns_invalid_grant(
        self, http_client: AsyncClient, jwt_bearer_keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = jwt_bearer_keypair
        token = _sign(private_pem, iss="https://attacker.example.com")
        resp = await http_client.post(
            "/token",
            data={"grant_type": _GRANT_TYPE, "assertion": token},
            auth=_BASIC,
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_wrong_audience_returns_invalid_grant(
        self, http_client: AsyncClient, jwt_bearer_keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = jwt_bearer_keypair
        token = _sign(private_pem, aud="https://other-server/token")
        resp = await http_client.post(
            "/token",
            data={"grant_type": _GRANT_TYPE, "assertion": token},
            auth=_BASIC,
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_expired_assertion_returns_invalid_grant(
        self, http_client: AsyncClient, jwt_bearer_keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = jwt_bearer_keypair
        token = _sign(private_pem, exp_delta=timedelta(seconds=-30))
        resp = await http_client.post(
            "/token",
            data={"grant_type": _GRANT_TYPE, "assertion": token},
            auth=_BASIC,
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    async def test_client_without_jwt_bearer_grant_rejected(
        self, http_client: AsyncClient, jwt_bearer_keypair: tuple[bytes, bytes]
    ) -> None:
        # `demo-client` is registered for client_credentials only.
        private_pem, _public = jwt_bearer_keypair
        resp = await http_client.post(
            "/token",
            data={"grant_type": _GRANT_TYPE, "assertion": _sign(private_pem)},
            auth=BasicAuth("demo-client", "demo-secret"),
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "unauthorized_client"
