"""JwtBearerGrant strategy — RFC 7523 §2.1 + §3 validation rules.

Scenario: jwt-bearer flow. Pure-domain test with a real PyJwt verifier
(it's cheap, in-process, and tests both layers together — the value of
the unit lives in the *behaviour* it specifies, not in faking
dependencies).

Location: `tests/unit/jwt_bearer_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from oauth_lab.adapter.outbound.crypto.key_generator import (
    generate_rsa_keypair_pem,
    public_key_pem_from_private,
)
from oauth_lab.adapter.outbound.crypto.pyjwt_assertion_verifier import PyJwtAssertionVerifier
from oauth_lab.adapter.outbound.persistence.memory.trusted_assertion_issuer_repository import (
    InMemoryTrustedAssertionIssuerRepository,
)
from oauth_lab.application.port.inbound.issue_token_use_case import TokenRequest
from oauth_lab.application.port.outbound.token_issuer import IssuedToken
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.jwt_bearer_grant import JwtBearerGrant
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidGrant, InvalidRequest, UnauthorizedClient
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import Scope, ScopeSet
from oauth_lab.domain.model.trusted_assertion_issuer import TrustedAssertionIssuer
from oauth_lab.domain.service.scope_validator import ScopeValidator

_ISSUER = "https://idp.example.com"
_AUDIENCE = "http://localhost:8000/token"
_SUBJECT = "user-alice"


class _StubTokenIssuer:
    async def issue(self, *, subject, client_id, scope, audience, ttl_seconds):
        return IssuedToken(value=f"stub-{subject}", expires_in_seconds=ttl_seconds)


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    private_pem = generate_rsa_keypair_pem()
    return private_pem, public_key_pem_from_private(private_pem)


@pytest.fixture
async def grant(keypair: tuple[bytes, bytes]) -> JwtBearerGrant:
    _private_pem, public_pem = keypair
    issuers = InMemoryTrustedAssertionIssuerRepository()
    await issuers.save(
        TrustedAssertionIssuer(
            issuer=_ISSUER,
            public_key_pem=public_pem,
            algorithm="RS256",
            allowed_audiences=frozenset({_AUDIENCE}),
        )
    )
    return JwtBearerGrant(
        token_issuer=_StubTokenIssuer(),
        trusted_issuers=issuers,
        assertion_verifier=PyJwtAssertionVerifier(),
        scope_validator=ScopeValidator(),
        expected_audience=_AUDIENCE,
        access_token_ttl_seconds=3600,
    )


def _make_client(
    *,
    grants: frozenset[GrantType] = frozenset({GrantType.JWT_BEARER}),
) -> AuthenticatedClient:
    return AuthenticatedClient(
        client=Client(
            id=ClientId("demo-jwt-bearer"),
            secret_hash=b"unused-in-this-test",
            token_endpoint_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
            allowed_grant_types=grants,
            allowed_scopes=ScopeSet(frozenset({Scope("read"), Scope("write")})),
            default_audience="https://api.example.com",
        ),
        auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
    )


def _sign(
    private_pem: bytes,
    *,
    iss: str = _ISSUER,
    sub: str = _SUBJECT,
    aud: str | list[str] = _AUDIENCE,
    exp_delta: timedelta = timedelta(minutes=5),
    nbf_delta: timedelta | None = None,
    algorithm: str = "RS256",
    extra: dict | None = None,
) -> str:
    now = datetime.now(tz=UTC)
    payload: dict = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": int(now.timestamp()),
        "exp": int((now + exp_delta).timestamp()),
    }
    if nbf_delta is not None:
        payload["nbf"] = int((now + nbf_delta).timestamp())
    if extra:
        payload.update(extra)
    return jwt.encode(payload, private_pem, algorithm=algorithm)


def _request(assertion: str) -> TokenRequest:
    return TokenRequest(grant_type=GrantType.JWT_BEARER, assertion=assertion)


class TestJwtBearerGrant:
    async def test_happy_path_returns_access_token_with_subject(
        self, grant: JwtBearerGrant, keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = keypair
        result = await grant.execute(_request(_sign(private_pem)), _make_client())
        assert result.access_token == f"stub-{_SUBJECT}"
        assert result.token_type == "Bearer"
        assert result.refresh_token is None  # jwt-bearer does not issue refresh

    async def test_missing_assertion_raises_invalid_request(self, grant: JwtBearerGrant) -> None:
        with pytest.raises(InvalidRequest):
            await grant.execute(TokenRequest(grant_type=GrantType.JWT_BEARER), _make_client())

    async def test_client_not_allowed_grant_raises(
        self, grant: JwtBearerGrant, keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = keypair
        client = _make_client(grants=frozenset({GrantType.CLIENT_CREDENTIALS}))
        with pytest.raises(UnauthorizedClient):
            await grant.execute(_request(_sign(private_pem)), client)

    async def test_unknown_issuer_raises_invalid_grant(
        self, grant: JwtBearerGrant, keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = keypair
        token = _sign(private_pem, iss="https://attacker.example.com")
        with pytest.raises(InvalidGrant, match="not trusted"):
            await grant.execute(_request(token), _make_client())

    async def test_expired_assertion_raises(
        self, grant: JwtBearerGrant, keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = keypair
        token = _sign(private_pem, exp_delta=timedelta(seconds=-1))
        with pytest.raises(InvalidGrant, match="expired"):
            await grant.execute(_request(token), _make_client())

    async def test_wrong_audience_raises(
        self, grant: JwtBearerGrant, keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = keypair
        token = _sign(private_pem, aud="https://some-other-server/token")
        with pytest.raises(InvalidGrant, match="audience"):
            await grant.execute(_request(token), _make_client())

    async def test_signature_signed_with_wrong_key_raises(self, grant: JwtBearerGrant) -> None:
        attacker_pem = generate_rsa_keypair_pem()
        token = _sign(attacker_pem)
        with pytest.raises(InvalidGrant, match="signature"):
            await grant.execute(_request(token), _make_client())

    async def test_garbage_assertion_raises(self, grant: JwtBearerGrant) -> None:
        with pytest.raises(InvalidGrant):
            await grant.execute(_request("not-a-jwt"), _make_client())

    async def test_nbf_in_future_raises(
        self, grant: JwtBearerGrant, keypair: tuple[bytes, bytes]
    ) -> None:
        private_pem, _public = keypair
        token = _sign(private_pem, nbf_delta=timedelta(minutes=5))
        with pytest.raises(InvalidGrant, match="not yet valid"):
            await grant.execute(_request(token), _make_client())

    async def test_missing_sub_claim_raises(
        self, grant: JwtBearerGrant, keypair: tuple[bytes, bytes]
    ) -> None:
        # Sign a payload that drops `sub` entirely.
        private_pem, _public = keypair
        now = datetime.now(tz=UTC)
        payload = {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        token = jwt.encode(payload, private_pem, algorithm="RS256")
        with pytest.raises(InvalidGrant, match="sub"):
            await grant.execute(_request(token), _make_client())
