"""TokenExchangeGrant strategy — RFC 8693 §2 + §4.

Scenario: token-exchange (downscope + audience switch).

Uses the real `JwtSubjectTokenValidator` against an in-process RSA
keypair — the verifier is cheap, in-process, and the value here lives
in the *behaviour* (scope intersection, claim pass-through), not in
faking the JWT.

Location: `tests/unit/token_exchange_flow/`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from oauth_lab.adapter.outbound.crypto.jwt_subject_token_validator import (
    JwtSubjectTokenValidator,
)
from oauth_lab.adapter.outbound.crypto.key_generator import (
    generate_rsa_keypair_pem,
    public_key_pem_from_private,
)
from oauth_lab.application.port.inbound.issue_token_use_case import TokenRequest
from oauth_lab.application.port.outbound.token_issuer import IssuedToken
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.token_exchange_grant import TokenExchangeGrant
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import (
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    OAuthError,
    UnauthorizedClient,
)
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import Scope, ScopeSet
from oauth_lab.domain.model.token_type_uri import TokenTypeURI
from oauth_lab.domain.service.scope_validator import ScopeValidator

_ISSUER = "http://localhost:8000"
_ACCESS_TOKEN_TYPE = TokenTypeURI.ACCESS_TOKEN.value
_SUBJECT = "user-alice"


class _RecordingTokenIssuer:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def issue(self, *, subject, client_id, scope, audience, ttl_seconds):
        self.calls.append(
            {
                "subject": subject,
                "client_id": client_id,
                "scope": scope,
                "audience": audience,
                "ttl_seconds": ttl_seconds,
            }
        )
        return IssuedToken(value=f"stub-{subject}", expires_in_seconds=ttl_seconds)


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    priv = generate_rsa_keypair_pem()
    return priv, public_key_pem_from_private(priv)


def _make_validator(keypair: tuple[bytes, bytes]) -> JwtSubjectTokenValidator:
    _priv, pub = keypair
    return JwtSubjectTokenValidator(issuer=_ISSUER, public_key_pem=pub, algorithm="RS256")


def _make_grant(
    keypair: tuple[bytes, bytes],
) -> tuple[TokenExchangeGrant, _RecordingTokenIssuer]:
    issuer = _RecordingTokenIssuer()
    grant = TokenExchangeGrant(
        token_issuer=issuer,
        subject_token_validator=_make_validator(keypair),
        scope_validator=ScopeValidator(),
        access_token_ttl_seconds=3600,
    )
    return grant, issuer


_DEFAULT_GRANTS = frozenset({GrantType.TOKEN_EXCHANGE, GrantType.CLIENT_CREDENTIALS})
_DEFAULT_SCOPES = frozenset({Scope("read"), Scope("write")})


def _make_client(
    *,
    grants: frozenset[GrantType] = _DEFAULT_GRANTS,
    allowed_scopes: frozenset[Scope] = _DEFAULT_SCOPES,
) -> AuthenticatedClient:
    return AuthenticatedClient(
        client=Client(
            id=ClientId("demo-exchange"),
            secret_hash=b"unused",
            token_endpoint_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
            allowed_grant_types=grants,
            allowed_scopes=ScopeSet(allowed_scopes),
            default_audience="https://api.example.com",
        ),
        auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
    )


def _sign_subject_token(
    private_pem: bytes,
    *,
    sub: str = _SUBJECT,
    iss: str = _ISSUER,
    scope: str = "read write",
    aud: str | None = "https://api.example.com",
    exp_delta: timedelta = timedelta(minutes=10),
    client_id: str = "original-client",
) -> str:
    now = datetime.now(tz=UTC)
    payload: dict = {
        "iss": iss,
        "sub": sub,
        "iat": int(now.timestamp()),
        "exp": int((now + exp_delta).timestamp()),
        "scope": scope,
        "client_id": client_id,
    }
    if aud is not None:
        payload["aud"] = aud
    return jwt.encode(payload, private_pem, algorithm="RS256")


def _request(
    subject_token: str,
    *,
    requested_scope: str | None = None,
    audience: tuple[str, ...] = (),
    requested_token_type: str | None = None,
    subject_token_type: str = _ACCESS_TOKEN_TYPE,
) -> TokenRequest:
    return TokenRequest(
        grant_type=GrantType.TOKEN_EXCHANGE,
        scope=ScopeSet.parse(requested_scope),
        audience=audience,
        subject_token=subject_token,
        subject_token_type=subject_token_type,
        requested_token_type=requested_token_type,
    )


class TestTokenExchangeGrant:
    async def test_happy_path_downscope(self, keypair: tuple[bytes, bytes]) -> None:
        priv, _pub = keypair
        grant, issuer = _make_grant(keypair)
        subject_jwt = _sign_subject_token(priv, scope="read write")

        result = await grant.execute(_request(subject_jwt, requested_scope="read"), _make_client())

        assert result.token_type == "Bearer"
        assert result.issued_token_type == _ACCESS_TOKEN_TYPE
        assert result.scope is not None and result.scope.to_str() == "read"
        # Subject identity passes through
        assert issuer.calls[-1]["subject"] == _SUBJECT
        # The exchanger's client_id wins (RFC 8693 §4.1)
        assert issuer.calls[-1]["client_id"] == "demo-exchange"

    async def test_audience_switch(self, keypair: tuple[bytes, bytes]) -> None:
        priv, _pub = keypair
        grant, issuer = _make_grant(keypair)
        subject_jwt = _sign_subject_token(priv)

        await grant.execute(
            _request(
                subject_jwt,
                requested_scope="read",
                audience=("https://downstream.example.com",),
            ),
            _make_client(),
        )

        assert issuer.calls[-1]["audience"] == "https://downstream.example.com"

    async def test_no_requested_scope_defaults_to_intersection(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        priv, _pub = keypair
        grant, issuer = _make_grant(keypair)
        subject_jwt = _sign_subject_token(priv, scope="read")  # subject has only read

        await grant.execute(_request(subject_jwt), _make_client())

        assert issuer.calls[-1]["scope"].to_str() == "read"

    async def test_requesting_wider_scope_than_subject_clipped(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        # Subject token has only "read"; caller asks for "write".
        # Exchange MUST NOT widen — RFC 8693 spirit; the scope validator
        # rejects with InvalidScope (or another OAuthError if the policy
        # decides to reduce silently).
        priv, _pub = keypair
        grant, issuer = _make_grant(keypair)
        subject_jwt = _sign_subject_token(priv, scope="read")

        with pytest.raises((InvalidScope, OAuthError)):
            await grant.execute(_request(subject_jwt, requested_scope="write"), _make_client())

        assert issuer.calls == []  # nothing was issued

    async def test_missing_subject_token_raises_invalid_request(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        grant, _issuer = _make_grant(keypair)
        with pytest.raises(InvalidRequest):
            await grant.execute(
                TokenRequest(
                    grant_type=GrantType.TOKEN_EXCHANGE,
                    subject_token_type=_ACCESS_TOKEN_TYPE,
                ),
                _make_client(),
            )

    async def test_missing_subject_token_type_raises_invalid_request(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        grant, _issuer = _make_grant(keypair)
        with pytest.raises(InvalidRequest):
            await grant.execute(
                TokenRequest(
                    grant_type=GrantType.TOKEN_EXCHANGE,
                    subject_token="anything",
                ),
                _make_client(),
            )

    async def test_unsupported_subject_token_type_raises(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        grant, _issuer = _make_grant(keypair)
        with pytest.raises(InvalidRequest):
            await grant.execute(
                _request("ignored", subject_token_type=TokenTypeURI.SAML2.value),
                _make_client(),
            )

    async def test_unsupported_requested_token_type_raises(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        priv, _pub = keypair
        grant, _issuer = _make_grant(keypair)
        subject_jwt = _sign_subject_token(priv)
        with pytest.raises(InvalidRequest):
            await grant.execute(
                _request(
                    subject_jwt,
                    requested_token_type=TokenTypeURI.SAML2.value,
                ),
                _make_client(),
            )

    async def test_expired_subject_token_raises(self, keypair: tuple[bytes, bytes]) -> None:
        priv, _pub = keypair
        grant, _issuer = _make_grant(keypair)
        expired = _sign_subject_token(priv, exp_delta=timedelta(seconds=-30))
        with pytest.raises(InvalidGrant, match="expired"):
            await grant.execute(_request(expired), _make_client())

    async def test_subject_token_signed_by_wrong_key_raises(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        grant, _issuer = _make_grant(keypair)
        attacker_pem = generate_rsa_keypair_pem()
        token = _sign_subject_token(attacker_pem)
        with pytest.raises(InvalidGrant):
            await grant.execute(_request(token), _make_client())

    async def test_client_not_allowed_token_exchange_raises(
        self, keypair: tuple[bytes, bytes]
    ) -> None:
        priv, _pub = keypair
        grant, _issuer = _make_grant(keypair)
        client = _make_client(grants=frozenset({GrantType.CLIENT_CREDENTIALS}))
        with pytest.raises(UnauthorizedClient):
            await grant.execute(_request(_sign_subject_token(priv)), client)
