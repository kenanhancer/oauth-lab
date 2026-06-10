"""Machine-to-machine (M2M) grant — pure-domain test of `ClientCredentialsGrant`.

Scenario: `client_credentials` per RFC 6749 §4.4. Actors: client app ↔ AS,
no user, no browser. This file tests the grant strategy in isolation —
stubbed `TokenIssuer`, real `ScopeValidator`, no HTTP, no DB.

Location: `tests/unit/m2m_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

import pytest

from oauth_lab.application.port.inbound.issue_token_use_case import TokenRequest
from oauth_lab.application.port.outbound.token_issuer import IssuedToken
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.client_credentials_grant import ClientCredentialsGrant
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidScope, UnauthorizedClient
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import Scope, ScopeSet
from oauth_lab.domain.service.scope_validator import ScopeValidator

# Module-level constants for `_make_client` defaults (Ruff B008: no function
# calls in argument defaults).
_DEFAULT_ALLOWED_SCOPES = ScopeSet(frozenset({Scope("read"), Scope("write")}))
_DEFAULT_ALLOWED_GRANTS = frozenset({GrantType.CLIENT_CREDENTIALS})


class StubTokenIssuer:
    def __init__(self, value: str = "stub-access-token") -> None:
        self._value = value
        self.last_call: dict[str, object] = {}

    async def issue(
        self,
        *,
        subject: str,
        client_id: str,
        scope: ScopeSet,
        audience: str | None,
        ttl_seconds: int,
    ) -> IssuedToken:
        self.last_call = {
            "subject": subject,
            "client_id": client_id,
            "scope": scope,
            "audience": audience,
            "ttl_seconds": ttl_seconds,
        }
        return IssuedToken(value=self._value, expires_in_seconds=ttl_seconds)


def _make_client(
    *,
    allowed_scopes: ScopeSet = _DEFAULT_ALLOWED_SCOPES,
    allowed_grants: frozenset[GrantType] = _DEFAULT_ALLOWED_GRANTS,
    default_audience: str | None = "https://api.example.com",
) -> AuthenticatedClient:
    return AuthenticatedClient(
        client=Client(
            id=ClientId("demo"),
            secret_hash=b"$argon2id$stub",
            token_endpoint_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
            allowed_grant_types=allowed_grants,
            allowed_scopes=allowed_scopes,
            default_audience=default_audience,
        ),
        auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
    )


def _make_grant(issuer: StubTokenIssuer, ttl: int = 3600) -> ClientCredentialsGrant:
    return ClientCredentialsGrant(
        token_issuer=issuer,
        scope_validator=ScopeValidator(),
        access_token_ttl_seconds=ttl,
    )


class TestClientCredentialsGrant:
    async def test_happy_path(self) -> None:
        issuer = StubTokenIssuer()
        grant = _make_grant(issuer)
        request = TokenRequest(
            grant_type=GrantType.CLIENT_CREDENTIALS,
            scope=ScopeSet.parse("read"),
        )

        result = await grant.execute(request, _make_client())

        assert result.access_token == "stub-access-token"
        assert result.token_type == "Bearer"
        assert result.expires_in == 3600
        assert result.scope is not None
        assert result.scope.to_str() == "read"
        assert issuer.last_call["audience"] == "https://api.example.com"

    async def test_empty_scope_falls_back_to_allowed(self) -> None:
        issuer = StubTokenIssuer()
        result = await _make_grant(issuer).execute(
            TokenRequest(grant_type=GrantType.CLIENT_CREDENTIALS),
            _make_client(),
        )
        assert result.scope is not None
        assert result.scope.to_str() == "read write"

    async def test_unauthorized_scope_raises(self) -> None:
        grant = _make_grant(StubTokenIssuer())
        with pytest.raises(InvalidScope, match="admin"):
            await grant.execute(
                TokenRequest(
                    grant_type=GrantType.CLIENT_CREDENTIALS,
                    scope=ScopeSet.parse("read admin"),
                ),
                _make_client(),
            )

    async def test_grant_not_allowed_for_client(self) -> None:
        grant = _make_grant(StubTokenIssuer())
        client = _make_client(allowed_grants=frozenset({GrantType.REFRESH_TOKEN}))
        with pytest.raises(UnauthorizedClient):
            await grant.execute(
                TokenRequest(grant_type=GrantType.CLIENT_CREDENTIALS),
                client,
            )

    async def test_request_audience_overrides_default(self) -> None:
        issuer = StubTokenIssuer()
        await _make_grant(issuer).execute(
            TokenRequest(
                grant_type=GrantType.CLIENT_CREDENTIALS,
                audience=("https://other.example.com",),
            ),
            _make_client(),
        )
        assert issuer.last_call["audience"] == "https://other.example.com"
