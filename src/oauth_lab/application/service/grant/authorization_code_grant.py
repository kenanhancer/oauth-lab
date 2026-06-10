"""Authorization Code grant — RFC 6749 § 4.1.3 + RFC 7636 (PKCE).

Exchanges an authorization code (obtained from `/authorize`) for tokens.
Verifies:

1. The grant_type is allowed for this client.
2. The code exists, is not expired, has not been used (atomic — replay
   protection is enforced by `AuthorizationCodeRepository.consume()`).
3. The code was issued to *this* client.
4. The `redirect_uri` (when present at /token) matches the URI bound at
   `/authorize`. OAuth 2.1 § 10.2 makes it optional, but if provided it
   MUST match.
5. PKCE: `BASE64URL(SHA256(verifier))` matches the bound challenge.

If the client supports `refresh_token` grant, a fresh refresh token is
issued alongside the access token (new rotation family).
"""

from __future__ import annotations

from datetime import timedelta
from typing import ClassVar

from oauth_lab.application.port.inbound.issue_token_use_case import (
    TokenIssuanceResult,
    TokenRequest,
)
from oauth_lab.application.port.outbound.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.id_token_issuer import IdTokenIssuer
from oauth_lab.application.port.outbound.random_source import RandomSource
from oauth_lab.application.port.outbound.refresh_token_repository import RefreshTokenRepository
from oauth_lab.application.port.outbound.token_issuer import TokenIssuer
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.grant_strategy import GrantStrategy
from oauth_lab.domain.model.errors import InvalidGrant, InvalidRequest, UnauthorizedClient
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.refresh_token import RefreshToken
from oauth_lab.domain.model.scope import Scope
from oauth_lab.domain.service.pkce_verifier import PKCEVerifier

_OPENID = Scope("openid")


class AuthorizationCodeGrant(GrantStrategy):
    grant_type: ClassVar[GrantType] = GrantType.AUTHORIZATION_CODE

    def __init__(
        self,
        *,
        token_issuer: TokenIssuer,
        id_token_issuer: IdTokenIssuer,
        auth_codes: AuthorizationCodeRepository,
        refresh_tokens: RefreshTokenRepository,
        random_source: RandomSource,
        pkce_verifier: PKCEVerifier,
        clock: Clock,
        access_token_ttl_seconds: int,
        refresh_token_ttl_seconds: int,
    ) -> None:
        self._token_issuer = token_issuer
        self._id_token_issuer = id_token_issuer
        self._auth_codes = auth_codes
        self._refresh_tokens = refresh_tokens
        self._random = random_source
        self._pkce_verifier = pkce_verifier
        self._clock = clock
        self._access_ttl = access_token_ttl_seconds
        self._refresh_ttl = refresh_token_ttl_seconds

    async def execute(
        self,
        request: TokenRequest,
        client: AuthenticatedClient,
    ) -> TokenIssuanceResult:
        if not client.supports_grant(self.grant_type):
            raise UnauthorizedClient(
                f"client is not allowed to use grant_type={self.grant_type.value}"
            )

        if not request.code:
            raise InvalidRequest("'code' is required for grant_type=authorization_code")
        if not request.code_verifier:
            raise InvalidRequest(
                "'code_verifier' is required for grant_type=authorization_code (PKCE mandatory)"
            )

        code = await self._auth_codes.consume(request.code, self._clock.now())

        if code.client_id != client.id:
            raise InvalidGrant("authorization code was issued to a different client")

        if request.redirect_uri is not None and code.redirect_uri != request.redirect_uri:
            raise InvalidGrant("redirect_uri does not match the value used at /authorize")

        if not self._pkce_verifier.verify(request.code_verifier, code.pkce_challenge):
            raise InvalidGrant("PKCE verification failed (code_verifier does not match)")

        now = self._clock.now()

        issued_access = await self._token_issuer.issue(
            subject=code.user_sub,
            client_id=str(client.id),
            scope=code.scope,
            audience=client.default_audience,
            ttl_seconds=self._access_ttl,
        )

        # Issue a refresh token if the client is configured for it.
        refresh_token_value: str | None = None
        if client.supports_grant(GrantType.REFRESH_TOKEN):
            refresh = RefreshToken(
                value=self._random.token_urlsafe(32),
                family_id=self._random.token_urlsafe(16),  # new chain
                client_id=client.id,
                user_sub=code.user_sub,
                scope=code.scope,
                issued_at=now,
                expires_at=now + timedelta(seconds=self._refresh_ttl),
            )
            await self._refresh_tokens.save(refresh)
            refresh_token_value = refresh.value

        # Issue an OIDC id_token if `openid` was in the granted scope.
        id_token_value: str | None = None
        if _OPENID in code.scope.scopes:
            id_token_value = await self._id_token_issuer.issue(
                subject=code.user_sub,
                audience=str(client.id),
                access_token=issued_access.value,
                nonce=code.nonce,
                auth_time=code.issued_at,
            )

        return TokenIssuanceResult(
            access_token=issued_access.value,
            token_type="Bearer",  # noqa: S106 — RFC 6749 §7.1 token type, not a credential
            expires_in=issued_access.expires_in_seconds,
            scope=code.scope,
            refresh_token=refresh_token_value,
            id_token=id_token_value,
        )
