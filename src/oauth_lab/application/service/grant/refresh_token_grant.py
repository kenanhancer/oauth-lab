"""Refresh Token grant — RFC 6749 § 6 + RFC 9700 § 2.2.2 (rotation).

Each `/token grant_type=refresh_token` exchange:

1. Looks up the presented token.
2. Verifies it was issued to the authenticated client.
3. **Replay defence**: if the token has already been consumed, every
   token in its `family_id` chain is revoked and the request fails
   with `invalid_grant`.
4. Otherwise: atomically consumes the old token and issues a fresh
   refresh token in the same family alongside a new access token.
"""

from __future__ import annotations

from datetime import timedelta
from typing import ClassVar

from oauth_lab.application.port.inbound.issue_token_use_case import (
    TokenIssuanceResult,
    TokenRequest,
)
from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.random_source import RandomSource
from oauth_lab.application.port.outbound.refresh_token_repository import RefreshTokenRepository
from oauth_lab.application.port.outbound.token_issuer import TokenIssuer
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.grant_strategy import GrantStrategy
from oauth_lab.domain.model.errors import (
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    UnauthorizedClient,
)
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.refresh_token import RefreshToken


class RefreshTokenGrant(GrantStrategy):
    grant_type: ClassVar[GrantType] = GrantType.REFRESH_TOKEN

    def __init__(
        self,
        *,
        token_issuer: TokenIssuer,
        refresh_tokens: RefreshTokenRepository,
        random_source: RandomSource,
        clock: Clock,
        access_token_ttl_seconds: int,
        refresh_token_ttl_seconds: int,
    ) -> None:
        self._token_issuer = token_issuer
        self._refresh_tokens = refresh_tokens
        self._random = random_source
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

        if not request.refresh_token:
            raise InvalidRequest("'refresh_token' is required")

        token = await self._refresh_tokens.find_by_value(request.refresh_token)
        if token is None:
            raise InvalidGrant("refresh token not found")
        if token.client_id != client.id:
            raise InvalidGrant("refresh token was issued to a different client")

        now = self._clock.now()

        # Replay defence — RFC 9700 § 2.2.2.
        if token.is_consumed():
            await self._refresh_tokens.revoke_family(token.family_id, now)
            raise InvalidGrant("refresh token replay detected; the token chain has been revoked")

        if token.is_expired(now):
            raise InvalidGrant("refresh token has expired")

        # Scope narrowing — RFC 6749 § 6: a refresh request MAY include a
        # scope, but it MUST NOT exceed the scope originally granted.
        # Absent (or empty) scope reuses the token's scope unchanged.
        if not request.scope.is_empty():
            if not request.scope.is_subset_of(token.scope):
                raise InvalidScope("requested scope exceeds the originally granted scope")
            granted_scope = request.scope.intersect(token.scope)
        else:
            granted_scope = token.scope

        # Mint replacement before the atomic rotation — same family.
        new_token = RefreshToken(
            value=self._random.token_urlsafe(32),
            family_id=token.family_id,
            client_id=token.client_id,
            user_sub=token.user_sub,
            scope=granted_scope,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._refresh_ttl),
        )
        await self._refresh_tokens.rotate(
            old_value=token.value,
            new_token=new_token,
            now=now,
        )

        issued_access = await self._token_issuer.issue(
            subject=token.user_sub,
            client_id=str(client.id),
            scope=granted_scope,
            audience=client.default_audience,
            ttl_seconds=self._access_ttl,
        )

        return TokenIssuanceResult(
            access_token=issued_access.value,
            token_type="Bearer",  # noqa: S106
            expires_in=issued_access.expires_in_seconds,
            scope=granted_scope,
            refresh_token=new_token.value,
        )
