"""Device Code grant — RFC 8628 § 3.4 + 3.5.

Polling responses (RFC 8628 § 3.5):

| State                   | Response               |
|-------------------------|------------------------|
| User hasn't approved    | `authorization_pending`|
| Polled too fast         | `slow_down`            |
| TTL elapsed             | `expired_token`        |
| User denied             | `access_denied`        |
| Approved                | 200 + access_token     |

On a 200 we also mint a refresh token if the client is allowed
`refresh_token` (same pattern as `authorization_code`).
"""

from __future__ import annotations

from datetime import timedelta
from typing import ClassVar

from oauth_lab.application.port.inbound.issue_token_use_case import (
    TokenIssuanceResult,
    TokenRequest,
)
from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.device_code_repository import DeviceCodeRepository
from oauth_lab.application.port.outbound.random_source import RandomSource
from oauth_lab.application.port.outbound.refresh_token_repository import RefreshTokenRepository
from oauth_lab.application.port.outbound.token_issuer import TokenIssuer
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.grant_strategy import GrantStrategy
from oauth_lab.domain.model.errors import (
    AccessDenied,
    AuthorizationPending,
    ExpiredToken,
    InvalidGrant,
    InvalidRequest,
    SlowDown,
    UnauthorizedClient,
)
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.refresh_token import RefreshToken


class DeviceCodeGrant(GrantStrategy):
    grant_type: ClassVar[GrantType] = GrantType.DEVICE_CODE

    def __init__(
        self,
        *,
        token_issuer: TokenIssuer,
        device_codes: DeviceCodeRepository,
        refresh_tokens: RefreshTokenRepository,
        random_source: RandomSource,
        clock: Clock,
        access_token_ttl_seconds: int,
        refresh_token_ttl_seconds: int,
    ) -> None:
        self._token_issuer = token_issuer
        self._device_codes = device_codes
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

        if not request.device_code:
            raise InvalidRequest("'device_code' is required")

        code = await self._device_codes.find_by_device_code(request.device_code)
        if code is None:
            raise InvalidGrant("device code not found")
        if code.client_id != client.id:
            raise InvalidGrant("device code was issued to a different client")

        now = self._clock.now()

        # Hard terminal states first (regardless of polling cadence).
        if code.is_expired(now):
            raise ExpiredToken("device code has expired")
        if code.is_denied():
            raise AccessDenied("user denied the authorization request")

        # Polling-interval enforcement (RFC 8628 § 3.5).
        if not code.can_poll_at(now):
            await self._device_codes.save(code.mark_polled(now))
            raise SlowDown("polling faster than the AS-mandated interval")

        # Pending — record the poll and tell the device to wait.
        if code.is_pending():
            await self._device_codes.save(code.mark_polled(now))
            raise AuthorizationPending("user has not yet approved")

        # Approved — issue tokens exactly once. A device code is a bearer
        # grant: replaying it after a successful exchange would amplify
        # one user approval into unlimited token issuance, so we enforce
        # single-use (same intent as RFC 6749 § 4.1.2 for authz codes).
        # `redeem()` is the atomic check-and-set: of N concurrent polls
        # exactly one gets the entity back, the rest get None. Marking
        # BEFORE minting means a crash here loses one issuance but can
        # never double-issue — the fail-safe direction.
        redeemed = await self._device_codes.redeem(request.device_code, now)
        if redeemed is None:
            raise InvalidGrant("device code already redeemed")
        assert redeemed.user_sub is not None                     # redeemable ⇒ approved

        issued_access = await self._token_issuer.issue(
            subject=redeemed.user_sub,
            client_id=str(client.id),
            scope=redeemed.scope,
            audience=client.default_audience,
            ttl_seconds=self._access_ttl,
        )

        refresh_token_value: str | None = None
        if client.supports_grant(GrantType.REFRESH_TOKEN):
            refresh = RefreshToken(
                value=self._random.token_urlsafe(32),
                family_id=self._random.token_urlsafe(16),
                client_id=client.id,
                user_sub=redeemed.user_sub,
                scope=redeemed.scope,
                issued_at=now,
                expires_at=now + timedelta(seconds=self._refresh_ttl),
            )
            await self._refresh_tokens.save(refresh)
            refresh_token_value = refresh.value

        return TokenIssuanceResult(
            access_token=issued_access.value,
            token_type="Bearer",                                                                # noqa: S106
            expires_in=issued_access.expires_in_seconds,
            scope=redeemed.scope,
            refresh_token=refresh_token_value,
        )
