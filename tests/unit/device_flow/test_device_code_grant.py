"""DeviceCodeGrant strategy — the 5 polling outcomes per RFC 8628 §3.5.

Scenario: device flow. Pure-domain test with stubbed ports.

Location: `tests/unit/device_flow/` — folder carries the scenario.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from oauth_lab.adapter.outbound.persistence.memory.device_code_repository import (
    InMemoryDeviceCodeRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.refresh_token_repository import (
    InMemoryRefreshTokenRepository,
)
from oauth_lab.adapter.outbound.random.secure_random_source import SecureRandomSource
from oauth_lab.application.port.inbound.issue_token_use_case import (
    TokenIssuanceResult,
    TokenRequest,
)
from oauth_lab.application.port.outbound.token_issuer import IssuedToken
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.device_code_grant import DeviceCodeGrant
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.device_code import DeviceCode
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
from oauth_lab.domain.model.scope import Scope, ScopeSet

_NOW = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


class _FixedClock:
    def __init__(self, value: datetime) -> None:
        self._value = value

    def now(self) -> datetime:
        return self._value


class _StubTokenIssuer:
    async def issue(self, *, subject, client_id, scope, audience, ttl_seconds):
        return IssuedToken(value="stub-access-token", expires_in_seconds=ttl_seconds)


def _make_client(
    *,
    grants: frozenset[GrantType] = frozenset({GrantType.DEVICE_CODE, GrantType.REFRESH_TOKEN}),
) -> AuthenticatedClient:
    return AuthenticatedClient(
        client=Client(
            id=ClientId("demo-device"),
            secret_hash=None,
            token_endpoint_auth_method=ClientAuthMethod.NONE,
            allowed_grant_types=grants,
            allowed_scopes=ScopeSet(frozenset({Scope("read"), Scope("write")})),
            default_audience="https://api.example.com",
        ),
        auth_method=ClientAuthMethod.NONE,
    )


def _make_code(
    *,
    user_sub: str | None = None,
    denied: bool = False,
    expires_in: timedelta = timedelta(minutes=30),
    interval: int = 5,
    last_polled_at: datetime | None = None,
) -> DeviceCode:
    return DeviceCode(
        device_code="dev-code-123",
        user_code="BCDF-GHJK",
        client_id=ClientId("demo-device"),
        scope=ScopeSet(frozenset({Scope("read")})),
        issued_at=_NOW,
        expires_at=_NOW + expires_in,
        interval=interval,
        last_polled_at=last_polled_at,
        user_sub=user_sub,
        denied=denied,
    )


def _grant(*, clock_value: datetime = _NOW) -> tuple[
    DeviceCodeGrant, InMemoryDeviceCodeRepository
]:
    device_codes = InMemoryDeviceCodeRepository()
    refresh_tokens = InMemoryRefreshTokenRepository()
    return (
        DeviceCodeGrant(
            token_issuer=_StubTokenIssuer(),
            device_codes=device_codes,
            refresh_tokens=refresh_tokens,
            random_source=SecureRandomSource(),
            clock=_FixedClock(clock_value),
            access_token_ttl_seconds=3600,
            refresh_token_ttl_seconds=2592000,
        ),
        device_codes,
    )


def _request(device_code: str = "dev-code-123") -> TokenRequest:
    return TokenRequest(grant_type=GrantType.DEVICE_CODE, device_code=device_code)


class TestDeviceCodeGrantStateMachine:
    async def test_missing_device_code_raises_invalid_request(self) -> None:
        grant, _repo = _grant()
        with pytest.raises(InvalidRequest):
            await grant.execute(
                TokenRequest(grant_type=GrantType.DEVICE_CODE), _make_client()
            )

    async def test_unknown_device_code_raises_invalid_grant(self) -> None:
        grant, _repo = _grant()
        with pytest.raises(InvalidGrant, match="not found"):
            await grant.execute(_request("ghost"), _make_client())

    async def test_wrong_client_raises_invalid_grant(self) -> None:
        grant, repo = _grant()
        await repo.save(_make_code())
        other_client = AuthenticatedClient(
            client=Client(
                id=ClientId("OTHER-CLIENT"),
                secret_hash=None,
                token_endpoint_auth_method=ClientAuthMethod.NONE,
                allowed_grant_types=frozenset({GrantType.DEVICE_CODE}),
                allowed_scopes=ScopeSet(frozenset()),
            ),
            auth_method=ClientAuthMethod.NONE,
        )
        with pytest.raises(InvalidGrant, match="different client"):
            await grant.execute(_request(), other_client)

    async def test_client_not_allowed_device_code_raises(self) -> None:
        grant, repo = _grant()
        await repo.save(_make_code())
        client = _make_client(grants=frozenset({GrantType.CLIENT_CREDENTIALS}))
        with pytest.raises(UnauthorizedClient):
            await grant.execute(_request(), client)

    async def test_pending_raises_authorization_pending(self) -> None:
        grant, repo = _grant()
        await repo.save(_make_code())
        with pytest.raises(AuthorizationPending):
            await grant.execute(_request(), _make_client())

    async def test_polling_too_fast_raises_slow_down(self) -> None:
        # Last polled 1s ago; interval is 5s → must wait.
        grant, repo = _grant(clock_value=_NOW + timedelta(seconds=1))
        await repo.save(_make_code(last_polled_at=_NOW, interval=5))
        with pytest.raises(SlowDown):
            await grant.execute(_request(), _make_client())

    async def test_expired_raises_expired_token(self) -> None:
        grant, repo = _grant(clock_value=_NOW + timedelta(hours=1))
        await repo.save(_make_code(expires_in=timedelta(seconds=10)))
        with pytest.raises(ExpiredToken):
            await grant.execute(_request(), _make_client())

    async def test_denied_raises_access_denied(self) -> None:
        grant, repo = _grant()
        await repo.save(_make_code(denied=True))
        with pytest.raises(AccessDenied):
            await grant.execute(_request(), _make_client())

    async def test_approved_returns_access_token(self) -> None:
        grant, repo = _grant()
        await repo.save(_make_code(user_sub="user-alice"))
        result = await grant.execute(_request(), _make_client())
        assert result.access_token == "stub-access-token"
        assert result.token_type == "Bearer"
        assert result.refresh_token is not None                   # demo-device supports refresh

    async def test_approved_code_is_single_use(self) -> None:
        # First poll after approval succeeds; the second must fail —
        # a device code is single-use (token-amplification defence).
        grant, repo = _grant()
        await repo.save(_make_code(user_sub="user-alice"))

        first = await grant.execute(_request(), _make_client())
        assert first.access_token == "stub-access-token"

        with pytest.raises(InvalidGrant, match="already redeemed"):
            await grant.execute(_request(), _make_client())


class TestAtomicRedemption:
    async def test_second_redeem_returns_none(self) -> None:
        repo = InMemoryDeviceCodeRepository()
        await repo.save(_make_code(user_sub="user-alice"))

        first = await repo.redeem("dev-code-123", _NOW)
        assert first is not None
        assert first.is_redeemed()

        assert await repo.redeem("dev-code-123", _NOW) is None

    async def test_concurrent_polls_issue_tokens_exactly_once(self) -> None:
        # Two simultaneous polls of one approved code: the atomic
        # `redeem()` lets exactly one mint tokens; the loser gets
        # invalid_grant instead of a duplicate issuance.
        grant, repo = _grant()
        await repo.save(_make_code(user_sub="user-alice"))

        results = await asyncio.gather(
            grant.execute(_request(), _make_client()),
            grant.execute(_request(), _make_client()),
            return_exceptions=True,
        )

        issued = [r for r in results if isinstance(r, TokenIssuanceResult)]
        rejected = [r for r in results if isinstance(r, InvalidGrant)]
        assert len(issued) == 1
        assert len(rejected) == 1
        assert "already redeemed" in str(rejected[0])
