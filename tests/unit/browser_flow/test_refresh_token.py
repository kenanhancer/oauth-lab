"""RefreshToken entity + in-memory repository — rotation + replay defence.

Replay defence is the security-critical contract: the second time a
refresh token is presented, the entire `family_id` chain is revoked
(RFC 9700 § 2.2.2).

Location: `tests/unit/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from oauth_lab.adapter.outbound.persistence.memory.refresh_token_repository import (
    InMemoryRefreshTokenRepository,
)
from oauth_lab.adapter.outbound.random.secure_random_source import SecureRandomSource
from oauth_lab.application.port.inbound.issue_token_use_case import TokenRequest
from oauth_lab.application.port.outbound.token_issuer import IssuedToken
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.refresh_token_grant import RefreshTokenGrant
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidGrant, InvalidScope
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.refresh_token import RefreshToken
from oauth_lab.domain.model.scope import Scope, ScopeSet

_NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)
_NEXT_USE = _NOW + timedelta(minutes=5)


def _make_token(
    value: str = "token-1",
    *,
    family_id: str = "family-A",
    consumed_at: datetime | None = None,
    expires_in: timedelta = timedelta(days=30),
) -> RefreshToken:
    return RefreshToken(
        value=value,
        family_id=family_id,
        client_id=ClientId("demo-spa"),
        user_sub="user-alice",
        scope=ScopeSet(frozenset({Scope("read")})),
        issued_at=_NOW,
        expires_at=_NOW + expires_in,
        consumed_at=consumed_at,
    )


class TestRefreshTokenEntity:
    def test_consume_returns_new_instance(self) -> None:
        t = _make_token()
        consumed = t.consume(_NEXT_USE)
        assert consumed.consumed_at == _NEXT_USE
        assert t.consumed_at is None  # immutable

    def test_is_expired(self) -> None:
        t = _make_token(expires_in=timedelta(minutes=1))
        assert t.is_expired(_NEXT_USE) is True
        assert t.is_expired(_NOW) is False

    def test_is_consumed(self) -> None:
        assert _make_token().is_consumed() is False
        assert _make_token(consumed_at=_NEXT_USE).is_consumed() is True


class TestInMemoryRefreshTokenRepository:
    async def test_save_and_find(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        t = _make_token()
        await repo.save(t)
        assert await repo.find_by_value(t.value) == t

    async def test_rotate_happy_path(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        old = _make_token("old-token")
        await repo.save(old)

        new = _make_token("new-token")
        result = await repo.rotate(old_value=old.value, new_token=new, now=_NEXT_USE)
        assert result == new

        # Old marked consumed
        old_after = await repo.find_by_value(old.value)
        assert old_after is not None
        assert old_after.is_consumed()

        # New saved
        assert await repo.find_by_value(new.value) == new

    async def test_rotate_replay_raises(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        old = _make_token("old", consumed_at=_NOW)
        await repo.save(old)
        with pytest.raises(InvalidGrant, match="already been used"):
            await repo.rotate(old_value=old.value, new_token=_make_token("new"), now=_NEXT_USE)

    async def test_rotate_missing_raises(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        with pytest.raises(InvalidGrant, match="not found"):
            await repo.rotate(old_value="ghost", new_token=_make_token("new"), now=_NEXT_USE)

    async def test_rotate_expired_raises(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        old = _make_token("old", expires_in=timedelta(seconds=1))
        await repo.save(old)
        future = _NOW + timedelta(minutes=1)
        with pytest.raises(InvalidGrant, match="expired"):
            await repo.rotate(old_value=old.value, new_token=_make_token("new"), now=future)

    async def test_revoke_family(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        a = _make_token("a", family_id="F")
        b = _make_token("b", family_id="F")
        unrelated = _make_token("c", family_id="OTHER")
        await repo.save(a)
        await repo.save(b)
        await repo.save(unrelated)

        revoked = await repo.revoke_family("F", _NEXT_USE)
        assert revoked == 2

        assert (await repo.find_by_value("a")).is_consumed()  # type: ignore[union-attr]
        assert (await repo.find_by_value("b")).is_consumed()  # type: ignore[union-attr]
        assert (await repo.find_by_value("c")).is_consumed() is False  # type: ignore[union-attr]


class _FixedClock:
    def __init__(self, value: datetime) -> None:
        self._value = value

    def now(self) -> datetime:
        return self._value


class _StubTokenIssuer:
    async def issue(self, *, subject, client_id, scope, audience, ttl_seconds):
        return IssuedToken(value="stub-access-token", expires_in_seconds=ttl_seconds)


def _make_client() -> AuthenticatedClient:
    return AuthenticatedClient(
        client=Client(
            id=ClientId("demo-spa"),
            secret_hash=None,
            token_endpoint_auth_method=ClientAuthMethod.NONE,
            allowed_grant_types=frozenset({GrantType.REFRESH_TOKEN}),
            allowed_scopes=ScopeSet(frozenset({Scope("read"), Scope("write")})),
        ),
        auth_method=ClientAuthMethod.NONE,
    )


def _narrowing_grant(
    repo: InMemoryRefreshTokenRepository,
) -> RefreshTokenGrant:
    return RefreshTokenGrant(
        token_issuer=_StubTokenIssuer(),
        refresh_tokens=repo,
        random_source=SecureRandomSource(),
        clock=_FixedClock(_NOW),
        access_token_ttl_seconds=3600,
        refresh_token_ttl_seconds=2592000,
    )


class TestRefreshTokenScopeNarrowing:
    """RFC 6749 § 6 — a refresh request may narrow scope but never widen it."""

    async def _seed(self, repo: InMemoryRefreshTokenRepository) -> RefreshToken:
        token = RefreshToken(
            value="rt-original",
            family_id="family-A",
            client_id=ClientId("demo-spa"),
            user_sub="user-alice",
            scope=ScopeSet(frozenset({Scope("read"), Scope("write")})),
            issued_at=_NOW,
            expires_at=_NOW + timedelta(days=30),
        )
        await repo.save(token)
        return token

    async def test_empty_scope_reuses_original(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        await self._seed(repo)
        grant = _narrowing_grant(repo)

        result = await grant.execute(
            TokenRequest(grant_type=GrantType.REFRESH_TOKEN, refresh_token="rt-original"),
            _make_client(),
        )
        assert result.scope == ScopeSet(frozenset({Scope("read"), Scope("write")}))

    async def test_subset_scope_narrows(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        await self._seed(repo)
        grant = _narrowing_grant(repo)

        result = await grant.execute(
            TokenRequest(
                grant_type=GrantType.REFRESH_TOKEN,
                refresh_token="rt-original",
                scope=ScopeSet(frozenset({Scope("read")})),
            ),
            _make_client(),
        )
        assert result.scope == ScopeSet(frozenset({Scope("read")}))
        # The new refresh token carries the narrowed scope too.
        new_rt = await repo.find_by_value(result.refresh_token)  # type: ignore[arg-type]
        assert new_rt is not None
        assert new_rt.scope == ScopeSet(frozenset({Scope("read")}))

    async def test_widening_scope_rejected(self) -> None:
        repo = InMemoryRefreshTokenRepository()
        await self._seed(repo)
        grant = _narrowing_grant(repo)

        with pytest.raises(InvalidScope, match="exceeds"):
            await grant.execute(
                TokenRequest(
                    grant_type=GrantType.REFRESH_TOKEN,
                    refresh_token="rt-original",
                    scope=ScopeSet(frozenset({Scope("read"), Scope("admin")})),
                ),
                _make_client(),
            )
