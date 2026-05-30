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
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidGrant
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
        assert t.consumed_at is None                                     # immutable

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

        assert (await repo.find_by_value("a")).is_consumed()             # type: ignore[union-attr]
        assert (await repo.find_by_value("b")).is_consumed()             # type: ignore[union-attr]
        assert (await repo.find_by_value("c")).is_consumed() is False    # type: ignore[union-attr]
