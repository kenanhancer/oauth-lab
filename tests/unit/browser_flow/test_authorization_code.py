"""AuthorizationCode entity + in-memory repository — single-use enforcement.

The replay-detection contract is the critical security property: a code
must be redeemable exactly once. Two concurrent `/token` requests with
the same code must not both succeed.

Location: `tests/unit/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from oauth_lab.adapter.outbound.persistence.memory.authorization_code_repository import (
    InMemoryAuthorizationCodeRepository,
)
from oauth_lab.domain.model.authorization_code import AuthorizationCode
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidGrant
from oauth_lab.domain.model.pkce import PKCEChallenge
from oauth_lab.domain.model.scope import Scope, ScopeSet

_NOW = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(seconds=120)
_BEFORE_EXPIRY = _NOW + timedelta(seconds=30)
_AFTER_EXPIRY = _NOW + timedelta(seconds=90)


def _make_code(value: str = "test-code", consumed_at: datetime | None = None) -> AuthorizationCode:
    return AuthorizationCode(
        value=value,
        client_id=ClientId("demo-spa"),
        user_sub="user-123",
        redirect_uri="http://localhost:8080/callback",
        scope=ScopeSet(frozenset({Scope("read")})),
        pkce_challenge=PKCEChallenge(value="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(seconds=60),
        consumed_at=consumed_at,
    )


class TestAuthorizationCodeEntity:
    def test_consume_returns_new_instance_with_consumed_at_set(self) -> None:
        code = _make_code()
        consumed = code.consume(_BEFORE_EXPIRY)
        assert consumed.consumed_at == _BEFORE_EXPIRY
        assert code.consumed_at is None  # immutable: original untouched

    def test_consume_twice_raises_replay(self) -> None:
        consumed = _make_code(consumed_at=_BEFORE_EXPIRY)
        with pytest.raises(InvalidGrant, match="already been used"):
            consumed.consume(_BEFORE_EXPIRY)

    def test_consume_after_expiry_raises(self) -> None:
        code = _make_code()
        with pytest.raises(InvalidGrant, match="expired"):
            code.consume(_AFTER_EXPIRY)

    def test_is_expired(self) -> None:
        code = _make_code()
        assert code.is_expired(_AFTER_EXPIRY) is True
        assert code.is_expired(_BEFORE_EXPIRY) is False

    def test_is_consumed(self) -> None:
        assert _make_code().is_consumed() is False
        assert _make_code(consumed_at=_BEFORE_EXPIRY).is_consumed() is True


class TestInMemoryAuthorizationCodeRepository:
    async def test_save_and_find(self) -> None:
        repo = InMemoryAuthorizationCodeRepository()
        code = _make_code()
        await repo.save(code)
        loaded = await repo.find_by_value(code.value)
        assert loaded == code

    async def test_consume_happy_path(self) -> None:
        repo = InMemoryAuthorizationCodeRepository()
        code = _make_code()
        await repo.save(code)
        consumed = await repo.consume(code.value, _BEFORE_EXPIRY)
        assert consumed.consumed_at == _BEFORE_EXPIRY

    async def test_consume_twice_raises_replay(self) -> None:
        repo = InMemoryAuthorizationCodeRepository()
        code = _make_code()
        await repo.save(code)
        await repo.consume(code.value, _BEFORE_EXPIRY)
        with pytest.raises(InvalidGrant, match="already been used"):
            await repo.consume(code.value, _BEFORE_EXPIRY)

    async def test_consume_missing_code_raises(self) -> None:
        repo = InMemoryAuthorizationCodeRepository()
        with pytest.raises(InvalidGrant, match="not found"):
            await repo.consume("does-not-exist", _BEFORE_EXPIRY)

    async def test_consume_expired_raises(self) -> None:
        repo = InMemoryAuthorizationCodeRepository()
        code = _make_code()
        await repo.save(code)
        with pytest.raises(InvalidGrant, match="expired"):
            await repo.consume(code.value, _AFTER_EXPIRY)
