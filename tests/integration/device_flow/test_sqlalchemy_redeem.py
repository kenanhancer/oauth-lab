"""SQLAlchemy `DeviceCodeRepository.redeem` — conditional UPDATE wins once.

Scenario: device flow. Exercises the shared SQLAlchemy adapter against an
in-memory SQLite database (`sqlite+aiosqlite:///:memory:`) — no HTTP.

Location: `tests/integration/device_flow/` — folder carries the scenario.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from oauth_lab.adapter.outbound.persistence.orm.models import Base
from oauth_lab.adapter.outbound.persistence.sqlalchemy.device_code_repository import (
    SqlAlchemyDeviceCodeRepository,
)
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.device_code import DeviceCode
from oauth_lab.domain.model.scope import Scope, ScopeSet

_NOW = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
async def repo() -> AsyncIterator[SqlAlchemyDeviceCodeRepository]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield SqlAlchemyDeviceCodeRepository(async_sessionmaker(engine, expire_on_commit=False))
    await engine.dispose()


async def test_redeem_is_single_use(repo: SqlAlchemyDeviceCodeRepository) -> None:
    approved = DeviceCode(
        device_code="dev-code-123",
        user_code="BCDF-GHJK",
        client_id=ClientId("demo-device"),
        scope=ScopeSet(frozenset({Scope("read")})),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(minutes=30),
        interval=5,
        user_sub="user-alice",  # approved, unredeemed
    )
    await repo.save(approved)

    first = await repo.redeem("dev-code-123", _NOW)
    assert first is not None
    assert first.is_redeemed()
    assert first.user_sub == "user-alice"

    second = await repo.redeem("dev-code-123", _NOW)
    assert second is None
