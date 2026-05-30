"""Shared SQLAlchemy `DeviceCodeRepository` (sqlite + postgres)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oauth_lab.adapter.outbound.persistence.orm.models import DeviceCodeRow
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.device_code import DeviceCode
from oauth_lab.domain.model.scope import Scope, ScopeSet


class SqlAlchemyDeviceCodeRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, code: DeviceCode) -> None:
        async with self._session_factory() as session:
            existing = await session.get(DeviceCodeRow, code.device_code)
            if existing is None:
                session.add(_to_row(code))
            else:
                _update_row(existing, code)
            await session.commit()

    async def find_by_device_code(self, device_code: str) -> DeviceCode | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(DeviceCodeRow).where(DeviceCodeRow.device_code == device_code)
            )
            return None if row is None else _to_domain(row)

    async def find_by_user_code(self, user_code: str) -> DeviceCode | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(DeviceCodeRow).where(DeviceCodeRow.user_code == user_code)
            )
            return None if row is None else _to_domain(row)


def _to_domain(row: DeviceCodeRow) -> DeviceCode:
    return DeviceCode(
        device_code=row.device_code,
        user_code=row.user_code,
        client_id=ClientId(row.client_id),
        scope=ScopeSet(frozenset(Scope(s) for s in row.scope.split() if s)),
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        interval=row.interval_seconds,
        last_polled_at=row.last_polled_at,
        user_sub=row.user_sub,
        denied=row.denied,
        redeemed_at=row.redeemed_at,
    )


def _to_row(code: DeviceCode) -> DeviceCodeRow:
    return DeviceCodeRow(
        device_code=code.device_code,
        user_code=code.user_code,
        client_id=code.client_id.value,
        scope=" ".join(sorted(s.value for s in code.scope.scopes)),
        issued_at=code.issued_at,
        expires_at=code.expires_at,
        interval_seconds=code.interval,
        last_polled_at=code.last_polled_at,
        user_sub=code.user_sub,
        denied=code.denied,
        redeemed_at=code.redeemed_at,
    )


def _update_row(row: DeviceCodeRow, code: DeviceCode) -> None:
    row.user_code = code.user_code
    row.client_id = code.client_id.value
    row.scope = " ".join(sorted(s.value for s in code.scope.scopes))
    row.issued_at = code.issued_at
    row.expires_at = code.expires_at
    row.interval_seconds = code.interval
    row.last_polled_at = code.last_polled_at
    row.user_sub = code.user_sub
    row.denied = code.denied
    row.redeemed_at = code.redeemed_at
