"""Shared SQLAlchemy `RefreshTokenRepository` for SQLite + Postgres.

`rotate()` and `revoke_family()` use conditional UPDATEs (atomic at the
SQL level) — no transaction lock needed for correctness against
concurrent rotations.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from oauth_lab.adapter.outbound.persistence.orm.models import RefreshTokenRow
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidGrant
from oauth_lab.domain.model.refresh_token import RefreshToken
from oauth_lab.domain.model.scope import Scope, ScopeSet


class SqlAlchemyRefreshTokenRepository:
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def save(self, token: RefreshToken) -> None:
        async with self._session_factory() as session:
            session.add(_to_row(token))
            await session.commit()

    async def find_by_value(self, value: str) -> RefreshToken | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(RefreshTokenRow).where(RefreshTokenRow.value == value)
            )
            return None if row is None else _to_domain(row)

    async def rotate(
        self,
        *,
        old_value: str,
        new_token: RefreshToken,
        now: datetime,
    ) -> RefreshToken:
        async with self._session_factory() as session:
            stmt = (
                update(RefreshTokenRow)
                .where(
                    RefreshTokenRow.value == old_value,
                    RefreshTokenRow.consumed_at.is_(None),
                    RefreshTokenRow.expires_at > now,
                )
                .values(consumed_at=now)
            )
            result = await session.execute(stmt)
            if result.rowcount == 0:
                old = await session.scalar(
                    select(RefreshTokenRow).where(RefreshTokenRow.value == old_value)
                )
                if old is None:
                    raise InvalidGrant("refresh token not found")
                if old.consumed_at is not None:
                    raise InvalidGrant("refresh token has already been used")
                raise InvalidGrant("refresh token has expired")

            session.add(_to_row(new_token))
            await session.commit()
            return new_token

    async def revoke_family(self, family_id: str, now: datetime) -> int:
        async with self._session_factory() as session:
            stmt = (
                update(RefreshTokenRow)
                .where(
                    RefreshTokenRow.family_id == family_id,
                    RefreshTokenRow.consumed_at.is_(None),
                )
                .values(consumed_at=now)
            )
            result = await session.execute(stmt)
            await session.commit()
            return result.rowcount


def _to_domain(row: RefreshTokenRow) -> RefreshToken:
    return RefreshToken(
        value=row.value,
        family_id=row.family_id,
        client_id=ClientId(row.client_id),
        user_sub=row.user_sub,
        scope=ScopeSet(frozenset(Scope(s) for s in row.scope.split() if s)),
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        consumed_at=row.consumed_at,
    )


def _to_row(token: RefreshToken) -> RefreshTokenRow:
    return RefreshTokenRow(
        value=token.value,
        family_id=token.family_id,
        client_id=token.client_id.value,
        user_sub=token.user_sub,
        scope=" ".join(sorted(s.value for s in token.scope.scopes)),
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        consumed_at=token.consumed_at,
    )
