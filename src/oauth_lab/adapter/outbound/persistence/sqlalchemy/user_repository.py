"""Shared SQLAlchemy `UserRepository` for SQLite + Postgres."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from oauth_lab.adapter.outbound.persistence.orm.models import UserRow
from oauth_lab.domain.model.user import User


class SqlAlchemyUserRepository:
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def find_by_sub(self, sub: str) -> User | None:
        async with self._session_factory() as session:
            row = await session.scalar(select(UserRow).where(UserRow.sub == sub))
            return None if row is None else _to_domain(row)

    async def find_by_username(self, username: str) -> User | None:
        async with self._session_factory() as session:
            row = await session.scalar(select(UserRow).where(UserRow.username == username))
            return None if row is None else _to_domain(row)

    async def save(self, user: User) -> None:
        async with self._session_factory() as session:
            existing = await session.get(UserRow, user.sub)
            if existing is None:
                session.add(_to_row(user))
            else:
                existing.username = user.username
                existing.password_hash = user.password_hash
                existing.email = user.email
            await session.commit()


def _to_domain(row: UserRow) -> User:
    return User(sub=row.sub, username=row.username, password_hash=row.password_hash, email=row.email)


def _to_row(user: User) -> UserRow:
    return UserRow(
        sub=user.sub, username=user.username, password_hash=user.password_hash, email=user.email
    )
