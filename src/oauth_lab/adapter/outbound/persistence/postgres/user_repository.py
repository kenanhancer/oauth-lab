"""Postgres `UserRepository` — thin wrapper."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oauth_lab.adapter.outbound.persistence.sqlalchemy.user_repository import (
    SqlAlchemyUserRepository,
)


class PostgresUserRepository(SqlAlchemyUserRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        super().__init__(session_factory)
