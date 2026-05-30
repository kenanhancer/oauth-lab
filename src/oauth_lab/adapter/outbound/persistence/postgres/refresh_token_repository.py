"""Postgres `RefreshTokenRepository` — thin wrapper."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import async_sessionmaker

from oauth_lab.adapter.outbound.persistence.sqlalchemy.refresh_token_repository import (
    SqlAlchemyRefreshTokenRepository,
)


class PostgresRefreshTokenRepository(SqlAlchemyRefreshTokenRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        super().__init__(session_factory)
