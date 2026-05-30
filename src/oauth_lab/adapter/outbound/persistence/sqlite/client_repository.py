"""SQLite `ClientRepository` adapter — thin wrapper over the shared
SQLAlchemy implementation."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oauth_lab.adapter.outbound.persistence.sqlalchemy.client_repository import (
    SqlAlchemyClientRepository,
)


class SQLiteClientRepository(SqlAlchemyClientRepository):
    """Uses `sqlite+aiosqlite://` engines under the hood."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        super().__init__(session_factory)
