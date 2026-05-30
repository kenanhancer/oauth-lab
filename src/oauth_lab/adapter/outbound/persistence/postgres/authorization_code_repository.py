"""Postgres `AuthorizationCodeRepository` — thin wrapper over the shared
SQLAlchemy implementation."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import async_sessionmaker

from oauth_lab.adapter.outbound.persistence.sqlalchemy.authorization_code_repository import (
    SqlAlchemyAuthorizationCodeRepository,
)


class PostgresAuthorizationCodeRepository(SqlAlchemyAuthorizationCodeRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        super().__init__(session_factory)
