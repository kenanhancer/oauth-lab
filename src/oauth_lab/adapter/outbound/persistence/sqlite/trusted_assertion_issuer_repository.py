"""SQLite `TrustedAssertionIssuerRepository` — thin wrapper."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import async_sessionmaker

from oauth_lab.adapter.outbound.persistence.sqlalchemy.trusted_assertion_issuer_repository import (
    SqlAlchemyTrustedAssertionIssuerRepository,
)


class SQLiteTrustedAssertionIssuerRepository(SqlAlchemyTrustedAssertionIssuerRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        super().__init__(session_factory)
