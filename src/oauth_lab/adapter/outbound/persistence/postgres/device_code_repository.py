"""Postgres `DeviceCodeRepository` — thin wrapper."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import async_sessionmaker

from oauth_lab.adapter.outbound.persistence.sqlalchemy.device_code_repository import (
    SqlAlchemyDeviceCodeRepository,
)


class PostgresDeviceCodeRepository(SqlAlchemyDeviceCodeRepository):
    def __init__(self, session_factory: async_sessionmaker) -> None:
        super().__init__(session_factory)
