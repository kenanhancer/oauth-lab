"""Alembic environment — async, single-source-of-truth URL.

The database URL is taken from `Settings().database_url` (env var
OAUTH_LAB_DATABASE_URL), the same place the running application reads it, so
the migration tooling can never drift onto a different database than the app.

Importing `models` registers all six Row classes on `Base.metadata`, which is
what autogenerate diffs against the live database.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from oauth_lab.adapter.outbound.persistence.orm import models
from oauth_lab.config import Settings

# Alembic injects `context.config` at runtime (typed via context.pyi).
config = context.config

# Honour the [loggers]/[handlers]/[formatters] stanzas in alembic.ini.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Diff target: every table declared on Base via the imported models module.
target_metadata = models.Base.metadata


def _database_url() -> str:
    """Resolve the SQL URL from Settings; reject the non-SQL memory backend."""
    url = Settings().database_url
    if url.startswith("memory://"):
        raise RuntimeError(
            "Alembic requires a SQL database_url; got memory://. "
            "Set OAUTH_LAB_DATABASE_URL to a sqlite+aiosqlite/postgresql+asyncpg URL."
        )
    return url


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a DBAPI connection (`alembic upgrade --sql`)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Configure the context against a live (sync-facing) connection and run."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Open an async engine, then drive the sync migration body via run_sync."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online mode — runs the async engine on a fresh loop."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
