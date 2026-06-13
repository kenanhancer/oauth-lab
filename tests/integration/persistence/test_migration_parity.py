"""Migration ⇄ models parity guard.

Applies every Alembic migration to a fresh database, then reflects the result
and asserts the table names and per-table column names match exactly what the
ORM declares on ``Base.metadata``. This permanently catches drift: edit a Row
class without writing a migration (or vice versa) and this test fails.

The migration is driven through the real ``migrations/env.py`` so the test also
exercises that the env wiring works. env.py resolves the URL from
``OAUTH_LAB_DATABASE_URL`` (single source of truth), so the test points that env
var at a throwaway tmp-file SQLite DB. A tmp file — not ``:memory:`` — is used
because Alembic opens its own connections and an in-memory SQLite DB is not
shared across them without shared-cache plumbing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from oauth_lab.adapter.outbound.persistence.orm.models import Base

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ALEMBIC_INI = _REPO_ROOT / "alembic.ini"


def _alembic_config() -> Config:
    cfg = Config(str(_ALEMBIC_INI))
    # script_location in the ini is relative to the repo root; make it absolute
    # so the test is independent of the process working directory.
    cfg.set_main_option("script_location", str(_REPO_ROOT / "migrations"))
    return cfg


def test_migration_head_matches_orm_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "parity.db"
    # env.py reads the URL from Settings (OAUTH_LAB_DATABASE_URL) and builds an
    # async engine, so the migration URL must use the async aiosqlite driver.
    monkeypatch.setenv("OAUTH_LAB_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")

    command.upgrade(_alembic_config(), "head")

    # Reflect the migrated database with a plain (sync) engine.
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        inspector = inspect(engine)
        migrated_tables = {
            name for name in inspector.get_table_names() if name != "alembic_version"
        }
        migrated_columns = {
            table: {col["name"] for col in inspector.get_columns(table)}
            for table in migrated_tables
        }
    finally:
        engine.dispose()

    expected_tables = set(Base.metadata.tables.keys())
    expected_columns = {
        name: set(table.columns.keys()) for name, table in Base.metadata.tables.items()
    }

    assert migrated_tables == expected_tables
    assert migrated_columns == expected_columns
