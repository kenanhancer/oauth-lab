"""Shared SQLAlchemy `AuthorizationCodeRepository` for SQLite + Postgres.

`consume()` uses a conditional UPDATE that only matches rows where
`consumed_at IS NULL`. If the UPDATE affects zero rows, a concurrent
request already consumed the code — we treat this as a replay attack
and raise `InvalidGrant`.

This is the SQL equivalent of an atomic check-and-set; it doesn't need
an explicit transaction lock.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oauth_lab.adapter.outbound.persistence.orm.models import AuthorizationCodeRow
from oauth_lab.domain.model.authorization_code import AuthorizationCode
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidGrant
from oauth_lab.domain.model.pkce import PKCEChallenge
from oauth_lab.domain.model.scope import Scope, ScopeSet


class SqlAlchemyAuthorizationCodeRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, code: AuthorizationCode) -> None:
        async with self._session_factory() as session:
            session.add(_to_row(code))
            await session.commit()

    async def find_by_value(self, value: str) -> AuthorizationCode | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(AuthorizationCodeRow).where(AuthorizationCodeRow.value == value)
            )
            return None if row is None else _to_domain(row)

    async def consume(self, value: str, now: datetime) -> AuthorizationCode:
        async with self._session_factory() as session:
            # Atomic: only consume if not already consumed and not expired.
            stmt = (
                update(AuthorizationCodeRow)
                .where(
                    AuthorizationCodeRow.value == value,
                    AuthorizationCodeRow.consumed_at.is_(None),
                    AuthorizationCodeRow.expires_at > now,
                )
                .values(consumed_at=now)
            )
            result = cast("CursorResult[Any]", await session.execute(stmt))
            await session.commit()
            if result.rowcount == 0:
                # Distinguish missing vs replayed vs expired for clearer errors.
                row = await session.scalar(
                    select(AuthorizationCodeRow).where(AuthorizationCodeRow.value == value)
                )
                if row is None:
                    raise InvalidGrant("authorization code not found")
                if row.consumed_at is not None:
                    raise InvalidGrant("authorization code has already been used")
                raise InvalidGrant("authorization code has expired")

            row = await session.scalar(
                select(AuthorizationCodeRow).where(AuthorizationCodeRow.value == value)
            )
            assert row is not None
            return _to_domain(row)


def _to_domain(row: AuthorizationCodeRow) -> AuthorizationCode:
    return AuthorizationCode(
        value=row.value,
        client_id=ClientId(row.client_id),
        user_sub=row.user_sub,
        redirect_uri=row.redirect_uri,
        scope=ScopeSet(frozenset(Scope(s) for s in row.scope.split() if s)),
        pkce_challenge=PKCEChallenge(
            value=row.pkce_challenge_value, method=row.pkce_challenge_method
        ),
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        consumed_at=row.consumed_at,
        nonce=row.nonce,
    )


def _to_row(code: AuthorizationCode) -> AuthorizationCodeRow:
    return AuthorizationCodeRow(
        value=code.value,
        client_id=code.client_id.value,
        user_sub=code.user_sub,
        redirect_uri=code.redirect_uri,
        scope=" ".join(sorted(s.value for s in code.scope.scopes)),
        pkce_challenge_value=code.pkce_challenge.value,
        pkce_challenge_method=code.pkce_challenge.method,
        issued_at=code.issued_at,
        expires_at=code.expires_at,
        consumed_at=code.consumed_at,
        nonce=code.nonce,
    )
