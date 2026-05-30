"""Shared SQLAlchemy `TrustedAssertionIssuerRepository` (sqlite + postgres)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from oauth_lab.adapter.outbound.persistence.orm.models import TrustedAssertionIssuerRow
from oauth_lab.domain.model.trusted_assertion_issuer import TrustedAssertionIssuer


class SqlAlchemyTrustedAssertionIssuerRepository:
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def find_by_issuer(self, iss: str) -> TrustedAssertionIssuer | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(TrustedAssertionIssuerRow).where(
                    TrustedAssertionIssuerRow.issuer == iss
                )
            )
            return None if row is None else _to_domain(row)

    async def save(self, issuer: TrustedAssertionIssuer) -> None:
        async with self._session_factory() as session:
            existing = await session.get(TrustedAssertionIssuerRow, issuer.issuer)
            if existing is None:
                session.add(_to_row(issuer))
            else:
                _update_row(existing, issuer)
            await session.commit()


def _to_domain(row: TrustedAssertionIssuerRow) -> TrustedAssertionIssuer:
    return TrustedAssertionIssuer(
        issuer=row.issuer,
        public_key_pem=row.public_key_pem,
        algorithm=row.algorithm,
        allowed_audiences=frozenset(a for a in row.allowed_audiences.split() if a),
    )


def _to_row(issuer: TrustedAssertionIssuer) -> TrustedAssertionIssuerRow:
    return TrustedAssertionIssuerRow(
        issuer=issuer.issuer,
        public_key_pem=issuer.public_key_pem,
        algorithm=issuer.algorithm,
        allowed_audiences=" ".join(sorted(issuer.allowed_audiences)),
    )


def _update_row(row: TrustedAssertionIssuerRow, issuer: TrustedAssertionIssuer) -> None:
    row.public_key_pem = issuer.public_key_pem
    row.algorithm = issuer.algorithm
    row.allowed_audiences = " ".join(sorted(issuer.allowed_audiences))
