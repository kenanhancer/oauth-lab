"""Shared SQLAlchemy `ClientRepository` implementation used by both the
SQLite and Postgres adapters (they differ only by URL scheme + driver).

This is an Adapter pattern in practice: the ORM model `ClientRow` is
translated to/from the domain `Client` entity at the boundary.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from oauth_lab.adapter.outbound.persistence.orm.models import ClientRow
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import Scope, ScopeSet


class SqlAlchemyClientRepository:
    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def find_by_id(self, client_id: ClientId) -> Client | None:
        async with self._session_factory() as session:
            row = await session.scalar(
                select(ClientRow).where(ClientRow.client_id == client_id.value)
            )
            return None if row is None else _to_domain(row)

    async def save(self, client: Client) -> None:
        async with self._session_factory() as session:
            existing = await session.get(ClientRow, client.id.value)
            if existing is None:
                session.add(_to_row(client))
            else:
                _update_row(existing, client)
            await session.commit()


def _to_domain(row: ClientRow) -> Client:
    return Client(
        id=ClientId(row.client_id),
        secret_hash=row.secret_hash,
        token_endpoint_auth_method=ClientAuthMethod(row.token_endpoint_auth_method),
        allowed_grant_types=frozenset(
            GrantType(g) for g in row.allowed_grant_types.split() if g
        ),
        allowed_scopes=ScopeSet(
            frozenset(Scope(s) for s in row.allowed_scopes.split() if s)
        ),
        redirect_uris=frozenset(u for u in row.redirect_uris.split() if u),
        default_audience=row.default_audience,
    )


def _to_row(client: Client) -> ClientRow:
    return ClientRow(
        client_id=client.id.value,
        secret_hash=client.secret_hash,
        token_endpoint_auth_method=client.token_endpoint_auth_method.value,
        allowed_grant_types=" ".join(sorted(g.value for g in client.allowed_grant_types)),
        allowed_scopes=" ".join(sorted(s.value for s in client.allowed_scopes.scopes)),
        redirect_uris=" ".join(sorted(client.redirect_uris)),
        default_audience=client.default_audience,
    )


def _update_row(row: ClientRow, client: Client) -> None:
    row.secret_hash = client.secret_hash
    row.token_endpoint_auth_method = client.token_endpoint_auth_method.value
    row.allowed_grant_types = " ".join(sorted(g.value for g in client.allowed_grant_types))
    row.allowed_scopes = " ".join(sorted(s.value for s in client.allowed_scopes.scopes))
    row.redirect_uris = " ".join(sorted(client.redirect_uris))
    row.default_audience = client.default_audience
