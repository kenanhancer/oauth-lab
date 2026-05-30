"""In-memory `ClientRepository` adapter — for tests and ephemeral dev."""

from __future__ import annotations

from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_id import ClientId


class InMemoryClientRepository:
    def __init__(self, initial: dict[ClientId, Client] | None = None) -> None:
        self._store: dict[ClientId, Client] = dict(initial or {})

    async def find_by_id(self, client_id: ClientId) -> Client | None:
        return self._store.get(client_id)

    async def save(self, client: Client) -> None:
        self._store[client.id] = client
