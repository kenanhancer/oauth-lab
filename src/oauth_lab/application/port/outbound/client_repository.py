"""Outbound port — persistence contract for the `Client` aggregate."""

from __future__ import annotations

from typing import Protocol

from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_id import ClientId


class ClientRepository(Protocol):
    async def find_by_id(self, client_id: ClientId) -> Client | None: ...
    async def save(self, client: Client) -> None: ...
