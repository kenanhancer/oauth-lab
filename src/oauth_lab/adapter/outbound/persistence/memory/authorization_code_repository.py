"""In-memory `AuthorizationCodeRepository` — tests and ephemeral dev.

Uses an `asyncio.Lock` to enforce atomic check-and-set in `consume()`.
A pure dict would be vulnerable to a race where two parallel `/token`
requests both observe `consumed_at is None` and both succeed.
"""

from __future__ import annotations

import asyncio
from datetime import datetime

from oauth_lab.domain.model.authorization_code import AuthorizationCode
from oauth_lab.domain.model.errors import InvalidGrant


class InMemoryAuthorizationCodeRepository:
    def __init__(self) -> None:
        self._store: dict[str, AuthorizationCode] = {}
        self._lock = asyncio.Lock()

    async def save(self, code: AuthorizationCode) -> None:
        async with self._lock:
            self._store[code.value] = code

    async def find_by_value(self, value: str) -> AuthorizationCode | None:
        return self._store.get(value)

    async def consume(self, value: str, now: datetime) -> AuthorizationCode:
        async with self._lock:
            code = self._store.get(value)
            if code is None:
                raise InvalidGrant("authorization code not found")
            consumed = code.consume(now)  # raises if expired / replayed
            self._store[value] = consumed
            return consumed
