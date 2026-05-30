"""In-memory `RefreshTokenRepository` — tests + ephemeral dev.

Uses an `asyncio.Lock` to make `rotate()` and `revoke_family()` atomic.
Without the lock, a concurrent attacker could redeem the same token
twice between the check and the mark.
"""

from __future__ import annotations

import asyncio
from datetime import datetime

from oauth_lab.domain.model.errors import InvalidGrant
from oauth_lab.domain.model.refresh_token import RefreshToken


class InMemoryRefreshTokenRepository:
    def __init__(self) -> None:
        self._store: dict[str, RefreshToken] = {}
        self._lock = asyncio.Lock()

    async def save(self, token: RefreshToken) -> None:
        async with self._lock:
            self._store[token.value] = token

    async def find_by_value(self, value: str) -> RefreshToken | None:
        return self._store.get(value)

    async def rotate(
        self,
        *,
        old_value: str,
        new_token: RefreshToken,
        now: datetime,
    ) -> RefreshToken:
        async with self._lock:
            old = self._store.get(old_value)
            if old is None:
                raise InvalidGrant("refresh token not found")
            if old.is_consumed():
                raise InvalidGrant("refresh token has already been used")
            if old.is_expired(now):
                raise InvalidGrant("refresh token has expired")
            self._store[old_value] = old.consume(now)
            self._store[new_token.value] = new_token
            return new_token

    async def revoke_family(self, family_id: str, now: datetime) -> int:
        async with self._lock:
            count = 0
            for value, token in list(self._store.items()):
                if token.family_id == family_id and not token.is_consumed():
                    self._store[value] = token.consume(now)
                    count += 1
            return count
