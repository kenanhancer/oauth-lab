"""Outbound port — persistence for the `User` aggregate."""

from __future__ import annotations

from typing import Protocol

from oauth_lab.domain.model.user import User


class UserRepository(Protocol):
    async def find_by_sub(self, sub: str) -> User | None: ...
    async def find_by_username(self, username: str) -> User | None: ...
    async def save(self, user: User) -> None: ...
