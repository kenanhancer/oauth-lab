"""In-memory `UserRepository`."""

from __future__ import annotations

from oauth_lab.domain.model.user import User


class InMemoryUserRepository:
    def __init__(self, initial: dict[str, User] | None = None) -> None:
        # Stored by sub; the username index is rebuilt on every lookup
        # (cheap for the demo; a real impl would maintain both maps).
        self._by_sub: dict[str, User] = dict(initial or {})

    async def find_by_sub(self, sub: str) -> User | None:
        return self._by_sub.get(sub)

    async def find_by_username(self, username: str) -> User | None:
        for user in self._by_sub.values():
            if user.username == username:
                return user
        return None

    async def save(self, user: User) -> None:
        self._by_sub[user.sub] = user
