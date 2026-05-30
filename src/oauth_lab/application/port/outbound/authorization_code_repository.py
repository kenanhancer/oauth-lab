"""Outbound port — persistence for `AuthorizationCode`.

`consume()` is the security-critical operation: it must atomically
check that the code is still valid (not consumed, not expired) and mark
it consumed in one indivisible step. Otherwise two concurrent `/token`
requests could both succeed (replay attack).
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from oauth_lab.domain.model.authorization_code import AuthorizationCode


class AuthorizationCodeRepository(Protocol):
    async def save(self, code: AuthorizationCode) -> None: ...

    async def find_by_value(self, value: str) -> AuthorizationCode | None: ...

    async def consume(self, value: str, now: datetime) -> AuthorizationCode:
        """Atomic single-use consumption; raises `InvalidGrant` if the
        code is missing, already consumed, or expired."""
        ...
