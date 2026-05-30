"""Outbound port — persistence for refresh tokens with family-based replay defence.

`rotate()` is the single security-critical operation: it must atomically
(a) verify the old token is still valid and (b) mark it consumed and
(c) persist the new replacement, all in one indivisible step. Otherwise
a concurrent attack could redeem the same token twice.

`revoke_family()` is invoked when replay is detected — it marks every
token in the chain as consumed, forcing the user to re-authenticate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from oauth_lab.domain.model.refresh_token import RefreshToken


class RefreshTokenRepository(Protocol):
    async def save(self, token: RefreshToken) -> None: ...

    async def find_by_value(self, value: str) -> RefreshToken | None: ...

    async def rotate(
        self,
        *,
        old_value: str,
        new_token: RefreshToken,
        now: datetime,
    ) -> RefreshToken:
        """Atomic single-use rotation. Raises `InvalidGrant` if the old
        token is missing, expired, or already consumed."""
        ...

    async def revoke_family(self, family_id: str, now: datetime) -> int:
        """Mark every active token in the family as consumed. Returns
        the count actually revoked."""
        ...
