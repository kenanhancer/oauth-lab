"""Outbound port — persistence for `DeviceCode`.

Two lookup keys: the opaque `device_code` (used by the device when
polling /token) and the short `user_code` (typed by the user on the
verification URI). Both must be unique per active record.

Concurrency: polling against approval is a benign race (worst case: an
extra `authorization_pending` / `slow_down` before success), so plain
`save()` upserts suffice there. Redemption is NOT benign: two concurrent
polls of an approved code must not both receive tokens, so `redeem()` is
the atomic check-and-set — same role as
`AuthorizationCodeRepository.consume` and `RefreshTokenRepository.rotate`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from oauth_lab.domain.model.device_code import DeviceCode


class DeviceCodeRepository(Protocol):
    async def save(self, code: DeviceCode) -> None: ...

    async def find_by_device_code(self, device_code: str) -> DeviceCode | None: ...

    async def find_by_user_code(self, user_code: str) -> DeviceCode | None: ...

    async def redeem(self, device_code: str, now: datetime) -> DeviceCode | None:
        """Atomic single-use redemption: transition an approved, unredeemed,
        unexpired code to redeemed in one indivisible step. Returns the
        redeemed entity, or `None` if the code was not in a redeemable
        state (missing, pending, denied, expired, or already redeemed)."""
        ...
