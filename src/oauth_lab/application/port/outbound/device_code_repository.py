"""Outbound port — persistence for `DeviceCode`.

Two lookup keys: the opaque `device_code` (used by the device when
polling /token) and the short `user_code` (typed by the user on the
verification URI). Both must be unique per active record.

Concurrency: device flow's only race is polling against approval, and
that race is benign (worst case: an extra `authorization_pending` /
`slow_down` before success). So no atomic check-and-set is required —
`save()` overwrites whole-record.
"""

from __future__ import annotations

from typing import Protocol

from oauth_lab.domain.model.device_code import DeviceCode


class DeviceCodeRepository(Protocol):
    async def save(self, code: DeviceCode) -> None: ...

    async def find_by_device_code(self, device_code: str) -> DeviceCode | None: ...

    async def find_by_user_code(self, user_code: str) -> DeviceCode | None: ...
