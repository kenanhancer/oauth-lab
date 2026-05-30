"""In-memory `DeviceCodeRepository` — tests + ephemeral dev.

`save()` is upsert by `device_code` (primary key). Both lookup keys
(`device_code` and `user_code`) point at the same row — we maintain a
side index so `find_by_user_code` is O(1) too.
"""

from __future__ import annotations

import asyncio

from oauth_lab.domain.model.device_code import DeviceCode


class InMemoryDeviceCodeRepository:
    def __init__(self) -> None:
        self._by_device_code: dict[str, DeviceCode] = {}
        self._by_user_code: dict[str, str] = {}                  # user_code → device_code
        self._lock = asyncio.Lock()

    async def save(self, code: DeviceCode) -> None:
        async with self._lock:
            self._by_device_code[code.device_code] = code
            self._by_user_code[code.user_code] = code.device_code

    async def find_by_device_code(self, device_code: str) -> DeviceCode | None:
        return self._by_device_code.get(device_code)

    async def find_by_user_code(self, user_code: str) -> DeviceCode | None:
        device_code = self._by_user_code.get(user_code)
        if device_code is None:
            return None
        return self._by_device_code.get(device_code)
