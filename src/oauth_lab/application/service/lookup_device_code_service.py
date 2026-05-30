"""LookupDeviceCodeService — read-only, for the consent page renderer.

Returns a flat view of the device code so the web adapter can render
the consent screen without ever touching the domain entity directly.
"""

from __future__ import annotations

from oauth_lab.application.port.inbound.lookup_device_code_use_case import DeviceCodeView
from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.device_code_repository import DeviceCodeRepository


class LookupDeviceCodeService:
    def __init__(self, *, device_codes: DeviceCodeRepository, clock: Clock) -> None:
        self._device_codes = device_codes
        self._clock = clock

    async def execute(self, user_code: str) -> DeviceCodeView | None:
        code = await self._device_codes.find_by_user_code(user_code)
        if code is None:
            return None
        return DeviceCodeView(
            user_code=code.user_code,
            client_id=str(code.client_id),
            requested_scopes=tuple(sorted(s.value for s in code.scope.scopes)),
            expired=code.is_expired(self._clock.now()),
            already_decided=not code.is_pending(),
        )
