"""DeviceConsentService — marks a `DeviceCode` approved or denied.

The user (in a browser, on a different device) has entered the
`user_code` and clicked Approve or Deny. We look the code up, validate
it's still pending and not expired, and mutate state.

No redirect is returned because the device is the one polling /token —
the user's browser just sees a "done" page.
"""

from __future__ import annotations

from oauth_lab.application.port.inbound.device_consent_use_case import DeviceConsentDecision
from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.device_code_repository import DeviceCodeRepository
from oauth_lab.domain.model.errors import ExpiredToken, InvalidGrant, InvalidRequest


class DeviceConsentService:
    def __init__(self, *, device_codes: DeviceCodeRepository, clock: Clock) -> None:
        self._device_codes = device_codes
        self._clock = clock

    async def execute(self, decision: DeviceConsentDecision) -> None:
        code = await self._device_codes.find_by_user_code(decision.user_code)
        if code is None:
            raise InvalidRequest("unknown user_code")
        if code.is_expired(self._clock.now()):
            raise ExpiredToken("device code has expired")
        if not code.is_pending():
            raise InvalidGrant("device code has already been decided")

        updated = code.approve(decision.user_sub) if decision.approved else code.deny()
        await self._device_codes.save(updated)
