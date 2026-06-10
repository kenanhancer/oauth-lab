"""Inbound port — user approves or denies the device authorization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class DeviceConsentDecision:
    user_code: str
    user_sub: str  # from the verified session
    approved: bool


class DeviceConsentUseCase(Protocol):
    async def execute(self, decision: DeviceConsentDecision) -> None: ...
