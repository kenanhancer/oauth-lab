"""Inbound port — fetch a device code for rendering the consent page.

Read-only — does NOT mutate state. Returns None when the code is not
recognised (or has expired / already been consumed), so the web
controller can render a friendly error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class DeviceCodeView:
    user_code: str
    client_id: str
    requested_scopes: tuple[str, ...]
    expired: bool
    already_decided: bool                                         # approved or denied


class LookupDeviceCodeUseCase(Protocol):
    async def execute(self, user_code: str) -> DeviceCodeView | None: ...
