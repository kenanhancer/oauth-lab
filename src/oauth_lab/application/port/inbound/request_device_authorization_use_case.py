"""Inbound port — `POST /device_authorization` (RFC 8628 § 3.1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationRequest:
    client_id: str | None
    scope: str | None


@dataclass(frozen=True, slots=True)
class DeviceAuthorizationResponse:
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


class RequestDeviceAuthorizationUseCase(Protocol):
    async def execute(
        self, request: DeviceAuthorizationRequest
    ) -> DeviceAuthorizationResponse: ...
