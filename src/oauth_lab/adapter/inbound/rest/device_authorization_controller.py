"""`POST /device_authorization` — RFC 8628 § 3.1.

Pure adapter: form-encoded body in, JSON response out. All business
logic lives in `RequestDeviceAuthorizationUseCase`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Form
from fastapi.responses import JSONResponse

from oauth_lab.application.port.inbound.request_device_authorization_use_case import (
    DeviceAuthorizationRequest,
    RequestDeviceAuthorizationUseCase,
)

_NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def build_router(
    *, request_device_authorization: Callable[[], RequestDeviceAuthorizationUseCase]
) -> APIRouter:
    """Mount `POST /device_authorization`. The use case is a provider
    resolved per request so the composition root can wire the container lazily."""
    router = APIRouter()

    @router.post("/device_authorization", tags=["Device Flow"])
    async def device_authorization(
        *,
        client_id: Annotated[str | None, Form()] = None,
        scope: Annotated[str | None, Form()] = None,
    ) -> JSONResponse:
        response = await request_device_authorization().execute(
            DeviceAuthorizationRequest(client_id=client_id, scope=scope)
        )
        body = {
            "device_code": response.device_code,
            "user_code": response.user_code,
            "verification_uri": response.verification_uri,
            "verification_uri_complete": response.verification_uri_complete,
            "expires_in": response.expires_in,
            "interval": response.interval,
        }
        return JSONResponse(content=body, headers=_NO_STORE_HEADERS)

    return router
