"""`POST /device_authorization` — RFC 8628 § 3.1.

Pure adapter: form-encoded body in, JSON response out. All business
logic lives in `RequestDeviceAuthorizationUseCase`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse

from oauth_lab.application.port.inbound.request_device_authorization_use_case import (
    DeviceAuthorizationRequest,
    RequestDeviceAuthorizationUseCase,
)
from oauth_lab.container import Container

router = APIRouter()


def _container(request: Request) -> Container:
    return request.app.state.container                                              # type: ignore[no-any-return]


def _use_case(
    container: Annotated[Container, Depends(_container)],
) -> RequestDeviceAuthorizationUseCase:
    return container.request_device_authorization


_NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@router.post("/device_authorization", tags=["Device Flow"])
async def device_authorization(
    *,
    use_case: Annotated[RequestDeviceAuthorizationUseCase, Depends(_use_case)],
    client_id: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
) -> JSONResponse:
    response = await use_case.execute(
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
