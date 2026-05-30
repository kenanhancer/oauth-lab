"""Browser-facing endpoints for the device flow.

- `GET /device` — entry form OR consent page (when `user_code` is in
  the query string, e.g. arriving via `verification_uri_complete`).
- `POST /device` — handle the entry-form submission; same dispatcher
  as the GET-with-query path.
- `POST /device/consent` — record the user's Approve / Deny.

Sessions: the consent page requires a logged-in user. If not logged in,
the controller redirects to `/login?next=/device?user_code=XYZ` so the
user comes back with the code intact.
"""

from __future__ import annotations

from typing import Annotated
from urllib.parse import quote_plus

from fastapi import APIRouter, Cookie, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from oauth_lab.adapter.inbound.web.authorize_controller import SESSION_COOKIE_NAME
from oauth_lab.application.port.inbound.device_consent_use_case import (
    DeviceConsentDecision,
    DeviceConsentUseCase,
)
from oauth_lab.application.port.inbound.lookup_device_code_use_case import (
    LookupDeviceCodeUseCase,
)
from oauth_lab.application.port.outbound.session_signer import SessionSigner
from oauth_lab.container import Container

router = APIRouter()


def _container(request: Request) -> Container:
    return request.app.state.container                                              # type: ignore[no-any-return]


def _lookup_use_case(
    container: Annotated[Container, Depends(_container)],
) -> LookupDeviceCodeUseCase:
    return container.lookup_device_code


def _consent_use_case(
    container: Annotated[Container, Depends(_container)],
) -> DeviceConsentUseCase:
    return container.device_consent


def _session_signer(
    container: Annotated[Container, Depends(_container)],
) -> SessionSigner:
    return container.session_signer


async def _render_device_page(
    request: Request,
    *,
    user_code: str | None,
    session_cookie: str | None,
    lookup: LookupDeviceCodeUseCase,
    signer: SessionSigner,
    error: str | None = None,
) -> Response:
    container: Container = request.app.state.container

    if not user_code:
        html = container.templates.render(
            "device_entry.html",
            user_code=None,
            error=error,
        )
        return HTMLResponse(content=html)

    view = await lookup.execute(user_code)
    if view is None:
        html = container.templates.render(
            "device_entry.html",
            user_code=user_code,
            error="Unknown code. Check your device's screen and try again.",
        )
        return HTMLResponse(content=html, status_code=404)

    if view.expired:
        html = container.templates.render(
            "error.html",
            error_code="expired_token",
            description="This device code has expired. Ask the device to start over.",
        )
        return HTMLResponse(content=html, status_code=400)

    if view.already_decided:
        html = container.templates.render(
            "error.html",
            error_code="already_decided",
            description="This device code has already been approved or denied.",
        )
        return HTMLResponse(content=html, status_code=400)

    # Need a logged-in user to grant consent.
    session = signer.verify(session_cookie)
    if session is None:
        next_url = "/device?user_code=" + quote_plus(view.user_code)
        return RedirectResponse(
            url="/login?next=" + quote_plus(next_url), status_code=303
        )

    html = container.templates.render(
        "device_consent.html",
        user_code=view.user_code,
        client_id=view.client_id,
        requested_scopes=list(view.requested_scopes),
    )
    return HTMLResponse(content=html)


@router.get("/device", tags=["Device Flow"])
async def device_get(
    request: Request,
    *,
    lookup: Annotated[LookupDeviceCodeUseCase, Depends(_lookup_use_case)],
    signer: Annotated[SessionSigner, Depends(_session_signer)],
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> Response:
    user_code = request.query_params.get("user_code")
    return await _render_device_page(
        request,
        user_code=user_code,
        session_cookie=session_cookie,
        lookup=lookup,
        signer=signer,
    )


@router.post("/device", tags=["Device Flow"])
async def device_post(
    request: Request,
    *,
    lookup: Annotated[LookupDeviceCodeUseCase, Depends(_lookup_use_case)],
    signer: Annotated[SessionSigner, Depends(_session_signer)],
    user_code: Annotated[str, Form()],
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> Response:
    return await _render_device_page(
        request,
        user_code=user_code.strip().upper(),
        session_cookie=session_cookie,
        lookup=lookup,
        signer=signer,
    )


@router.post("/device/consent", tags=["Device Flow"])
async def device_consent(
    request: Request,
    *,
    consent_use_case: Annotated[DeviceConsentUseCase, Depends(_consent_use_case)],
    signer: Annotated[SessionSigner, Depends(_session_signer)],
    user_code: Annotated[str, Form()],
    decision: Annotated[str, Form()],                                  # "approve" | "deny"
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> Response:
    session = signer.verify(session_cookie)
    if session is None:
        return RedirectResponse(url="/login", status_code=303)

    await consent_use_case.execute(
        DeviceConsentDecision(
            user_code=user_code,
            user_sub=session.user_sub,
            approved=(decision == "approve"),
        )
    )

    container: Container = request.app.state.container
    html = container.templates.render("success.html")
    return HTMLResponse(content=html)
