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

import secrets
from collections.abc import Callable
from typing import Annotated
from urllib.parse import quote_plus

from fastapi import APIRouter, Cookie, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from oauth_lab.adapter.inbound.web.session_constants import SESSION_COOKIE_NAME
from oauth_lab.adapter.inbound.web.template_renderer import TemplateRenderer
from oauth_lab.application.port.inbound.device_consent_use_case import (
    DeviceConsentDecision,
    DeviceConsentUseCase,
)
from oauth_lab.application.port.inbound.lookup_device_code_use_case import (
    LookupDeviceCodeUseCase,
)
from oauth_lab.application.port.outbound.session_signer import SessionSigner
from oauth_lab.domain.model.errors import InvalidRequest


def build_router(
    *,
    lookup_device_code: Callable[[], LookupDeviceCodeUseCase],
    device_consent: Callable[[], DeviceConsentUseCase],
    session_signer: Callable[[], SessionSigner],
    templates: TemplateRenderer,
) -> APIRouter:
    """Mount the `/device` browser endpoints. The use cases and signer are
    providers resolved per request so the composition root can wire the
    container lazily."""
    router = APIRouter()

    async def _render_device_page(
        *,
        user_code: str | None,
        session_cookie: str | None,
        error: str | None = None,
    ) -> Response:
        if not user_code:
            html = templates.render(
                "device_entry.html",
                user_code=None,
                error=error,
            )
            return HTMLResponse(content=html)

        view = await lookup_device_code().execute(user_code)
        if view is None:
            html = templates.render(
                "device_entry.html",
                user_code=user_code,
                error="Unknown code. Check your device's screen and try again.",
            )
            return HTMLResponse(content=html, status_code=404)

        if view.expired:
            html = templates.render(
                "error.html",
                error_code="expired_token",
                description="This device code has expired. Ask the device to start over.",
            )
            return HTMLResponse(content=html, status_code=400)

        if view.already_decided:
            html = templates.render(
                "error.html",
                error_code="already_decided",
                description="This device code has already been approved or denied.",
            )
            return HTMLResponse(content=html, status_code=400)

        # Need a logged-in user to grant consent.
        session = session_signer().verify(session_cookie)
        if session is None:
            next_url = "/device?user_code=" + quote_plus(view.user_code)
            return RedirectResponse(
                url="/login?next=" + quote_plus(next_url), status_code=303
            )

        html = templates.render(
            "device_consent.html",
            user_code=view.user_code,
            client_id=view.client_id,
            requested_scopes=list(view.requested_scopes),
            csrf_token=session.csrf_token,
        )
        return HTMLResponse(content=html)

    @router.get("/device", tags=["Device Flow"])
    async def device_get(
        request: Request,
        *,
        session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
    ) -> Response:
        user_code = request.query_params.get("user_code")
        return await _render_device_page(
            user_code=user_code,
            session_cookie=session_cookie,
        )

    @router.post("/device", tags=["Device Flow"])
    async def device_post(
        *,
        user_code: Annotated[str, Form()],
        session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
    ) -> Response:
        return await _render_device_page(
            user_code=user_code.strip().upper(),
            session_cookie=session_cookie,
        )

    @router.post("/device/consent", tags=["Device Flow"])
    async def device_consent_submit(
        *,
        user_code: Annotated[str, Form()],
        decision: Annotated[str, Form()],                              # "approve" | "deny"
        csrf_token: Annotated[str, Form()] = "",
        session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
    ) -> Response:
        session = session_signer().verify(session_cookie)
        if session is None:
            return RedirectResponse(url="/login", status_code=303)

        if not secrets.compare_digest(csrf_token, session.csrf_token):
            raise InvalidRequest("CSRF token mismatch")

        await device_consent().execute(
            DeviceConsentDecision(
                user_code=user_code,
                user_sub=session.user_sub,
                approved=(decision == "approve"),
            )
        )

        html = templates.render("success.html")
        return HTMLResponse(content=html)

    return router
