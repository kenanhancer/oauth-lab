"""`GET/POST /login` — the credential check page.

GET renders the form. POST verifies credentials with `LoginUseCase`,
sets the session cookie on success, and 303s back to `next`. On failure
it re-renders the form with an error.

Open-redirect defence: `next` is attacker-controllable (it travels in the
query string and the form). Before using it as a redirect target it is run
through `safe_next`, which only accepts a same-origin relative path and
falls back to "/" otherwise.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from oauth_lab.adapter.inbound.web.session_constants import SESSION_COOKIE_NAME
from oauth_lab.adapter.inbound.web.template_renderer import TemplateRenderer
from oauth_lab.application.port.inbound.login_use_case import InvalidCredentials, LoginUseCase


def safe_next(next_url: str | None) -> str:
    """Return `next_url` only if it is a same-origin relative path, else "/".

    A safe value must start with a single "/" so it stays on this origin.
    Reject "//host" (protocol-relative → off-origin) and anything carrying a
    scheme/authority (e.g. "https://evil", "javascript:..."). This blocks the
    open-redirect where a crafted `next` bounces the user off the AS.
    """
    if not next_url or not next_url.startswith("/") or next_url.startswith("//"):
        return "/"
    return next_url


def build_router(
    *,
    login: Callable[[], LoginUseCase],
    templates: TemplateRenderer,
    cookie_secure: bool,
    cookie_max_age_seconds: int,
) -> APIRouter:
    """Mount `GET/POST /login`. `login` is a provider resolved per request so
    the composition root can wire the container lazily; the cookie parameters
    are composition-time config (secure flag derived from the issuer scheme)."""
    router = APIRouter()

    @router.get("/login", tags=["Browser"])
    async def login_form(request: Request) -> Response:
        html = templates.render(
            "login.html",
            next_url=safe_next(request.query_params.get("next")),
            username=None,
            error=None,
        )
        return HTMLResponse(content=html)

    @router.post("/login", tags=["Browser"])
    async def login_submit(
        *,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        next: Annotated[str, Form()] = "/",
    ) -> Response:
        target = safe_next(next)
        try:
            cookie_value = await login().execute(username=username, password=password)
        except InvalidCredentials:
            html = templates.render(
                "login.html",
                next_url=target,
                username=username,
                error="Invalid username or password.",
            )
            return HTMLResponse(content=html, status_code=401)

        response = RedirectResponse(url=target, status_code=303)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=cookie_value,
            httponly=True,
            samesite="lax",
            # Secure in prod (https issuer) but still usable on localhost http.
            secure=cookie_secure,
            max_age=cookie_max_age_seconds,
        )
        return response

    return router
