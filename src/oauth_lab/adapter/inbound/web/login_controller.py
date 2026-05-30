"""`GET/POST /login` — the credential check page.

GET renders the form. POST verifies credentials with `LoginUseCase`,
sets the session cookie on success, and 303s back to `next`. On failure
it re-renders the form with an error.

This route does not enforce that `next` is a relative URL pointing into
this AS — Phase 7 (hardening) will add open-redirect protection.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from oauth_lab.adapter.inbound.web.authorize_controller import SESSION_COOKIE_NAME
from oauth_lab.application.port.inbound.login_use_case import LoginUseCase
from oauth_lab.application.service.login_service import InvalidCredentials
from oauth_lab.container import Container

router = APIRouter()


def _container(request: Request) -> Container:
    return request.app.state.container                                              # type: ignore[no-any-return]


def _use_case(container: Annotated[Container, Depends(_container)]) -> LoginUseCase:
    return container.login


@router.get("/login", tags=["Browser"])
async def login_form(
    request: Request,
    next: Annotated[str | None, "Query"] = None,
) -> Response:
    container: Container = request.app.state.container
    html = container.templates.render(
        "login.html",
        next_url=request.query_params.get("next") or "/",
        username=None,
        error=None,
    )
    return HTMLResponse(content=html)


@router.post("/login", tags=["Browser"])
async def login_submit(
    request: Request,
    *,
    use_case: Annotated[LoginUseCase, Depends(_use_case)],
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
) -> Response:
    container: Container = request.app.state.container
    try:
        cookie_value = await use_case.execute(username=username, password=password)
    except InvalidCredentials:
        html = container.templates.render(
            "login.html",
            next_url=next,
            username=username,
            error="Invalid username or password.",
        )
        return HTMLResponse(content=html, status_code=401)

    response = RedirectResponse(url=next, status_code=303)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=cookie_value,
        httponly=True,
        samesite="lax",
        max_age=container.settings.session_ttl_seconds,
        # `secure=True` would be added by reverse-proxy / Phase 7 hardening
    )
    return response
