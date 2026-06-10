"""`GET /authorize` — entry point of the browser flow.

Dispatches `AuthorizeUseCase` results to one of four HTTP responses:
- `AuthorizeRedirectToLogin` → 303 to `/login?next=<authorize_url>`
- `AuthorizeShowConsent` → 200 HTML consent page
- `AuthorizeRenderError` → 400 HTML error page (RFC 6749 §4.1.2.1)
- `AuthorizeRedirectError` → 303 to client redirect_uri with error params
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated
from urllib.parse import quote_plus, urlencode

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from oauth_lab.adapter.inbound.web.session_constants import SESSION_COOKIE_NAME
from oauth_lab.adapter.inbound.web.template_renderer import TemplateRenderer
from oauth_lab.application.port.inbound.authorize_use_case import (
    AuthorizeRedirectError,
    AuthorizeRedirectToLogin,
    AuthorizeRenderError,
    AuthorizeRequest,
    AuthorizeShowConsent,
    AuthorizeUseCase,
)


def build_router(
    *,
    authorize: Callable[[], AuthorizeUseCase],
    templates: TemplateRenderer,
    issuer: str,
) -> APIRouter:
    """Mount `GET /authorize`. `authorize` is a provider resolved per request
    so the composition root can wire the container lazily; `issuer` feeds the
    RFC 9207 `iss` parameter on error redirects."""
    router = APIRouter()

    @router.get("/authorize", tags=["Browser"])
    async def authorize_endpoint(
        request: Request,
        *,
        session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
    ) -> Response:
        qp = request.query_params
        result = await authorize().execute(
            request=AuthorizeRequest(
                response_type=qp.get("response_type"),
                client_id=qp.get("client_id"),
                redirect_uri=qp.get("redirect_uri"),
                scope=qp.get("scope"),
                state=qp.get("state"),
                code_challenge=qp.get("code_challenge"),
                code_challenge_method=qp.get("code_challenge_method"),
            ),
            session_cookie=session_cookie,
            full_request_url=str(request.url),
        )

        if isinstance(result, AuthorizeRedirectToLogin):
            next_url = quote_plus(result.next_authorize_url)
            return RedirectResponse(url=f"/login?next={next_url}", status_code=303)

        if isinstance(result, AuthorizeShowConsent):
            html = templates.render(
                "consent.html",
                client_id=str(result.client.id),
                username=result.user.username,
                requested_scopes=sorted(s.value for s in result.requested_scope.scopes),
                scope_str=result.requested_scope.to_str(),
                redirect_uri=result.redirect_uri,
                state=result.state,
                code_challenge_value=result.code_challenge.value,
                code_challenge_method=result.code_challenge.method,
                csrf_token=result.csrf_token,
            )
            return HTMLResponse(content=html, status_code=200)

        if isinstance(result, AuthorizeRenderError):
            html = templates.render(
                "error.html",
                error_code=result.error_code,
                description=result.description,
            )
            return HTMLResponse(content=html, status_code=400)

        if isinstance(result, AuthorizeRedirectError):
            params: dict[str, str] = {
                "error": result.error,
                "error_description": result.error_description,
                "iss": issuer,                                               # RFC 9207
            }
            if result.state:
                params["state"] = result.state
            sep = "&" if "?" in result.redirect_uri else "?"
            return RedirectResponse(
                url=result.redirect_uri + sep + urlencode(params),
                status_code=303,
            )

        raise AssertionError(f"unhandled AuthorizeResult variant: {type(result).__name__}")

    return router
