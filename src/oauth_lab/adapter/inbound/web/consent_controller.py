"""`POST /consent` — user clicks Approve / Deny.

Requires a valid session cookie. Re-validates everything via
`ConsentUseCase` (the consent form's hidden fields are user-controllable
— never trust them blindly).

CSRF: the form carries a hidden `csrf_token` that must match the
synchronizer token minted into the signed session at login. A mismatch
raises `InvalidRequest` (RFC 6749 §5.2 `invalid_request`).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Cookie, Form
from fastapi.responses import RedirectResponse, Response

from oauth_lab.adapter.inbound.web.authorization_response import (
    encode_authorization_response,
)
from oauth_lab.adapter.inbound.web.session_constants import SESSION_COOKIE_NAME
from oauth_lab.adapter.inbound.web.session_guard import require_session_with_csrf
from oauth_lab.application.port.inbound.consent_use_case import (
    ConsentDecision,
    ConsentDenied,
    ConsentUseCase,
)
from oauth_lab.application.port.outbound.session_signer import SessionSigner


def build_router(
    *,
    consent: Callable[[], ConsentUseCase],
    session_signer: Callable[[], SessionSigner],
    issuer: str,
) -> APIRouter:
    """Mount `POST /consent`. The use case and signer are providers resolved
    per request so the composition root can wire the container lazily;
    `issuer` feeds the RFC 9207 `iss` parameter on the redirect back."""
    router = APIRouter()

    @router.post("/consent", tags=["Browser"])
    async def consent_submit(
        *,
        session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
        decision: Annotated[str, Form()],
        csrf_token: Annotated[str, Form()] = "",
        client_id: Annotated[str, Form()],
        redirect_uri: Annotated[str, Form()],
        scope: Annotated[str | None, Form()] = None,
        state: Annotated[str | None, Form()] = None,
        code_challenge: Annotated[str, Form()] = "",
        code_challenge_method: Annotated[str, Form()] = "S256",
    ) -> Response:
        session = require_session_with_csrf(
            session_signer=session_signer(),
            session_cookie=session_cookie,
            csrf_token=csrf_token,
        )
        if isinstance(session, Response):
            return session

        result = await consent().execute(
            ConsentDecision(
                approved=(decision == "approve"),
                user_sub=session.user_sub,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )
        )
        if isinstance(result, ConsentDenied):
            params = {
                "error": ConsentDenied.ERROR_CODE,
                "error_description": result.error_description,
            }
        else:
            params = {"code": result.code}
        target_url = encode_authorization_response(
            result.redirect_uri, params, state=result.state, issuer=issuer
        )
        return RedirectResponse(url=target_url, status_code=303)

    return router
