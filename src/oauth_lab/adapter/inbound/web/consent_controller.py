"""`POST /consent` — user clicks Approve / Deny.

Requires a valid session cookie. Re-validates everything via
`ConsentUseCase` (the consent form's hidden fields are user-controllable
— never trust them blindly).

CSRF: the form carries a hidden `csrf_token` that must match the
synchronizer token minted into the signed session at login. A mismatch
raises `InvalidRequest` (RFC 6749 §5.2 `invalid_request`).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Cookie, Form
from fastapi.responses import RedirectResponse, Response

from oauth_lab.adapter.inbound.web.session_constants import SESSION_COOKIE_NAME
from oauth_lab.application.port.inbound.consent_use_case import ConsentDecision, ConsentUseCase
from oauth_lab.application.port.outbound.session_signer import SessionSigner
from oauth_lab.domain.model.errors import InvalidRequest


def build_router(
    *,
    consent: Callable[[], ConsentUseCase],
    session_signer: Callable[[], SessionSigner],
) -> APIRouter:
    """Mount `POST /consent`. Both dependencies are providers resolved per
    request so the composition root can wire the container lazily."""
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
        session = session_signer().verify(session_cookie)
        if session is None:
            # No valid session — start the flow again.
            return RedirectResponse(url="/login", status_code=303)

        if not secrets.compare_digest(csrf_token, session.csrf_token):
            raise InvalidRequest("CSRF token mismatch")

        target_url = await consent().execute(
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
        return RedirectResponse(url=target_url, status_code=303)

    return router
