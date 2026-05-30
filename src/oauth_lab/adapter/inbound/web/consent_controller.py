"""`POST /consent` — user clicks Approve / Deny.

Requires a valid session cookie. Re-validates everything via
`ConsentUseCase` (the consent form's hidden fields are user-controllable
— never trust them blindly).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response

from oauth_lab.adapter.inbound.web.authorize_controller import SESSION_COOKIE_NAME
from oauth_lab.application.port.inbound.consent_use_case import ConsentUseCase
from oauth_lab.application.port.outbound.session_signer import SessionSigner
from oauth_lab.application.service.consent_service import ConsentDecision
from oauth_lab.container import Container

router = APIRouter()


def _container(request: Request) -> Container:
    return request.app.state.container                                              # type: ignore[no-any-return]


def _use_case(container: Annotated[Container, Depends(_container)]) -> ConsentUseCase:
    return container.consent


def _session_signer(container: Annotated[Container, Depends(_container)]) -> SessionSigner:
    return container.session_signer


@router.post("/consent", tags=["Browser"])
async def consent_submit(
    *,
    use_case: Annotated[ConsentUseCase, Depends(_use_case)],
    signer: Annotated[SessionSigner, Depends(_session_signer)],
    session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
    decision: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    scope: Annotated[str | None, Form()] = None,
    state: Annotated[str | None, Form()] = None,
    code_challenge: Annotated[str, Form()] = "",
    code_challenge_method: Annotated[str, Form()] = "S256",
) -> Response:
    session = signer.verify(session_cookie)
    if session is None:
        # No valid session — start the flow again.
        return RedirectResponse(url="/login", status_code=303)

    target_url = await use_case.execute(
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
