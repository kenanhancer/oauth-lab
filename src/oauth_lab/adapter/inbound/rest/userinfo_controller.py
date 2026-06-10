"""`GET /userinfo` — OIDC Core § 5.3.

Pure adapter: extracts the Bearer token from the Authorization header,
calls `GetUserInfoUseCase`, and serialises the result. Token
verification and the scope→claims policy live in the application layer.

A missing/malformed Authorization header is handled here — RFC 6750 §3
says a request with no usable token gets a bare `WWW-Authenticate:
Bearer` challenge (no error attribute); that is transport-level parsing,
not business logic. Invalid tokens raise `InvalidToken` from the use
case and render via the shared OAuthError exception handler.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse

from oauth_lab.application.port.inbound.get_user_info_use_case import GetUserInfoUseCase
from oauth_lab.container import Container

router = APIRouter()


def _container(request: Request) -> Container:
    return request.app.state.container                                              # type: ignore[no-any-return]


def _use_case(container: Annotated[Container, Depends(_container)]) -> GetUserInfoUseCase:
    return container.get_user_info

# OIDC Core § 5.3 returns user claims — never cache them (they are
# per-token, potentially sensitive PII).
_NO_STORE_HEADERS = {"Cache-Control": "no-store"}


@router.get("/userinfo", tags=["OIDC"])
async def userinfo(
    *,
    use_case: Annotated[GetUserInfoUseCase, Depends(_use_case)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> JSONResponse:
    if not authorization or not authorization.lower().startswith("bearer "):
        return JSONResponse(
            content={"error": "invalid_token", "error_description": "Bearer token required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="oauth-lab"'},
        )
    token = authorization[len("Bearer ") :].strip()

    result = await use_case.execute(token)

    body: dict[str, object] = {"sub": result.sub}
    if result.preferred_username is not None:
        body["preferred_username"] = result.preferred_username
    if result.email is not None:
        body["email"] = result.email
        body["email_verified"] = result.email_verified
    return JSONResponse(content=body, headers=_NO_STORE_HEADERS)
