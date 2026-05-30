"""`GET /userinfo` — OIDC Core § 5.3.

Accepts an OAuth Bearer access token (a JWT in our setup). Verifies the
JWT signature with our signing key, looks up the user by `sub`, and
returns standard OIDC claims based on the scopes the token was granted.

This endpoint only handles JWT access tokens. With opaque tokens you'd
introspect (RFC 7662) instead — that's a future addition.
"""

from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from oauth_lab.container import Container
from oauth_lab.domain.model.errors import InvalidClient

router = APIRouter()


@router.get("/userinfo", tags=["OIDC"])
async def userinfo(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> JSONResponse:
    container: Container = request.app.state.container
    if not authorization or not authorization.lower().startswith("bearer "):
        return JSONResponse(
            content={"error": "invalid_token", "error_description": "Bearer token required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="oauth-lab"'},
        )

    token = authorization[len("Bearer ") :].strip()
    try:
        claims = jwt.decode(
            token,
            container.jwks.public_pem(),
            algorithms=[container.settings.jwt_algorithm],
            options={"verify_aud": False},                            # we accept any audience here
        )
    except jwt.PyJWTError as exc:
        return JSONResponse(
            content={"error": "invalid_token", "error_description": str(exc)},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="oauth-lab", error="invalid_token"'},
        )

    sub = claims.get("sub")
    scope_str = claims.get("scope", "")
    scopes = set(scope_str.split()) if scope_str else set()

    if not isinstance(sub, str):
        raise InvalidClient("token has no `sub` claim")

    user = await container.users.find_by_sub(sub)
    if user is None:
        # Could be a client_credentials token (no user) — return what we know.
        return JSONResponse(content={"sub": sub})

    # Standard OIDC scopes → claim sets (OIDC Core § 5.4).
    response: dict[str, object] = {"sub": user.sub}
    if "profile" in scopes:
        response["preferred_username"] = user.username
    if "email" in scopes and user.email is not None:
        response["email"] = user.email
        response["email_verified"] = True                             # demo defaults

    return JSONResponse(content=response)
