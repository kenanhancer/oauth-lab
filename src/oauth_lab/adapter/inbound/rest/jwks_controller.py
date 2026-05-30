"""`GET /jwks` — public keys for verifying JWT access + id tokens (RFC 7517)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from oauth_lab.container import Container

router = APIRouter()

# RFC 7517 §8.5 registers `application/jwk-set+json` as the media type for a
# JWK Set. We serve it by default, but fall back to plain `application/json`
# for clients that ask for json yet don't list the JWK-Set type (many JWKS
# fetchers send `Accept: application/json` and choke on an unknown subtype).
_JWK_SET_MEDIA_TYPE = "application/jwk-set+json"
_JSON_MEDIA_TYPE = "application/json"


@router.get("/jwks", tags=["Discovery"])
async def jwks(
    request: Request,
    accept: Annotated[str | None, Header(alias="Accept")] = None,
) -> JSONResponse:
    container: Container = request.app.state.container
    accepts = (accept or "").lower()
    if _JWK_SET_MEDIA_TYPE not in accepts and _JSON_MEDIA_TYPE in accepts:
        media_type = _JSON_MEDIA_TYPE
    else:
        media_type = _JWK_SET_MEDIA_TYPE
    return JSONResponse(
        content=container.jwks.to_dict(),
        media_type=media_type,
        headers={"Cache-Control": "public, max-age=3600"},
    )
