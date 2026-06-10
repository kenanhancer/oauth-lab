"""`GET /jwks` — public keys for verifying JWT access + id tokens (RFC 7517)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from oauth_lab.application.port.outbound.jwks_provider import JwksProvider

# RFC 7517 §8.5 registers `application/jwk-set+json` as the media type for a
# JWK Set. We serve it by default, but fall back to plain `application/json`
# for clients that ask for json yet don't list the JWK-Set type (many JWKS
# fetchers send `Accept: application/json` and choke on an unknown subtype).
_JWK_SET_MEDIA_TYPE = "application/jwk-set+json"
_JSON_MEDIA_TYPE = "application/json"


def build_router(*, jwks: Callable[[], JwksProvider]) -> APIRouter:
    """Mount `GET /jwks`. `jwks` is a provider resolved per request so the
    composition root can wire the container lazily."""
    router = APIRouter()

    @router.get("/jwks", tags=["Discovery"])
    async def jwks_document(
        accept: Annotated[str | None, Header(alias="Accept")] = None,
    ) -> JSONResponse:
        accepts = (accept or "").lower()
        if _JWK_SET_MEDIA_TYPE not in accepts and _JSON_MEDIA_TYPE in accepts:
            media_type = _JSON_MEDIA_TYPE
        else:
            media_type = _JWK_SET_MEDIA_TYPE
        return JSONResponse(
            content=jwks().to_dict(),
            media_type=media_type,
            headers={"Cache-Control": "public, max-age=3600"},
        )

    return router
