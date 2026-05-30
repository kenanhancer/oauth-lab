"""`GET /jwks` — public keys for verifying JWT access + id tokens (RFC 7517)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from oauth_lab.container import Container

router = APIRouter()


@router.get("/jwks", tags=["Discovery"])
async def jwks(request: Request) -> JSONResponse:
    container: Container = request.app.state.container
    return JSONResponse(
        content=container.jwks.to_dict(),
        headers={"Cache-Control": "public, max-age=3600"},
    )
