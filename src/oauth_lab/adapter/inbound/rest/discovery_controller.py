"""Discovery endpoints — RFC 8414 + OIDC Discovery 1.0.

Two `.well-known` documents:

- `/.well-known/oauth-authorization-server` (RFC 8414) — describes the AS
  capabilities for any OAuth client.
- `/.well-known/openid-configuration` (OIDC Discovery 1.0) — superset that
  adds OIDC-specific fields (`userinfo_endpoint`, `id_token_signing_alg_values_supported`,
  `subject_types_supported`).

Pure adapter: the documents are assembled by `GetServerMetadataUseCase`,
which introspects the grant registry and client-auth pipeline; this
module only serialises them.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from oauth_lab.application.port.inbound.get_server_metadata_use_case import (
    GetServerMetadataUseCase,
)


def build_router(*, server_metadata: Callable[[], GetServerMetadataUseCase]) -> APIRouter:
    """Mount the two `.well-known` endpoints. `server_metadata` is a provider
    resolved per request so the composition root can wire the container lazily."""
    router = APIRouter()

    @router.get("/.well-known/oauth-authorization-server", tags=["Discovery"])
    async def oauth_authorization_server() -> JSONResponse:
        """RFC 8414 OAuth 2.0 Authorization Server Metadata."""
        return JSONResponse(content=server_metadata().oauth_metadata())

    @router.get("/.well-known/openid-configuration", tags=["Discovery"])
    async def openid_configuration() -> JSONResponse:
        """OIDC Discovery 1.0 — same as RFC 8414 plus OIDC-specific entries."""
        return JSONResponse(content=server_metadata().openid_metadata())

    return router
