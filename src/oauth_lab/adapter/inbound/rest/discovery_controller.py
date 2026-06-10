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

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from oauth_lab.application.port.inbound.get_server_metadata_use_case import (
    GetServerMetadataUseCase,
)
from oauth_lab.container import Container

router = APIRouter()


def _container(request: Request) -> Container:
    return request.app.state.container                                              # type: ignore[no-any-return]


def _use_case(container: Annotated[Container, Depends(_container)]) -> GetServerMetadataUseCase:
    return container.server_metadata


@router.get("/.well-known/oauth-authorization-server", tags=["Discovery"])
async def oauth_authorization_server(
    use_case: Annotated[GetServerMetadataUseCase, Depends(_use_case)],
) -> JSONResponse:
    """RFC 8414 OAuth 2.0 Authorization Server Metadata."""
    return JSONResponse(content=use_case.oauth_metadata())


@router.get("/.well-known/openid-configuration", tags=["Discovery"])
async def openid_configuration(
    use_case: Annotated[GetServerMetadataUseCase, Depends(_use_case)],
) -> JSONResponse:
    """OIDC Discovery 1.0 — same as RFC 8414 plus OIDC-specific entries."""
    return JSONResponse(content=use_case.openid_metadata())
