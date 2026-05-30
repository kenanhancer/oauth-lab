"""Discovery endpoints — RFC 8414 + OIDC Discovery 1.0.

Two `.well-known` documents:

- `/.well-known/oauth-authorization-server` (RFC 8414) — describes the AS
  capabilities for any OAuth client.
- `/.well-known/openid-configuration` (OIDC Discovery 1.0) — superset that
  adds OIDC-specific fields (`userinfo_endpoint`, `id_token_signing_alg_values_supported`,
  `subject_types_supported`).

Values are derived from `settings.issuer` and the static set of grants,
auth methods, and scopes we support. A real implementation would
introspect the `GrantRegistry` and `ClientCredentialsPipeline` to derive
the lists; for `oauth-lab` we hard-code them.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from oauth_lab.container import Container

router = APIRouter()


def _base_metadata(container: Container) -> dict[str, object]:
    issuer = container.settings.issuer.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "response_types_supported": ["code"],                                     # OAuth 2.1
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
        ],
        "code_challenge_methods_supported": ["S256"],                             # plain is rejected
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "scopes_supported": ["openid", "profile", "email", "read", "write"],
    }


@router.get("/.well-known/oauth-authorization-server", tags=["Discovery"])
async def oauth_authorization_server(request: Request) -> JSONResponse:
    """RFC 8414 OAuth 2.0 Authorization Server Metadata."""
    container: Container = request.app.state.container
    return JSONResponse(content=_base_metadata(container))


@router.get("/.well-known/openid-configuration", tags=["Discovery"])
async def openid_configuration(request: Request) -> JSONResponse:
    """OIDC Discovery 1.0 — same as RFC 8414 plus OIDC-specific entries."""
    container: Container = request.app.state.container
    issuer = container.settings.issuer.rstrip("/")
    metadata = _base_metadata(container)
    metadata.update(
        {
            "userinfo_endpoint": f"{issuer}/userinfo",
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [container.settings.jwt_algorithm],
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "nonce",
                "at_hash",
                "preferred_username",
                "email",
                "email_verified",
            ],
        }
    )
    return JSONResponse(content=metadata)
