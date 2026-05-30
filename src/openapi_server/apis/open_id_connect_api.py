# coding: utf-8

from typing import Dict, List  # noqa: F401
import importlib
import pkgutil

from openapi_server.apis.open_id_connect_api_base import BaseOpenIDConnectApi
import openapi_server.impl

from fastapi import (  # noqa: F401
    APIRouter,
    Body,
    Cookie,
    Depends,
    Form,
    Header,
    HTTPException,
    Path,
    Query,
    Response,
    Security,
    status,
)

from openapi_server.models.extra_models import TokenModel  # noqa: F401
from pydantic import Field, StrictStr
from typing import Optional
from typing_extensions import Annotated
from openapi_server.models.error_response import ErrorResponse
from openapi_server.models.user_info_response import UserInfoResponse
from openapi_server.security_api import get_token_dpop, get_token_bearerAuth

router = APIRouter()

ns_pkg = openapi_server.impl
for _, name, _ in pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + "."):
    importlib.import_module(name)


@router.get(
    "/userinfo",
    responses={
        200: {"model": UserInfoResponse, "description": "UserInfo claims"},
        401: {"model": ErrorResponse, "description": "Resource-server error per RFC 6750 §3 — includes a Bearer challenge in the WWW-Authenticate header. "},
        403: {"model": ErrorResponse, "description": "Resource-server error per RFC 6750 §3 — includes a Bearer challenge in the WWW-Authenticate header. "},
    },
    tags=["OpenID Connect"],
    summary="UserInfo endpoint (GET, OIDC)",
    response_model_by_alias=True,
)
async def userinfo_get(
    dpo_p: Annotated[Optional[StrictStr], Field(description="DPoP proof JWT (RFC 9449 §4). Required on `/token`, `/par`, protected resources, and `/userinfo` whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with `typ=dpop+jwt`, `alg`, `jwk` in the header and `jti`, `htm`, `htu`, `iat` claims (plus `ath` at resource servers and `nonce` when the AS issues a DPoP-Nonce challenge). ")] = Header(None, description="DPoP proof JWT (RFC 9449 §4). Required on &#x60;/token&#x60;, &#x60;/par&#x60;, protected resources, and &#x60;/userinfo&#x60; whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with &#x60;typ&#x3D;dpop+jwt&#x60;, &#x60;alg&#x60;, &#x60;jwk&#x60; in the header and &#x60;jti&#x60;, &#x60;htm&#x60;, &#x60;htu&#x60;, &#x60;iat&#x60; claims (plus &#x60;ath&#x60; at resource servers and &#x60;nonce&#x60; when the AS issues a DPoP-Nonce challenge). "),
    token_dpop: TokenModel = Security(
        get_token_dpop
    ),
    token_bearerAuth: TokenModel = Security(
        get_token_bearerAuth
    ),
) -> UserInfoResponse:
    """Returns claims about the authenticated end-user. Requires a valid OIDC access token in the &#x60;Authorization&#x60; header (Bearer or DPoP). When the response is &#x60;application/jwt&#x60; (signed/encrypted), the JWT also carries &#x60;iss&#x60; and &#x60;aud&#x60; claims (OIDC Core §5.3.2). """
    if not BaseOpenIDConnectApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseOpenIDConnectApi.subclasses[0]().userinfo_get(dpo_p)


@router.post(
    "/userinfo",
    responses={
        200: {"model": UserInfoResponse, "description": "UserInfo claims"},
        401: {"model": ErrorResponse, "description": "Resource-server error per RFC 6750 §3 — includes a Bearer challenge in the WWW-Authenticate header. "},
        403: {"model": ErrorResponse, "description": "Resource-server error per RFC 6750 §3 — includes a Bearer challenge in the WWW-Authenticate header. "},
    },
    tags=["OpenID Connect"],
    summary="UserInfo endpoint (POST, OIDC)",
    response_model_by_alias=True,
)
async def userinfo_post(
    dpo_p: Annotated[Optional[StrictStr], Field(description="DPoP proof JWT (RFC 9449 §4). Required on `/token`, `/par`, protected resources, and `/userinfo` whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with `typ=dpop+jwt`, `alg`, `jwk` in the header and `jti`, `htm`, `htu`, `iat` claims (plus `ath` at resource servers and `nonce` when the AS issues a DPoP-Nonce challenge). ")] = Header(None, description="DPoP proof JWT (RFC 9449 §4). Required on &#x60;/token&#x60;, &#x60;/par&#x60;, protected resources, and &#x60;/userinfo&#x60; whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with &#x60;typ&#x3D;dpop+jwt&#x60;, &#x60;alg&#x60;, &#x60;jwk&#x60; in the header and &#x60;jti&#x60;, &#x60;htm&#x60;, &#x60;htu&#x60;, &#x60;iat&#x60; claims (plus &#x60;ath&#x60; at resource servers and &#x60;nonce&#x60; when the AS issues a DPoP-Nonce challenge). "),
    token_dpop: TokenModel = Security(
        get_token_dpop
    ),
    token_bearerAuth: TokenModel = Security(
        get_token_bearerAuth
    ),
) -> UserInfoResponse:
    """Same semantics as GET; some clients prefer POST per OIDC Core §5.3.1. Either &#x60;application/x-www-form-urlencoded&#x60; (with &#x60;access_token&#x60; form field) or an Authorization header. """
    if not BaseOpenIDConnectApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseOpenIDConnectApi.subclasses[0]().userinfo_post(dpo_p)
