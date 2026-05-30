# coding: utf-8

from typing import Dict, List  # noqa: F401
import importlib
import pkgutil

from openapi_server.apis.token_lifecycle_api_base import BaseTokenLifecycleApi
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
from pydantic import Field, StrictStr, field_validator
from typing import Any, Optional
from typing_extensions import Annotated
from openapi_server.models.error_response import ErrorResponse
from openapi_server.models.introspection_response import IntrospectionResponse
from openapi_server.security_api import get_token_clientAssertion, get_token_clientSecretBasic, get_token_none, get_token_bearerAuth, get_token_clientSecretPost

router = APIRouter()

ns_pkg = openapi_server.impl
for _, name, _ in pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + "."):
    importlib.import_module(name)


@router.post(
    "/introspect",
    responses={
        200: {"model": IntrospectionResponse, "description": "Introspection result (always 200, even for inactive tokens)."},
        401: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
    },
    tags=["Token Lifecycle"],
    summary="Token introspection",
    response_model_by_alias=True,
)
async def introspect(
    token: Annotated[StrictStr, Field(description="The token to introspect (access or refresh token).")] = Form(None, description="The token to introspect (access or refresh token)."),
    client_id: Annotated[Optional[StrictStr], Field(description="REQUIRED for public clients (no client secret) and clients that authenticate via `client_assertion`. RFC 6749 §3.2.1. ")] = Form(None, description="REQUIRED for public clients (no client secret) and clients that authenticate via &#x60;client_assertion&#x60;. RFC 6749 §3.2.1. "),
    client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")] = Form(None, description="Used with &#x60;client_id&#x60; for &#x60;client_secret_post&#x60; authentication. HTTP Basic (&#x60;client_secret_basic&#x60;) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. "),
    client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")] = Form(None, description="JWT bearing claims that authenticate the client. Used with &#x60;client_assertion_type&#x60; for &#x60;client_secret_jwt&#x60; or &#x60;private_key_jwt&#x60; authentication. RFC 7523 §2.2. "),
    client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")] = Form(None, description="RFC 7523 §2.2."),
    token_type_hint: Annotated[Optional[StrictStr], Field(description="Hint to the AS about the type of token being introspected. Values come from the IANA OAuth Token Type Hint registry (RFC 7009 §4.1.2); the schema is kept open rather than a closed enum so future registrations work without spec churn. ")] = Form(None, description="Hint to the AS about the type of token being introspected. Values come from the IANA OAuth Token Type Hint registry (RFC 7009 §4.1.2); the schema is kept open rather than a closed enum so future registrations work without spec churn. "),
    token_clientAssertion: TokenModel = Security(
        get_token_clientAssertion
    ),
    token_clientSecretBasic: TokenModel = Security(
        get_token_clientSecretBasic
    ),
    token_bearerAuth: TokenModel = Security(
        get_token_bearerAuth
    ),
    token_clientSecretPost: TokenModel = Security(
        get_token_clientSecretPost
    ),
) -> IntrospectionResponse:
    """A protected resource queries the authorization server about the meta-information of a token (active state, scopes, expiry, subject). Critical for opaque (non-JWT) tokens. JWT tokens can usually be validated locally by verifying the signature against the JWKS. """
    if not BaseTokenLifecycleApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseTokenLifecycleApi.subclasses[0]().introspect(token, client_id, client_secret, client_assertion, client_assertion_type, token_type_hint)


@router.post(
    "/revoke",
    responses={
        200: {"description": "Revocation accepted (returned even if the token was unknown)."},
        400: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
        401: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
    },
    tags=["Token Lifecycle"],
    summary="Token revocation",
    response_model_by_alias=True,
)
async def revoke(
    token: Annotated[StrictStr, Field(description="The token (access or refresh) to revoke.")] = Form(None, description="The token (access or refresh) to revoke."),
    client_id: Annotated[Optional[StrictStr], Field(description="REQUIRED for public clients (no client secret) and clients that authenticate via `client_assertion`. RFC 6749 §3.2.1. ")] = Form(None, description="REQUIRED for public clients (no client secret) and clients that authenticate via &#x60;client_assertion&#x60;. RFC 6749 §3.2.1. "),
    client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")] = Form(None, description="Used with &#x60;client_id&#x60; for &#x60;client_secret_post&#x60; authentication. HTTP Basic (&#x60;client_secret_basic&#x60;) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. "),
    client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")] = Form(None, description="JWT bearing claims that authenticate the client. Used with &#x60;client_assertion_type&#x60; for &#x60;client_secret_jwt&#x60; or &#x60;private_key_jwt&#x60; authentication. RFC 7523 §2.2. "),
    client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")] = Form(None, description="RFC 7523 §2.2."),
    token_type_hint: Annotated[Optional[StrictStr], Field(description="Hint to the AS about the token type. Open per IANA OAuth Token Type Hint registry (RFC 7009 §4.1.2). ")] = Form(None, description="Hint to the AS about the token type. Open per IANA OAuth Token Type Hint registry (RFC 7009 §4.1.2). "),
    token_clientAssertion: TokenModel = Security(
        get_token_clientAssertion
    ),
    token_clientSecretBasic: TokenModel = Security(
        get_token_clientSecretBasic
    ),
    token_none: TokenModel = Security(
        get_token_none
    ),
    token_clientSecretPost: TokenModel = Security(
        get_token_clientSecretPost
    ),
) -> None:
    """Revokes an access or refresh token before its natural expiry. Per RFC 7009 §2.1, when a refresh token is revoked the AS SHOULD also invalidate all access tokens issued under the same authorization grant. (Cascade is from refresh → access; not the other direction.) A successful revocation always returns HTTP 200 with an empty body — even when the token is unknown to the server. """
    if not BaseTokenLifecycleApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseTokenLifecycleApi.subclasses[0]().revoke(token, client_id, client_secret, client_assertion, client_assertion_type, token_type_hint)
