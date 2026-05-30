# coding: utf-8

from typing import Dict, List  # noqa: F401
import importlib
import pkgutil

from openapi_server.apis.par_api_base import BasePARApi
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
from typing import Any, List, Optional
from typing_extensions import Annotated
from openapi_server.models.error_response import ErrorResponse
from openapi_server.models.par_response import PARResponse
from openapi_server.security_api import get_token_clientAssertion, get_token_clientSecretBasic, get_token_none, get_token_clientSecretPost

router = APIRouter()

ns_pkg = openapi_server.impl
for _, name, _ in pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + "."):
    importlib.import_module(name)


@router.post(
    "/par",
    responses={
        201: {"model": PARResponse, "description": "Pushed authorization request accepted."},
        400: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
        401: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
        405: {"description": "Method Not Allowed (RFC 9126 §2.3) — only POST is permitted."},
        413: {"description": "Payload Too Large (RFC 9126 §2.3) — request exceeds AS-defined limit."},
        429: {"description": "Too Many Requests (RFC 9126 §2.3) — rate limit exceeded."},
    },
    tags=["PAR"],
    summary="Pushed Authorization Request (RFC 9126)",
    response_model_by_alias=True,
)
async def pushed_authorization_request(
    client_id: StrictStr = Form(None, description=""),
    response_type: StrictStr = Form(None, description=""),
    code_challenge: Annotated[str, Field(min_length=43, strict=True, max_length=128)] = Form(None, description="", regex=r"/^[A-Za-z0-9._~-]+$/", min_length=43, max_length=128),
    code_challenge_method: StrictStr = Form(S256, description=""),
    dpo_p: Annotated[Optional[StrictStr], Field(description="DPoP proof JWT (RFC 9449 §4). Required on `/token`, `/par`, protected resources, and `/userinfo` whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with `typ=dpop+jwt`, `alg`, `jwk` in the header and `jti`, `htm`, `htu`, `iat` claims (plus `ath` at resource servers and `nonce` when the AS issues a DPoP-Nonce challenge). ")] = Header(None, description="DPoP proof JWT (RFC 9449 §4). Required on &#x60;/token&#x60;, &#x60;/par&#x60;, protected resources, and &#x60;/userinfo&#x60; whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with &#x60;typ&#x3D;dpop+jwt&#x60;, &#x60;alg&#x60;, &#x60;jwk&#x60; in the header and &#x60;jti&#x60;, &#x60;htm&#x60;, &#x60;htu&#x60;, &#x60;iat&#x60; claims (plus &#x60;ath&#x60; at resource servers and &#x60;nonce&#x60; when the AS issues a DPoP-Nonce challenge). "),
    client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")] = Form(None, description="Used with &#x60;client_id&#x60; for &#x60;client_secret_post&#x60; authentication. HTTP Basic (&#x60;client_secret_basic&#x60;) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. "),
    client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")] = Form(None, description="JWT bearing claims that authenticate the client. Used with &#x60;client_assertion_type&#x60; for &#x60;client_secret_jwt&#x60; or &#x60;private_key_jwt&#x60; authentication. RFC 7523 §2.2. "),
    client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")] = Form(None, description="RFC 7523 §2.2."),
    resource: Annotated[Optional[List[StrictStr]], Field(description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. ")] = Form(None, description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. "),
    redirect_uri: Optional[StrictStr] = Form(None, description=""),
    scope: Optional[StrictStr] = Form(None, description=""),
    state: Optional[StrictStr] = Form(None, description=""),
    nonce: Optional[StrictStr] = Form(None, description=""),
    prompt: Optional[StrictStr] = Form(None, description=""),
    login_hint: Optional[StrictStr] = Form(None, description=""),
    max_age: Optional[Annotated[int, Field(strict=True, ge=0)]] = Form(None, description="", ge=0),
    ui_locales: Optional[StrictStr] = Form(None, description=""),
    id_token_hint: Optional[StrictStr] = Form(None, description=""),
    acr_values: Optional[StrictStr] = Form(None, description=""),
    response_mode: Optional[StrictStr] = Form(None, description=""),
    display: Optional[StrictStr] = Form(None, description=""),
    claims: Annotated[Optional[StrictStr], Field(description="JSON-encoded claims request (OIDC Core §5.5).")] = Form(None, description="JSON-encoded claims request (OIDC Core §5.5)."),
    authorization_details: Annotated[Optional[StrictStr], Field(description="JSON-encoded array of AuthorizationDetail (RFC 9396).")] = Form(None, description="JSON-encoded array of AuthorizationDetail (RFC 9396)."),
    request: Annotated[Optional[StrictStr], Field(description="Optional signed JWT request object (JAR, RFC 9101 §5).")] = Form(None, description="Optional signed JWT request object (JAR, RFC 9101 §5)."),
    dpop_jkt: Annotated[Optional[StrictStr], Field(description="DPoP key thumbprint binding (RFC 9449 §10.1).")] = Form(None, description="DPoP key thumbprint binding (RFC 9449 §10.1)."),
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
) -> PARResponse:
    """Pushes the authorization request parameters to the server before the user-agent redirect. The server returns a short-lived &#x60;request_uri&#x60; that the client then passes (instead of the full request) to &#x60;/authorize&#x60;. This avoids leaking parameters via browser history, keeps URLs short, and enables integrity protection.  Per §2.1, the request body MUST NOT contain a &#x60;request_uri&#x60; parameter. Per §4, when &#x60;/authorize&#x60; is reached via a PAR-issued &#x60;request_uri&#x60;, only &#x60;client_id&#x60; and &#x60;request_uri&#x60; are sent — all other parameters come from the pushed body. """
    if not BasePARApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BasePARApi.subclasses[0]().pushed_authorization_request(client_id, response_type, code_challenge, code_challenge_method, dpo_p, client_secret, client_assertion, client_assertion_type, resource, redirect_uri, scope, state, nonce, prompt, login_hint, max_age, ui_locales, id_token_hint, acr_values, response_mode, display, claims, authorization_details, request, dpop_jkt)
