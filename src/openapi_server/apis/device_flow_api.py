# coding: utf-8

from typing import Dict, List  # noqa: F401
import importlib
import pkgutil

from openapi_server.apis.device_flow_api_base import BaseDeviceFlowApi
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
from typing import List, Optional
from typing_extensions import Annotated
from openapi_server.models.device_authorization_response import DeviceAuthorizationResponse
from openapi_server.models.error_response import ErrorResponse
from openapi_server.security_api import get_token_clientAssertion, get_token_clientSecretBasic, get_token_none, get_token_clientSecretPost

router = APIRouter()

ns_pkg = openapi_server.impl
for _, name, _ in pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + "."):
    importlib.import_module(name)


@router.post(
    "/device_authorization",
    responses={
        200: {"model": DeviceAuthorizationResponse, "description": "Device authorization issued."},
        400: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
        401: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
    },
    tags=["Device Flow"],
    summary="Device Authorization Endpoint (RFC 8628)",
    response_model_by_alias=True,
)
async def device_authorization(
    client_id: StrictStr = Form(None, description=""),
    client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")] = Form(None, description="Used with &#x60;client_id&#x60; for &#x60;client_secret_post&#x60; authentication. HTTP Basic (&#x60;client_secret_basic&#x60;) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. "),
    client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")] = Form(None, description="JWT bearing claims that authenticate the client. Used with &#x60;client_assertion_type&#x60; for &#x60;client_secret_jwt&#x60; or &#x60;private_key_jwt&#x60; authentication. RFC 7523 §2.2. "),
    client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")] = Form(None, description="RFC 7523 §2.2."),
    resource: Annotated[Optional[List[StrictStr]], Field(description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. ")] = Form(None, description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. "),
    scope: Annotated[Optional[StrictStr], Field(description="Space-delimited list of requested scopes.")] = Form(None, description="Space-delimited list of requested scopes."),
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
) -> DeviceAuthorizationResponse:
    """Initiates the Device Authorization Grant. The client receives a &#x60;device_code&#x60; and &#x60;user_code&#x60;; the user is instructed to visit &#x60;verification_uri&#x60; on a second device and enter the &#x60;user_code&#x60;. The client then polls &#x60;/token&#x60; with &#x60;grant_type&#x3D;urn:ietf:params:oauth:grant-type:device_code&#x60; until the user authorizes or &#x60;expires_in&#x60; elapses.  Polling protocol (RFC 8628 §3.5): the AS may return &#x60;slow_down&#x60; to increase the polling interval by 5 seconds, or &#x60;authorization_pending&#x60; while the user is still consenting. Clients MUST stop polling on any non-pending error (&#x60;access_denied&#x60;, &#x60;expired_token&#x60;).  The &#x60;device_code&#x60; MUST NOT be displayed to the end user. The &#x60;user_code&#x60; is per §6.1 displayed to the user; servers SHOULD accept dashed and case-insensitive variants. """
    if not BaseDeviceFlowApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseDeviceFlowApi.subclasses[0]().device_authorization(client_id, client_secret, client_assertion, client_assertion_type, resource, scope)
