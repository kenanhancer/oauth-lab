# coding: utf-8

from typing import ClassVar, Dict, List, Tuple  # noqa: F401

from pydantic import Field, StrictStr, field_validator
from typing import Any, List, Optional
from typing_extensions import Annotated
from openapi_server.models.error_response import ErrorResponse
from openapi_server.models.par_response import PARResponse
from openapi_server.security_api import get_token_clientAssertion, get_token_clientSecretBasic, get_token_none, get_token_clientSecretPost

class BasePARApi:
    subclasses: ClassVar[Tuple] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        BasePARApi.subclasses = BasePARApi.subclasses + (cls,)
    async def pushed_authorization_request(
        self,
        client_id: StrictStr,
        response_type: StrictStr,
        code_challenge: Annotated[str, Field(min_length=43, strict=True, max_length=128)],
        code_challenge_method: StrictStr,
        dpo_p: Annotated[Optional[StrictStr], Field(description="DPoP proof JWT (RFC 9449 §4). Required on `/token`, `/par`, protected resources, and `/userinfo` whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with `typ=dpop+jwt`, `alg`, `jwk` in the header and `jti`, `htm`, `htu`, `iat` claims (plus `ath` at resource servers and `nonce` when the AS issues a DPoP-Nonce challenge). ")],
        client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")],
        client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")],
        client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")],
        resource: Annotated[Optional[List[StrictStr]], Field(description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. ")],
        redirect_uri: Optional[StrictStr],
        scope: Optional[StrictStr],
        state: Optional[StrictStr],
        nonce: Optional[StrictStr],
        prompt: Optional[StrictStr],
        login_hint: Optional[StrictStr],
        max_age: Optional[Annotated[int, Field(strict=True, ge=0)]],
        ui_locales: Optional[StrictStr],
        id_token_hint: Optional[StrictStr],
        acr_values: Optional[StrictStr],
        response_mode: Optional[StrictStr],
        display: Optional[StrictStr],
        claims: Annotated[Optional[StrictStr], Field(description="JSON-encoded claims request (OIDC Core §5.5).")],
        authorization_details: Annotated[Optional[StrictStr], Field(description="JSON-encoded array of AuthorizationDetail (RFC 9396).")],
        request: Annotated[Optional[StrictStr], Field(description="Optional signed JWT request object (JAR, RFC 9101 §5).")],
        dpop_jkt: Annotated[Optional[StrictStr], Field(description="DPoP key thumbprint binding (RFC 9449 §10.1).")],
    ) -> PARResponse:
        """Pushes the authorization request parameters to the server before the user-agent redirect. The server returns a short-lived &#x60;request_uri&#x60; that the client then passes (instead of the full request) to &#x60;/authorize&#x60;. This avoids leaking parameters via browser history, keeps URLs short, and enables integrity protection.  Per §2.1, the request body MUST NOT contain a &#x60;request_uri&#x60; parameter. Per §4, when &#x60;/authorize&#x60; is reached via a PAR-issued &#x60;request_uri&#x60;, only &#x60;client_id&#x60; and &#x60;request_uri&#x60; are sent — all other parameters come from the pushed body. """
        ...
