# coding: utf-8

from typing import ClassVar, Dict, List, Tuple  # noqa: F401

from pydantic import Field, StrictStr
from typing import Optional
from typing_extensions import Annotated
from openapi_server.models.error_response import ErrorResponse
from openapi_server.models.user_info_response import UserInfoResponse
from openapi_server.security_api import get_token_dpop, get_token_bearerAuth

class BaseOpenIDConnectApi:
    subclasses: ClassVar[Tuple] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        BaseOpenIDConnectApi.subclasses = BaseOpenIDConnectApi.subclasses + (cls,)
    async def userinfo_get(
        self,
        dpo_p: Annotated[Optional[StrictStr], Field(description="DPoP proof JWT (RFC 9449 §4). Required on `/token`, `/par`, protected resources, and `/userinfo` whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with `typ=dpop+jwt`, `alg`, `jwk` in the header and `jti`, `htm`, `htu`, `iat` claims (plus `ath` at resource servers and `nonce` when the AS issues a DPoP-Nonce challenge). ")],
    ) -> UserInfoResponse:
        """Returns claims about the authenticated end-user. Requires a valid OIDC access token in the &#x60;Authorization&#x60; header (Bearer or DPoP). When the response is &#x60;application/jwt&#x60; (signed/encrypted), the JWT also carries &#x60;iss&#x60; and &#x60;aud&#x60; claims (OIDC Core §5.3.2). """
        ...


    async def userinfo_post(
        self,
        dpo_p: Annotated[Optional[StrictStr], Field(description="DPoP proof JWT (RFC 9449 §4). Required on `/token`, `/par`, protected resources, and `/userinfo` whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with `typ=dpop+jwt`, `alg`, `jwk` in the header and `jti`, `htm`, `htu`, `iat` claims (plus `ath` at resource servers and `nonce` when the AS issues a DPoP-Nonce challenge). ")],
    ) -> UserInfoResponse:
        """Same semantics as GET; some clients prefer POST per OIDC Core §5.3.1. Either &#x60;application/x-www-form-urlencoded&#x60; (with &#x60;access_token&#x60; form field) or an Authorization header. """
        ...
