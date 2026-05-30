# coding: utf-8

from typing import ClassVar, Dict, List, Tuple  # noqa: F401

from pydantic import Field, StrictStr, field_validator
from typing import Any, Optional
from typing_extensions import Annotated
from openapi_server.models.error_response import ErrorResponse
from openapi_server.models.introspection_response import IntrospectionResponse
from openapi_server.security_api import get_token_clientAssertion, get_token_clientSecretBasic, get_token_none, get_token_bearerAuth, get_token_clientSecretPost

class BaseTokenLifecycleApi:
    subclasses: ClassVar[Tuple] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        BaseTokenLifecycleApi.subclasses = BaseTokenLifecycleApi.subclasses + (cls,)
    async def introspect(
        self,
        token: Annotated[StrictStr, Field(description="The token to introspect (access or refresh token).")],
        client_id: Annotated[Optional[StrictStr], Field(description="REQUIRED for public clients (no client secret) and clients that authenticate via `client_assertion`. RFC 6749 §3.2.1. ")],
        client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")],
        client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")],
        client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")],
        token_type_hint: Annotated[Optional[StrictStr], Field(description="Hint to the AS about the type of token being introspected. Values come from the IANA OAuth Token Type Hint registry (RFC 7009 §4.1.2); the schema is kept open rather than a closed enum so future registrations work without spec churn. ")],
    ) -> IntrospectionResponse:
        """A protected resource queries the authorization server about the meta-information of a token (active state, scopes, expiry, subject). Critical for opaque (non-JWT) tokens. JWT tokens can usually be validated locally by verifying the signature against the JWKS. """
        ...


    async def revoke(
        self,
        token: Annotated[StrictStr, Field(description="The token (access or refresh) to revoke.")],
        client_id: Annotated[Optional[StrictStr], Field(description="REQUIRED for public clients (no client secret) and clients that authenticate via `client_assertion`. RFC 6749 §3.2.1. ")],
        client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")],
        client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")],
        client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")],
        token_type_hint: Annotated[Optional[StrictStr], Field(description="Hint to the AS about the token type. Open per IANA OAuth Token Type Hint registry (RFC 7009 §4.1.2). ")],
    ) -> None:
        """Revokes an access or refresh token before its natural expiry. Per RFC 7009 §2.1, when a refresh token is revoked the AS SHOULD also invalidate all access tokens issued under the same authorization grant. (Cascade is from refresh → access; not the other direction.) A successful revocation always returns HTTP 200 with an empty body — even when the token is unknown to the server. """
        ...
