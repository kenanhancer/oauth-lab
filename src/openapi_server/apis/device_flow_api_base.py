# coding: utf-8

from typing import ClassVar, Dict, List, Tuple  # noqa: F401

from pydantic import Field, StrictStr, field_validator
from typing import List, Optional
from typing_extensions import Annotated
from openapi_server.models.device_authorization_response import DeviceAuthorizationResponse
from openapi_server.models.error_response import ErrorResponse
from openapi_server.security_api import get_token_clientAssertion, get_token_clientSecretBasic, get_token_none, get_token_clientSecretPost

class BaseDeviceFlowApi:
    subclasses: ClassVar[Tuple] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        BaseDeviceFlowApi.subclasses = BaseDeviceFlowApi.subclasses + (cls,)
    async def device_authorization(
        self,
        client_id: StrictStr,
        client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")],
        client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")],
        client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")],
        resource: Annotated[Optional[List[StrictStr]], Field(description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. ")],
        scope: Annotated[Optional[StrictStr], Field(description="Space-delimited list of requested scopes.")],
    ) -> DeviceAuthorizationResponse:
        """Initiates the Device Authorization Grant. The client receives a &#x60;device_code&#x60; and &#x60;user_code&#x60;; the user is instructed to visit &#x60;verification_uri&#x60; on a second device and enter the &#x60;user_code&#x60;. The client then polls &#x60;/token&#x60; with &#x60;grant_type&#x3D;urn:ietf:params:oauth:grant-type:device_code&#x60; until the user authorizes or &#x60;expires_in&#x60; elapses.  Polling protocol (RFC 8628 §3.5): the AS may return &#x60;slow_down&#x60; to increase the polling interval by 5 seconds, or &#x60;authorization_pending&#x60; while the user is still consenting. Clients MUST stop polling on any non-pending error (&#x60;access_denied&#x60;, &#x60;expired_token&#x60;).  The &#x60;device_code&#x60; MUST NOT be displayed to the end user. The &#x60;user_code&#x60; is per §6.1 displayed to the user; servers SHOULD accept dashed and case-insensitive variants. """
        ...
