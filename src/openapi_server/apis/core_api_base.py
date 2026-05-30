# coding: utf-8

from typing import ClassVar, Dict, List, Tuple  # noqa: F401

from pydantic import Field, StrictStr, field_validator
from typing import Any, List, Optional
from typing_extensions import Annotated
from openapi_server.models.error_response import ErrorResponse
from openapi_server.models.token_response import TokenResponse
from openapi_server.models.token_type_uri import TokenTypeURI
from openapi_server.security_api import get_token_clientAssertion, get_token_clientSecretBasic, get_token_none, get_token_clientSecretPost

class BaseCoreApi:
    subclasses: ClassVar[Tuple] = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        BaseCoreApi.subclasses = BaseCoreApi.subclasses + (cls,)
    async def authorize(
        self,
        response_type: Annotated[StrictStr, Field(description="OAuth 2.1 §10.1 permits only `code` (the Authorization Code grant). OIDC Core §3.1.2.1 also defines `id_token` and `code id_token` for OIDC Hybrid Flow. The hybrid front-channel-token variants `code token` and `code id_token token` are intentionally excluded per OAuth 2.1 / RFC 9700 §2.1.2 because front-channel access tokens are insecure (browser history leakage). ")],
        client_id: Annotated[StrictStr, Field(description="The client identifier issued at registration time (RFC 6749 §2.2).")],
        code_challenge: Annotated[str, Field(min_length=43, strict=True, max_length=128, description="PKCE challenge — `BASE64URL(SHA256(code_verifier))` for the `S256` method. 43-128 characters from the unreserved set `[A-Z] / [a-z] / [0-9] / \"-\" / \".\" / \"_\" / \"~\"`. **Mandatory in OAuth 2.1 for all clients.** RFC 7636 §4.2. ")],
        code_challenge_method: Annotated[StrictStr, Field(description="Always `S256` per OAuth 2.1 §4.8 and RFC 9700 §4.8. The legacy `plain` method (RFC 7636 §4.4) is intentionally omitted; clients and servers compliant with OAuth 2.1 MUST use S256 only. ")],
        redirect_uri: Annotated[Optional[StrictStr], Field(description="Where the user-agent is redirected after authorization. Per OAuth 2.1 §2.3.1 and RFC 9700 §4.1.3, the AS MUST compare against registered URIs **using exact-string matching**, not pattern matching. REQUIRED when the client has more than one registered redirect URI; OPTIONAL otherwise. Per RFC 6749 §4.1.2.1, when invalid, the AS MUST NOT redirect — it returns an HTML error page (modeled as the 400 response on `/authorize`). ")],
        scope: Annotated[Optional[Annotated[str, Field(strict=True)]], Field(description="Space-delimited list of scopes. For OIDC, MUST include `openid` to request an ID token. Standard OIDC scopes: `profile`, `email`, `address`, `phone`, `offline_access`. Per RFC 6749 §3.3 ABNF, each scope token is `1*( %x21 / %x23-5B / %x5D-7E )` — printable ASCII excluding `\"` and `\\`; tokens are separated by single SP characters. ")],
        state: Annotated[Optional[StrictStr], Field(description="Opaque value used by the client to maintain state and prevent CSRF. The server returns it unchanged in the redirect. RFC 6749 §10.12. ")],
        nonce: Annotated[Optional[StrictStr], Field(description="OIDC: opaque random value bound to the ID token's `nonce` claim, for replay protection. OIDC Core §3.1.2.1. ")],
        prompt: Annotated[Optional[StrictStr], Field(description="OIDC: how the auth server should prompt the user. Space-delimited. ")],
        login_hint: Annotated[Optional[StrictStr], Field(description="OIDC: hint to the auth server about the login identifier (e.g. e-mail).")],
        max_age: Annotated[Optional[Annotated[int, Field(strict=True, ge=0)]], Field(description="OIDC: maximum allowed elapsed time since last authentication, in seconds.")],
        acr_values: Annotated[Optional[StrictStr], Field(description="OIDC: requested Authentication Context Class Reference values, space-separated.")],
        response_mode: Annotated[Optional[StrictStr], Field(description="Mechanism for delivering the authorization response. `query`, `fragment`, `form_post` (OAuth 2.0 Form Post Response Mode). ")],
        request_uri: Annotated[Optional[StrictStr], Field(description="Reference to a request previously submitted via PAR (RFC 9126 §4). When present, takes precedence over individual query parameters. ")],
        authorization_details: Annotated[Optional[StrictStr], Field(description="Rich Authorization Requests (RAR) — JSON-encoded array of authorization detail objects. RFC 9396. ")],
        resource: Annotated[Optional[List[StrictStr]], Field(description="Indicator of the protected resource(s) for which authorization is requested. MUST be an absolute URI without a fragment component. MAY appear multiple times to request audience for multiple resources. RFC 8707 §2. ")],
        display: Annotated[Optional[StrictStr], Field(description="OIDC: how the AS should display the authentication and consent UI. OIDC Core §3.1.2.1. Mandatory-to-implement (§15.1). ")],
        ui_locales: Annotated[Optional[StrictStr], Field(description="OIDC: end-user UI language(s), space-separated BCP47 tags (e.g. `fr-CA fr en`). Mandatory-to-implement (§15.1). ")],
        claims_locales: Annotated[Optional[StrictStr], Field(description="OIDC: preferred languages for Claims being returned, space-separated BCP47 tags. OIDC Core §5.2. Mandatory-to-implement (§15.1). ")],
        id_token_hint: Annotated[Optional[StrictStr], Field(description="OIDC: previously issued ID Token passed as a hint about the user's current or past authenticated session. OIDC Core §3.1.2.1. ")],
        claims: Annotated[Optional[StrictStr], Field(description="OIDC: JSON-encoded object describing specific Claims being requested for delivery in the ID Token and/or UserInfo response. OIDC Core §5.5. ")],
        request: Annotated[Optional[StrictStr], Field(description="OIDC / RFC 9101 (JAR): a self-contained JWT containing the full authorization request as claims. Mutually exclusive with `request_uri`. OIDC Core §6. ")],
        dpop_jkt: Annotated[Optional[StrictStr], Field(description="DPoP key thumbprint to bind the resulting authorization code to a specific DPoP key, even before the token request. RFC 9449 §10.1. ")],
    ) -> str:
        """Initiates a browser-driven authorization request. The user-agent is navigated to this URL; the server authenticates the resource owner and obtains consent, then redirects the user-agent back to &#x60;redirect_uri&#x60; with a &#x60;code&#x60; (success) or an &#x60;error&#x60;.  Under OAuth 2.1 only &#x60;response_type&#x3D;code&#x60; is permitted (Implicit is deprecated). PKCE (&#x60;code_challenge&#x60;) is mandatory. """
        ...


    async def token(
        self,
        dpo_p: Annotated[Optional[StrictStr], Field(description="DPoP proof JWT (RFC 9449 §4). Required on `/token`, `/par`, protected resources, and `/userinfo` whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with `typ=dpop+jwt`, `alg`, `jwk` in the header and `jti`, `htm`, `htu`, `iat` claims (plus `ath` at resource servers and `nonce` when the AS issues a DPoP-Nonce challenge). ")],
        client_id: Annotated[Optional[StrictStr], Field(description="REQUIRED for public clients (no client secret) and clients that authenticate via `client_assertion`. RFC 6749 §3.2.1. ")],
        client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")],
        client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")],
        client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")],
        resource: Annotated[Optional[List[StrictStr]], Field(description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. ")],
        grant_type: Optional[StrictStr],
        code: Annotated[Optional[StrictStr], Field(description="The authorization code received from `/authorize`.")],
        redirect_uri: Annotated[Optional[StrictStr], Field(description="OPTIONAL under OAuth 2.1 §10.2 (was REQUIRED in OAuth 2.0 §4.1.3). When present, MUST match the `redirect_uri` used at `/authorize`. Some legacy AS implementations still require it. ")],
        code_verifier: Annotated[Optional[Annotated[str, Field(min_length=43, strict=True, max_length=128)]], Field(description="PKCE verifier (RFC 7636 §4.1). 43-128 chars from the unreserved set `[A-Z] / [a-z] / [0-9] / \\\"-\\\" / \\\".\\\" / \\\"_\\\" / \\\"~\\\"`. ")],
        authorization_details: Annotated[Optional[StrictStr], Field(description="JSON-encoded array of `AuthorizationDetail` objects (RFC 9396 §5). Sent as a string because the form-encoded body cannot carry structured JSON natively. The decoded value conforms to `AuthorizationDetail[]`. ")],
        scope: Optional[StrictStr],
        audience: Annotated[Optional[List[StrictStr]], Field(description="RFC 8693-defined parameter (distinct from RFC 8707 `resource`). Logical name(s) of the target service(s). MAY appear multiple times in the form body — modeled here as array. ")],
        refresh_token: Optional[StrictStr],
        device_code: Annotated[Optional[StrictStr], Field(description="The opaque `device_code` from `/device_authorization`. MUST NOT be displayed to the end user. ")],
        assertion: Annotated[Optional[StrictStr], Field(description="Signed JWT bearer assertion. REQUIRED claims (RFC 7523 §3): `iss`, `sub`, `aud` (the AS token endpoint URL), `exp`. RECOMMENDED: `nbf`, `iat`, `jti`. The JWT MUST be digitally signed or MAC'd by the issuer and MUST be rejected by the AS if any required claim is missing or invalid. ")],
        subject_token: Annotated[Optional[StrictStr], Field(description="Token representing the identity of the party on whose behalf the request is made.")],
        subject_token_type: Optional[TokenTypeURI],
        actor_token: Annotated[Optional[StrictStr], Field(description="Token representing the identity of the acting party (delegation/impersonation).")],
        actor_token_type: Annotated[Optional[TokenTypeURI], Field(description="REQUIRED when `actor_token` is present.")],
        requested_token_type: Annotated[Optional[TokenTypeURI], Field(description="Type of token the client is requesting be issued.")],
    ) -> TokenResponse:
        """Issues access tokens. The &#x60;grant_type&#x60; form field selects the grant. All grants supported by OAuth 2.1 are modeled here:  - &#x60;authorization_code&#x60; — RFC 6749 §4.1.3 (with PKCE per RFC 7636) - &#x60;client_credentials&#x60; — RFC 6749 §4.4 - &#x60;refresh_token&#x60; — RFC 6749 §6 - &#x60;urn:ietf:params:oauth:grant-type:device_code&#x60; — RFC 8628 §3.4 - &#x60;urn:ietf:params:oauth:grant-type:jwt-bearer&#x60; — RFC 7523 - &#x60;urn:ietf:params:oauth:grant-type:token-exchange&#x60; — RFC 8693  The deprecated &#x60;password&#x60; and &#x60;implicit&#x60; grants are intentionally omitted (per OAuth 2.1). """
        ...
