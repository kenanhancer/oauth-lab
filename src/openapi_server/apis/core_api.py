# coding: utf-8

from typing import Dict, List  # noqa: F401
import importlib
import pkgutil

from openapi_server.apis.core_api_base import BaseCoreApi
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
from openapi_server.models.token_response import TokenResponse
from openapi_server.models.token_type_uri import TokenTypeURI
from openapi_server.security_api import get_token_clientAssertion, get_token_clientSecretBasic, get_token_none, get_token_clientSecretPost

router = APIRouter()

ns_pkg = openapi_server.impl
for _, name, _ in pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + "."):
    importlib.import_module(name)


@router.get(
    "/authorize",
    responses={
        302: {"description": "User-agent redirect back to &#x60;redirect_uri&#x60;. The &#x60;Location&#x60; header carries: - on success: &#x60;code&#x60;, &#x60;state&#x60;, plus &#x60;iss&#x60; (RFC 9207) when the AS   advertises &#x60;authorization_response_iss_parameter_supported&#x60;.   For OIDC Hybrid (&#x60;response_type&#x3D;code id_token&#x60;) it also carries   &#x60;id_token&#x60; in the URL fragment. - on failure: &#x60;error&#x60;, &#x60;error_description&#x60;, &#x60;error_uri&#x60;, &#x60;state&#x60;,   plus &#x60;iss&#x60; per RFC 9207.  OAuth 2.1 §7.5.4 / RFC 9700 §4.11 RECOMMEND HTTP 303 over 302 and PROHIBIT 307; both are modeled as alternative status codes. "},
        303: {"description": "Same as 302; RECOMMENDED status code per OAuth 2.1 §7.5.4."},
        200: {"model": str, "description": "HTML consent or authentication page (intermediate state)"},
        400: {"model": str, "description": "Non-redirecting error. Per RFC 6749 §4.1.2.1, when &#x60;redirect_uri&#x60; is missing, malformed, or does not match a registered URI, the AS MUST NOT redirect to it; instead it returns an HTML error page. Also returned for malformed &#x60;client_id&#x60;. "},
    },
    tags=["Core"],
    summary="Authorization endpoint",
    response_model_by_alias=True,
)
async def authorize(
    response_type: Annotated[StrictStr, Field(description="OAuth 2.1 §10.1 permits only `code` (the Authorization Code grant). OIDC Core §3.1.2.1 also defines `id_token` and `code id_token` for OIDC Hybrid Flow. The hybrid front-channel-token variants `code token` and `code id_token token` are intentionally excluded per OAuth 2.1 / RFC 9700 §2.1.2 because front-channel access tokens are insecure (browser history leakage). ")] = Query(None, description="OAuth 2.1 §10.1 permits only &#x60;code&#x60; (the Authorization Code grant). OIDC Core §3.1.2.1 also defines &#x60;id_token&#x60; and &#x60;code id_token&#x60; for OIDC Hybrid Flow. The hybrid front-channel-token variants &#x60;code token&#x60; and &#x60;code id_token token&#x60; are intentionally excluded per OAuth 2.1 / RFC 9700 §2.1.2 because front-channel access tokens are insecure (browser history leakage). ", alias="response_type"),
    client_id: Annotated[StrictStr, Field(description="The client identifier issued at registration time (RFC 6749 §2.2).")] = Query(None, description="The client identifier issued at registration time (RFC 6749 §2.2).", alias="client_id"),
    code_challenge: Annotated[str, Field(min_length=43, strict=True, max_length=128, description="PKCE challenge — `BASE64URL(SHA256(code_verifier))` for the `S256` method. 43-128 characters from the unreserved set `[A-Z] / [a-z] / [0-9] / \"-\" / \".\" / \"_\" / \"~\"`. **Mandatory in OAuth 2.1 for all clients.** RFC 7636 §4.2. ")] = Query(None, description="PKCE challenge — &#x60;BASE64URL(SHA256(code_verifier))&#x60; for the &#x60;S256&#x60; method. 43-128 characters from the unreserved set &#x60;[A-Z] / [a-z] / [0-9] / \&quot;-\&quot; / \&quot;.\&quot; / \&quot;_\&quot; / \&quot;~\&quot;&#x60;. **Mandatory in OAuth 2.1 for all clients.** RFC 7636 §4.2. ", alias="code_challenge", regex=r"/^[A-Za-z0-9._~-]+$/", min_length=43, max_length=128),
    code_challenge_method: Annotated[StrictStr, Field(description="Always `S256` per OAuth 2.1 §4.8 and RFC 9700 §4.8. The legacy `plain` method (RFC 7636 §4.4) is intentionally omitted; clients and servers compliant with OAuth 2.1 MUST use S256 only. ")] = Query(S256, description="Always &#x60;S256&#x60; per OAuth 2.1 §4.8 and RFC 9700 §4.8. The legacy &#x60;plain&#x60; method (RFC 7636 §4.4) is intentionally omitted; clients and servers compliant with OAuth 2.1 MUST use S256 only. ", alias="code_challenge_method"),
    redirect_uri: Annotated[Optional[StrictStr], Field(description="Where the user-agent is redirected after authorization. Per OAuth 2.1 §2.3.1 and RFC 9700 §4.1.3, the AS MUST compare against registered URIs **using exact-string matching**, not pattern matching. REQUIRED when the client has more than one registered redirect URI; OPTIONAL otherwise. Per RFC 6749 §4.1.2.1, when invalid, the AS MUST NOT redirect — it returns an HTML error page (modeled as the 400 response on `/authorize`). ")] = Query(None, description="Where the user-agent is redirected after authorization. Per OAuth 2.1 §2.3.1 and RFC 9700 §4.1.3, the AS MUST compare against registered URIs **using exact-string matching**, not pattern matching. REQUIRED when the client has more than one registered redirect URI; OPTIONAL otherwise. Per RFC 6749 §4.1.2.1, when invalid, the AS MUST NOT redirect — it returns an HTML error page (modeled as the 400 response on &#x60;/authorize&#x60;). ", alias="redirect_uri"),
    scope: Annotated[Optional[Annotated[str, Field(strict=True)]], Field(description="Space-delimited list of scopes. For OIDC, MUST include `openid` to request an ID token. Standard OIDC scopes: `profile`, `email`, `address`, `phone`, `offline_access`. Per RFC 6749 §3.3 ABNF, each scope token is `1*( %x21 / %x23-5B / %x5D-7E )` — printable ASCII excluding `\"` and `\\`; tokens are separated by single SP characters. ")] = Query(None, description="Space-delimited list of scopes. For OIDC, MUST include &#x60;openid&#x60; to request an ID token. Standard OIDC scopes: &#x60;profile&#x60;, &#x60;email&#x60;, &#x60;address&#x60;, &#x60;phone&#x60;, &#x60;offline_access&#x60;. Per RFC 6749 §3.3 ABNF, each scope token is &#x60;1*( %x21 / %x23-5B / %x5D-7E )&#x60; — printable ASCII excluding &#x60;\&quot;&#x60; and &#x60;\\&#x60;; tokens are separated by single SP characters. ", alias="scope", regex=r"/^[\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*$/"),
    state: Annotated[Optional[StrictStr], Field(description="Opaque value used by the client to maintain state and prevent CSRF. The server returns it unchanged in the redirect. RFC 6749 §10.12. ")] = Query(None, description="Opaque value used by the client to maintain state and prevent CSRF. The server returns it unchanged in the redirect. RFC 6749 §10.12. ", alias="state"),
    nonce: Annotated[Optional[StrictStr], Field(description="OIDC: opaque random value bound to the ID token's `nonce` claim, for replay protection. OIDC Core §3.1.2.1. ")] = Query(None, description="OIDC: opaque random value bound to the ID token&#39;s &#x60;nonce&#x60; claim, for replay protection. OIDC Core §3.1.2.1. ", alias="nonce"),
    prompt: Annotated[Optional[StrictStr], Field(description="OIDC: how the auth server should prompt the user. Space-delimited. ")] = Query(None, description="OIDC: how the auth server should prompt the user. Space-delimited. ", alias="prompt"),
    login_hint: Annotated[Optional[StrictStr], Field(description="OIDC: hint to the auth server about the login identifier (e.g. e-mail).")] = Query(None, description="OIDC: hint to the auth server about the login identifier (e.g. e-mail).", alias="login_hint"),
    max_age: Annotated[Optional[Annotated[int, Field(strict=True, ge=0)]], Field(description="OIDC: maximum allowed elapsed time since last authentication, in seconds.")] = Query(None, description="OIDC: maximum allowed elapsed time since last authentication, in seconds.", alias="max_age", ge=0),
    acr_values: Annotated[Optional[StrictStr], Field(description="OIDC: requested Authentication Context Class Reference values, space-separated.")] = Query(None, description="OIDC: requested Authentication Context Class Reference values, space-separated.", alias="acr_values"),
    response_mode: Annotated[Optional[StrictStr], Field(description="Mechanism for delivering the authorization response. `query`, `fragment`, `form_post` (OAuth 2.0 Form Post Response Mode). ")] = Query(None, description="Mechanism for delivering the authorization response. &#x60;query&#x60;, &#x60;fragment&#x60;, &#x60;form_post&#x60; (OAuth 2.0 Form Post Response Mode). ", alias="response_mode"),
    request_uri: Annotated[Optional[StrictStr], Field(description="Reference to a request previously submitted via PAR (RFC 9126 §4). When present, takes precedence over individual query parameters. ")] = Query(None, description="Reference to a request previously submitted via PAR (RFC 9126 §4). When present, takes precedence over individual query parameters. ", alias="request_uri"),
    authorization_details: Annotated[Optional[StrictStr], Field(description="Rich Authorization Requests (RAR) — JSON-encoded array of authorization detail objects. RFC 9396. ")] = Query(None, description="Rich Authorization Requests (RAR) — JSON-encoded array of authorization detail objects. RFC 9396. ", alias="authorization_details"),
    resource: Annotated[Optional[List[StrictStr]], Field(description="Indicator of the protected resource(s) for which authorization is requested. MUST be an absolute URI without a fragment component. MAY appear multiple times to request audience for multiple resources. RFC 8707 §2. ")] = Query(None, description="Indicator of the protected resource(s) for which authorization is requested. MUST be an absolute URI without a fragment component. MAY appear multiple times to request audience for multiple resources. RFC 8707 §2. ", alias="resource"),
    display: Annotated[Optional[StrictStr], Field(description="OIDC: how the AS should display the authentication and consent UI. OIDC Core §3.1.2.1. Mandatory-to-implement (§15.1). ")] = Query(None, description="OIDC: how the AS should display the authentication and consent UI. OIDC Core §3.1.2.1. Mandatory-to-implement (§15.1). ", alias="display"),
    ui_locales: Annotated[Optional[StrictStr], Field(description="OIDC: end-user UI language(s), space-separated BCP47 tags (e.g. `fr-CA fr en`). Mandatory-to-implement (§15.1). ")] = Query(None, description="OIDC: end-user UI language(s), space-separated BCP47 tags (e.g. &#x60;fr-CA fr en&#x60;). Mandatory-to-implement (§15.1). ", alias="ui_locales"),
    claims_locales: Annotated[Optional[StrictStr], Field(description="OIDC: preferred languages for Claims being returned, space-separated BCP47 tags. OIDC Core §5.2. Mandatory-to-implement (§15.1). ")] = Query(None, description="OIDC: preferred languages for Claims being returned, space-separated BCP47 tags. OIDC Core §5.2. Mandatory-to-implement (§15.1). ", alias="claims_locales"),
    id_token_hint: Annotated[Optional[StrictStr], Field(description="OIDC: previously issued ID Token passed as a hint about the user's current or past authenticated session. OIDC Core §3.1.2.1. ")] = Query(None, description="OIDC: previously issued ID Token passed as a hint about the user&#39;s current or past authenticated session. OIDC Core §3.1.2.1. ", alias="id_token_hint"),
    claims: Annotated[Optional[StrictStr], Field(description="OIDC: JSON-encoded object describing specific Claims being requested for delivery in the ID Token and/or UserInfo response. OIDC Core §5.5. ")] = Query(None, description="OIDC: JSON-encoded object describing specific Claims being requested for delivery in the ID Token and/or UserInfo response. OIDC Core §5.5. ", alias="claims"),
    request: Annotated[Optional[StrictStr], Field(description="OIDC / RFC 9101 (JAR): a self-contained JWT containing the full authorization request as claims. Mutually exclusive with `request_uri`. OIDC Core §6. ")] = Query(None, description="OIDC / RFC 9101 (JAR): a self-contained JWT containing the full authorization request as claims. Mutually exclusive with &#x60;request_uri&#x60;. OIDC Core §6. ", alias="request"),
    dpop_jkt: Annotated[Optional[StrictStr], Field(description="DPoP key thumbprint to bind the resulting authorization code to a specific DPoP key, even before the token request. RFC 9449 §10.1. ")] = Query(None, description="DPoP key thumbprint to bind the resulting authorization code to a specific DPoP key, even before the token request. RFC 9449 §10.1. ", alias="dpop_jkt"),
) -> str:
    """Initiates a browser-driven authorization request. The user-agent is navigated to this URL; the server authenticates the resource owner and obtains consent, then redirects the user-agent back to &#x60;redirect_uri&#x60; with a &#x60;code&#x60; (success) or an &#x60;error&#x60;.  Under OAuth 2.1 only &#x60;response_type&#x3D;code&#x60; is permitted (Implicit is deprecated). PKCE (&#x60;code_challenge&#x60;) is mandatory. """
    if not BaseCoreApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseCoreApi.subclasses[0]().authorize(response_type, client_id, code_challenge, code_challenge_method, redirect_uri, scope, state, nonce, prompt, login_hint, max_age, acr_values, response_mode, request_uri, authorization_details, resource, display, ui_locales, claims_locales, id_token_hint, claims, request, dpop_jkt)


@router.post(
    "/token",
    responses={
        200: {"model": TokenResponse, "description": "Access token issued"},
        400: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
        401: {"model": ErrorResponse, "description": "Standard OAuth 2.0 error response (RFC 6749 §5.2)"},
    },
    tags=["Core"],
    summary="Token endpoint (all grants)",
    response_model_by_alias=True,
)
async def token(
    dpo_p: Annotated[Optional[StrictStr], Field(description="DPoP proof JWT (RFC 9449 §4). Required on `/token`, `/par`, protected resources, and `/userinfo` whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with `typ=dpop+jwt`, `alg`, `jwk` in the header and `jti`, `htm`, `htu`, `iat` claims (plus `ath` at resource servers and `nonce` when the AS issues a DPoP-Nonce challenge). ")] = Header(None, description="DPoP proof JWT (RFC 9449 §4). Required on &#x60;/token&#x60;, &#x60;/par&#x60;, protected resources, and &#x60;/userinfo&#x60; whenever DPoP-bound access tokens are in use. Header value is a single compact-serialized JWT with &#x60;typ&#x3D;dpop+jwt&#x60;, &#x60;alg&#x60;, &#x60;jwk&#x60; in the header and &#x60;jti&#x60;, &#x60;htm&#x60;, &#x60;htu&#x60;, &#x60;iat&#x60; claims (plus &#x60;ath&#x60; at resource servers and &#x60;nonce&#x60; when the AS issues a DPoP-Nonce challenge). "),
    client_id: Annotated[Optional[StrictStr], Field(description="REQUIRED for public clients (no client secret) and clients that authenticate via `client_assertion`. RFC 6749 §3.2.1. ")] = Form(None, description="REQUIRED for public clients (no client secret) and clients that authenticate via &#x60;client_assertion&#x60;. RFC 6749 §3.2.1. "),
    client_secret: Annotated[Optional[StrictStr], Field(description="Used with `client_id` for `client_secret_post` authentication. HTTP Basic (`client_secret_basic`) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. ")] = Form(None, description="Used with &#x60;client_id&#x60; for &#x60;client_secret_post&#x60; authentication. HTTP Basic (&#x60;client_secret_basic&#x60;) is preferred; this form-body variant is NOT RECOMMENDED per RFC 6749 §2.3.1. "),
    client_assertion: Annotated[Optional[StrictStr], Field(description="JWT bearing claims that authenticate the client. Used with `client_assertion_type` for `client_secret_jwt` or `private_key_jwt` authentication. RFC 7523 §2.2. ")] = Form(None, description="JWT bearing claims that authenticate the client. Used with &#x60;client_assertion_type&#x60; for &#x60;client_secret_jwt&#x60; or &#x60;private_key_jwt&#x60; authentication. RFC 7523 §2.2. "),
    client_assertion_type: Annotated[Optional[StrictStr], Field(description="RFC 7523 §2.2.")] = Form(None, description="RFC 7523 §2.2."),
    resource: Annotated[Optional[List[StrictStr]], Field(description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. ")] = Form(None, description="Indicator(s) of the protected resource(s) for which the access token is requested. Each value MUST be an absolute URI without a fragment component. The parameter MAY be included multiple times in the underlying form-encoded body. RFC 8707. "),
    grant_type: Optional[StrictStr] = Form(None, description=""),
    code: Annotated[Optional[StrictStr], Field(description="The authorization code received from `/authorize`.")] = Form(None, description="The authorization code received from &#x60;/authorize&#x60;."),
    redirect_uri: Annotated[Optional[StrictStr], Field(description="OPTIONAL under OAuth 2.1 §10.2 (was REQUIRED in OAuth 2.0 §4.1.3). When present, MUST match the `redirect_uri` used at `/authorize`. Some legacy AS implementations still require it. ")] = Form(None, description="OPTIONAL under OAuth 2.1 §10.2 (was REQUIRED in OAuth 2.0 §4.1.3). When present, MUST match the &#x60;redirect_uri&#x60; used at &#x60;/authorize&#x60;. Some legacy AS implementations still require it. "),
    code_verifier: Annotated[Optional[Annotated[str, Field(min_length=43, strict=True, max_length=128)]], Field(description="PKCE verifier (RFC 7636 §4.1). 43-128 chars from the unreserved set `[A-Z] / [a-z] / [0-9] / \\\"-\\\" / \\\".\\\" / \\\"_\\\" / \\\"~\\\"`. ")] = Form(None, description="PKCE verifier (RFC 7636 §4.1). 43-128 chars from the unreserved set &#x60;[A-Z] / [a-z] / [0-9] / \\\&quot;-\\\&quot; / \\\&quot;.\\\&quot; / \\\&quot;_\\\&quot; / \\\&quot;~\\\&quot;&#x60;. ", regex=r"/^[A-Za-z0-9._~-]+$/", min_length=43, max_length=128),
    authorization_details: Annotated[Optional[StrictStr], Field(description="JSON-encoded array of `AuthorizationDetail` objects (RFC 9396 §5). Sent as a string because the form-encoded body cannot carry structured JSON natively. The decoded value conforms to `AuthorizationDetail[]`. ")] = Form(None, description="JSON-encoded array of &#x60;AuthorizationDetail&#x60; objects (RFC 9396 §5). Sent as a string because the form-encoded body cannot carry structured JSON natively. The decoded value conforms to &#x60;AuthorizationDetail[]&#x60;. "),
    scope: Optional[StrictStr] = Form(None, description=""),
    audience: Annotated[Optional[List[StrictStr]], Field(description="RFC 8693-defined parameter (distinct from RFC 8707 `resource`). Logical name(s) of the target service(s). MAY appear multiple times in the form body — modeled here as array. ")] = Form(None, description="RFC 8693-defined parameter (distinct from RFC 8707 &#x60;resource&#x60;). Logical name(s) of the target service(s). MAY appear multiple times in the form body — modeled here as array. "),
    refresh_token: Optional[StrictStr] = Form(None, description=""),
    device_code: Annotated[Optional[StrictStr], Field(description="The opaque `device_code` from `/device_authorization`. MUST NOT be displayed to the end user. ")] = Form(None, description="The opaque &#x60;device_code&#x60; from &#x60;/device_authorization&#x60;. MUST NOT be displayed to the end user. "),
    assertion: Annotated[Optional[StrictStr], Field(description="Signed JWT bearer assertion. REQUIRED claims (RFC 7523 §3): `iss`, `sub`, `aud` (the AS token endpoint URL), `exp`. RECOMMENDED: `nbf`, `iat`, `jti`. The JWT MUST be digitally signed or MAC'd by the issuer and MUST be rejected by the AS if any required claim is missing or invalid. ")] = Form(None, description="Signed JWT bearer assertion. REQUIRED claims (RFC 7523 §3): &#x60;iss&#x60;, &#x60;sub&#x60;, &#x60;aud&#x60; (the AS token endpoint URL), &#x60;exp&#x60;. RECOMMENDED: &#x60;nbf&#x60;, &#x60;iat&#x60;, &#x60;jti&#x60;. The JWT MUST be digitally signed or MAC&#39;d by the issuer and MUST be rejected by the AS if any required claim is missing or invalid. "),
    subject_token: Annotated[Optional[StrictStr], Field(description="Token representing the identity of the party on whose behalf the request is made.")] = Form(None, description="Token representing the identity of the party on whose behalf the request is made."),
    subject_token_type: Optional[TokenTypeURI] = Form(None, description=""),
    actor_token: Annotated[Optional[StrictStr], Field(description="Token representing the identity of the acting party (delegation/impersonation).")] = Form(None, description="Token representing the identity of the acting party (delegation/impersonation)."),
    actor_token_type: Annotated[Optional[TokenTypeURI], Field(description="REQUIRED when `actor_token` is present.")] = Form(None, description="REQUIRED when &#x60;actor_token&#x60; is present."),
    requested_token_type: Annotated[Optional[TokenTypeURI], Field(description="Type of token the client is requesting be issued.")] = Form(None, description="Type of token the client is requesting be issued."),
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
) -> TokenResponse:
    """Issues access tokens. The &#x60;grant_type&#x60; form field selects the grant. All grants supported by OAuth 2.1 are modeled here:  - &#x60;authorization_code&#x60; — RFC 6749 §4.1.3 (with PKCE per RFC 7636) - &#x60;client_credentials&#x60; — RFC 6749 §4.4 - &#x60;refresh_token&#x60; — RFC 6749 §6 - &#x60;urn:ietf:params:oauth:grant-type:device_code&#x60; — RFC 8628 §3.4 - &#x60;urn:ietf:params:oauth:grant-type:jwt-bearer&#x60; — RFC 7523 - &#x60;urn:ietf:params:oauth:grant-type:token-exchange&#x60; — RFC 8693  The deprecated &#x60;password&#x60; and &#x60;implicit&#x60; grants are intentionally omitted (per OAuth 2.1). """
    if not BaseCoreApi.subclasses:
        raise HTTPException(status_code=500, detail="Not implemented")
    return await BaseCoreApi.subclasses[0]().token(dpo_p, client_id, client_secret, client_assertion, client_assertion_type, resource, grant_type, code, redirect_uri, code_verifier, authorization_details, scope, audience, refresh_token, device_code, assertion, subject_token, subject_token_type, actor_token, actor_token_type, requested_token_type)
