"""AuthorizeService — implements `AuthorizeUseCase` for `GET /authorize`.

Returns a discriminated `AuthorizeResult`: the route handler dispatches
on its type. Four terminal outcomes:

1. `AuthorizeRedirectToLogin` — no valid session; send the user to /login
   carrying the full authorize URL in `next`.
2. `AuthorizeShowConsent` — valid session; render consent.html with the
   client name and requested scopes.
3. `AuthorizeRenderError` — unrecoverable: missing/invalid client_id or
   bad redirect_uri. Per RFC 6749 §4.1.2.1 the AS MUST NOT redirect in
   these cases — it shows an HTML error page.
4. `AuthorizeRedirectError` — recoverable (client_id + redirect_uri are
   valid but something else is wrong): redirect back to the client with
   `?error=...` + `state` per RFC 6749 §4.1.2.1.

OAuth 2.1 / PKCE is mandatory: code_challenge + S256 method required.
"""

from __future__ import annotations

from dataclasses import dataclass

from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.application.port.outbound.session_signer import SessionSigner
from oauth_lab.application.port.outbound.user_repository import UserRepository
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.pkce import PKCEChallenge
from oauth_lab.domain.model.scope import ScopeSet
from oauth_lab.domain.model.user import User


@dataclass(frozen=True, slots=True)
class AuthorizeRequest:
    response_type: str | None
    client_id: str | None
    redirect_uri: str | None
    scope: str | None
    state: str | None
    code_challenge: str | None
    code_challenge_method: str | None


@dataclass(frozen=True, slots=True)
class AuthorizeRedirectToLogin:
    next_authorize_url: str


@dataclass(frozen=True, slots=True)
class AuthorizeShowConsent:
    client: Client
    user: User
    requested_scope: ScopeSet
    redirect_uri: str
    state: str | None
    code_challenge: PKCEChallenge


@dataclass(frozen=True, slots=True)
class AuthorizeRenderError:
    """Non-redirectable error: render HTML and stop. RFC 6749 §4.1.2.1."""

    error_code: str
    description: str


@dataclass(frozen=True, slots=True)
class AuthorizeRedirectError:
    """Redirectable error: redirect to client with `?error=...`."""

    redirect_uri: str
    error: str
    error_description: str
    state: str | None


AuthorizeResult = (
    AuthorizeRedirectToLogin
    | AuthorizeShowConsent
    | AuthorizeRenderError
    | AuthorizeRedirectError
)


class AuthorizeService:
    def __init__(
        self,
        *,
        clients: ClientRepository,
        users: UserRepository,
        session_signer: SessionSigner,
    ) -> None:
        self._clients = clients
        self._users = users
        self._session_signer = session_signer

    async def execute(
        self,
        *,
        request: AuthorizeRequest,
        session_cookie: str | None,
        full_request_url: str,
    ) -> AuthorizeResult:
        # 1. Validate client_id — non-redirectable.
        if not request.client_id:
            return AuthorizeRenderError("invalid_request", "client_id is required")
        client = await self._clients.find_by_id(ClientId(request.client_id))
        if client is None:
            return AuthorizeRenderError(
                "invalid_client", f"unknown client_id: {request.client_id}"
            )

        # 2. Validate redirect_uri — non-redirectable (RFC 6749 §4.1.2.1, RFC 9700 §4.1.3).
        if not request.redirect_uri:
            return AuthorizeRenderError("invalid_request", "redirect_uri is required")
        if request.redirect_uri not in client.redirect_uris:
            return AuthorizeRenderError(
                "invalid_request",
                "redirect_uri does not match any registered URI for this client",
            )

        # From here on, errors are redirectable to redirect_uri.
        redirect_uri = request.redirect_uri

        # 3. response_type — only `code` allowed in OAuth 2.1.
        if request.response_type != "code":
            return AuthorizeRedirectError(
                redirect_uri=redirect_uri,
                error="unsupported_response_type",
                error_description="only response_type=code is supported (OAuth 2.1)",
                state=request.state,
            )

        # 4. PKCE — mandatory in OAuth 2.1 + RFC 9700 §4.8.
        if not request.code_challenge:
            return AuthorizeRedirectError(
                redirect_uri=redirect_uri,
                error="invalid_request",
                error_description="code_challenge is required (PKCE mandatory)",
                state=request.state,
            )
        method = request.code_challenge_method or "S256"
        try:
            pkce_challenge = PKCEChallenge(value=request.code_challenge, method=method)
        except ValueError as exc:
            return AuthorizeRedirectError(
                redirect_uri=redirect_uri,
                error="invalid_request",
                error_description=str(exc),
                state=request.state,
            )

        # 5. Scope validation — must be subset of client.allowed_scopes.
        try:
            requested_scope = ScopeSet.parse(request.scope)
        except ValueError as exc:
            return AuthorizeRedirectError(
                redirect_uri=redirect_uri,
                error="invalid_scope",
                error_description=str(exc),
                state=request.state,
            )
        if not requested_scope.is_empty() and not requested_scope.is_subset_of(
            client.allowed_scopes
        ):
            return AuthorizeRedirectError(
                redirect_uri=redirect_uri,
                error="invalid_scope",
                error_description="requested scope contains values not allowed for this client",
                state=request.state,
            )
        if requested_scope.is_empty():
            requested_scope = client.allowed_scopes

        # 6. Client must support authorization_code grant.
        if not client.supports_grant(GrantType.AUTHORIZATION_CODE):
            return AuthorizeRedirectError(
                redirect_uri=redirect_uri,
                error="unauthorized_client",
                error_description="client is not allowed to use authorization_code grant",
                state=request.state,
            )

        # 7. Session check — drive UI decision.
        session = self._session_signer.verify(session_cookie)
        if session is None:
            return AuthorizeRedirectToLogin(next_authorize_url=full_request_url)

        user = await self._users.find_by_sub(session.user_sub)
        if user is None:
            return AuthorizeRedirectToLogin(next_authorize_url=full_request_url)

        return AuthorizeShowConsent(
            client=client,
            user=user,
            requested_scope=requested_scope,
            redirect_uri=redirect_uri,
            state=request.state,
            code_challenge=pkce_challenge,
        )


__all__ = [
    "AuthorizeRedirectError",
    "AuthorizeRedirectToLogin",
    "AuthorizeRenderError",
    "AuthorizeRequest",
    "AuthorizeResult",
    "AuthorizeService",
    "AuthorizeShowConsent",
]
