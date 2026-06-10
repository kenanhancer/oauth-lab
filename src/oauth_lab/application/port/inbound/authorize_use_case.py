"""Inbound port — `/authorize` endpoint contract.

The port owns the request DTO and the discriminated `AuthorizeResult`
union; the driving adapter dispatches on the concrete variant. Four
terminal outcomes:

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

Implementation: `oauth_lab.application.service.authorize_service`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from oauth_lab.domain.model.client import Client
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
    csrf_token: str


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


class AuthorizeUseCase(Protocol):
    async def execute(
        self,
        *,
        request: AuthorizeRequest,
        session_cookie: str | None,
        full_request_url: str,
    ) -> AuthorizeResult: ...
