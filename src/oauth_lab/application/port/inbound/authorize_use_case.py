"""Inbound port — `/authorize` endpoint contract.

The port owns the request DTO and the discriminated `AuthorizeResult`
union; the driving adapter dispatches on the concrete variant. Four
terminal outcomes:

1. `AuthenticationRequired` — no valid session; the user must
   authenticate before the request can proceed.
2. `ConsentRequired` — valid session; the user must approve the
   client's request (client name + requested scopes).
3. `AuthorizationRequestError` — unrecoverable: missing/invalid
   client_id or bad redirect_uri. Not safe to redirect — per RFC 6749
   §4.1.2.1 the AS MUST NOT redirect in these cases.
4. `AuthorizationResponseError` — RFC 6749 §4.1.2.1 Error Response:
   client_id + redirect_uri are valid, so the error is delivered to the
   client via redirect with `?error=...` + `state`.

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
class AuthenticationRequired:
    """No authenticated end-user; the adapter decides how to obtain one."""


@dataclass(frozen=True, slots=True)
class ConsentRequired:
    client: Client
    user: User
    requested_scope: ScopeSet
    redirect_uri: str
    state: str | None
    code_challenge: PKCEChallenge
    csrf_token: str


@dataclass(frozen=True, slots=True)
class AuthorizationRequestError:
    """Not safe to redirect — unknown client/redirect_uri. RFC 6749 §4.1.2.1
    says the AS MUST NOT redirect; inform the resource owner directly."""

    error_code: str
    description: str


@dataclass(frozen=True, slots=True)
class AuthorizationResponseError:
    """RFC 6749 §4.1.2.1 Error Response, delivered to the client via redirect."""

    redirect_uri: str
    error: str
    error_description: str
    state: str | None


AuthorizeResult = (
    AuthenticationRequired
    | ConsentRequired
    | AuthorizationRequestError
    | AuthorizationResponseError
)


class AuthorizeUseCase(Protocol):
    async def execute(
        self,
        *,
        request: AuthorizeRequest,
        session_token: str | None,
    ) -> AuthorizeResult: ...
