"""Grant Strategy — the abstract algorithm for issuing a token.

One subclass per OAuth grant type. Each strategy receives:
- An `AuthenticatedClient` (the client-auth pipeline has already run)
- A `TokenRequest` carrying grant-specific parameters

…and produces a `TokenIssuanceResult` (or raises an `OAuthError`).

This is the canonical Strategy pattern: 6+ algorithms with one shape,
dispatched by `grant_type`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class TokenRequest:
    """The form-encoded `/token` body, normalised into domain values."""

    grant_type: GrantType
    scope: ScopeSet = field(default_factory=lambda: ScopeSet(frozenset()))
    audience: tuple[str, ...] = ()
    resource: tuple[str, ...] = ()

    # authorization_code grant
    code: str | None = None
    redirect_uri: str | None = None
    code_verifier: str | None = None

    # refresh_token grant
    refresh_token: str | None = None

    # device_code grant
    device_code: str | None = None

    # jwt-bearer grant
    assertion: str | None = None

    # token-exchange grant
    subject_token: str | None = None
    subject_token_type: str | None = None
    actor_token: str | None = None
    actor_token_type: str | None = None
    requested_token_type: str | None = None


@dataclass(frozen=True, slots=True)
class TokenIssuanceResult:
    """The domain-level token response (the API layer maps this to the DTO)."""

    access_token: str
    token_type: str
    expires_in: int
    scope: ScopeSet | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    issued_token_type: str | None = None


class GrantStrategy(ABC):
    grant_type: ClassVar[GrantType]

    @abstractmethod
    async def execute(
        self,
        request: TokenRequest,
        client: AuthenticatedClient,
    ) -> TokenIssuanceResult: ...
