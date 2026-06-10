"""Inbound port — the `/token` endpoint's contract with the application.

A driving adapter (REST controller) calls this exactly once per `/token`
request. The port owns the request/response DTOs of that contract:
`ClientCredentials` and `TokenRequest` in, `TokenIssuanceResult` out.
The implementation lives in
`oauth_lab.application.service.issue_token_service`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class ClientCredentials:
    """The raw credentials extracted from an HTTP request, before validation."""

    basic_auth_header: str | None = None  # HTTP Basic header value (no "Basic " prefix)
    form_client_id: str | None = None
    form_client_secret: str | None = None
    client_assertion: str | None = None
    client_assertion_type: str | None = None


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


class IssueTokenUseCase(Protocol):
    async def execute(
        self,
        creds: ClientCredentials,
        request: TokenRequest,
    ) -> TokenIssuanceResult: ...
