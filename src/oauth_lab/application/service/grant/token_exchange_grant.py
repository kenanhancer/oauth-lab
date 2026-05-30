"""Token Exchange grant — RFC 8693.

`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`

Lets a client trade a token it already holds (the `subject_token`)
for a *different* token — typically narrower in scope, scoped to a
different audience, or both. Common shapes:

- **Downscope** — exchange a `read write` access token for a `read`
  one before forwarding to a less-trusted service.
- **Audience switch** — exchange a token issued for service A for one
  valid against service B.
- **Delegation** — paired with an `actor_token`, prove "client X is
  acting on behalf of user Y". Not implemented in the lab; would
  attach an `act` claim per RFC 8693 §4.1.

Response shape (RFC 8693 §2.2):

- `access_token`         — REQUIRED; the new token
- `issued_token_type`    — REQUIRED; URI of what was issued
- `token_type`           — usually "Bearer"
- `expires_in`, `scope`  — same as RFC 6749 §5.1

Scope policy:
  granted = requested  ∩  subject_token.scope  ∩  client.allowed_scope
  (if requested is empty, default to subject ∩ client_allowed)

This enforces the canonical "exchange never widens" invariant.
"""

from __future__ import annotations

from typing import ClassVar

from oauth_lab.application.port.outbound.subject_token_validator import (
    SubjectTokenClaims,
    SubjectTokenValidator,
)
from oauth_lab.application.port.outbound.token_issuer import TokenIssuer
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.grant_strategy import (
    GrantStrategy,
    TokenIssuanceResult,
    TokenRequest,
)
from oauth_lab.domain.model.errors import InvalidRequest, UnauthorizedClient
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import ScopeSet
from oauth_lab.domain.model.token_type_uri import TokenTypeURI
from oauth_lab.domain.service.scope_validator import ScopeValidator


class TokenExchangeGrant(GrantStrategy):
    grant_type: ClassVar[GrantType] = GrantType.TOKEN_EXCHANGE

    def __init__(
        self,
        *,
        token_issuer: TokenIssuer,
        subject_token_validator: SubjectTokenValidator,
        scope_validator: ScopeValidator,
        access_token_ttl_seconds: int,
    ) -> None:
        self._token_issuer = token_issuer
        self._validator = subject_token_validator
        self._scope_validator = scope_validator
        self._access_ttl = access_token_ttl_seconds

    async def execute(
        self,
        request: TokenRequest,
        client: AuthenticatedClient,
    ) -> TokenIssuanceResult:
        if not client.supports_grant(self.grant_type):
            raise UnauthorizedClient(
                f"client is not allowed to use grant_type={self.grant_type.value}"
            )
        if not request.subject_token:
            raise InvalidRequest("subject_token is required")
        if not request.subject_token_type:
            raise InvalidRequest("subject_token_type is required")

        requested_type = request.requested_token_type or TokenTypeURI.ACCESS_TOKEN.value
        if requested_type != TokenTypeURI.ACCESS_TOKEN.value:
            raise InvalidRequest(
                f"requested_token_type {requested_type!r} is not supported"
            )

        claims = self._validator.validate(
            request.subject_token, request.subject_token_type
        )

        granted_scope = self._derive_scope(request=request, subject=claims, client=client)
        audience = self._derive_audience(request=request, client=client)

        issued = await self._token_issuer.issue(
            subject=claims.subject,
            client_id=str(client.id),
            scope=granted_scope,
            audience=audience,
            ttl_seconds=self._access_ttl,
        )

        return TokenIssuanceResult(
            access_token=issued.value,
            token_type="Bearer",                                                            # noqa: S106
            expires_in=issued.expires_in_seconds,
            scope=granted_scope,
            issued_token_type=TokenTypeURI.ACCESS_TOKEN.value,
        )

    def _derive_scope(
        self,
        *,
        request: TokenRequest,
        subject: SubjectTokenClaims,
        client: AuthenticatedClient,
    ) -> ScopeSet:
        # Step 1 — pin to what the original token actually had.
        # Step 2 — clip to what the requesting client is allowed.
        # Step 3 — if the caller named a subset, honour it (else default).
        upper_bound = ScopeSet(
            subject.scope.scopes & client.allowed_scopes.scopes
        )
        if request.scope.is_empty():
            return upper_bound
        return self._scope_validator.grantable(
            requested=request.scope,
            allowed=upper_bound,
        )

    @staticmethod
    def _derive_audience(
        *,
        request: TokenRequest,
        client: AuthenticatedClient,
    ) -> str | None:
        # RFC 8693 lets the caller name either an `audience` or a `resource`.
        # Audience wins if both present; otherwise fall back to the client default.
        if request.audience:
            return request.audience[0]
        if request.resource:
            return request.resource[0]
        return client.default_audience
