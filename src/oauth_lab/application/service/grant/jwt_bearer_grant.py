"""JWT Bearer grant — RFC 7523 §2.1.

`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`

A caller presents a signed JWT (`assertion`) issued by a previously
registered trusted party. The AS exchanges that proof of identity
for an OAuth access token — the JWT plays the role of "the user has
already been authenticated by someone we trust".

Common shapes:

- **Service-account / impersonation** — an admin issues a JWT for a
  named user (`sub=user-id`) so a backend can mint user-scoped tokens.
- **Federation** — an IdP issues JWTs that this AS accepts.

Validation per RFC 7523 §3:

1. JWT MUST contain `iss`, `sub`, `aud`, `exp`.
2. `iss` MUST resolve to a registered `TrustedAssertionIssuer`.
3. Signature MUST verify with the registered key/alg.
4. `aud` MUST include this AS (the token endpoint URL).
5. `exp` MUST be in the future; `nbf` (if present) MUST be in the past.

`jti` replay protection (§3.7) is intentionally NOT implemented here —
documented as a follow-up; would require a short-TTL seen-jti cache.
"""

from __future__ import annotations

from typing import ClassVar

from oauth_lab.application.port.inbound.issue_token_use_case import (
    TokenIssuanceResult,
    TokenRequest,
)
from oauth_lab.application.port.outbound.assertion_verifier import (
    AssertionClaims,
    AssertionVerifier,
)
from oauth_lab.application.port.outbound.token_issuer import TokenIssuer
from oauth_lab.application.port.outbound.trusted_assertion_issuer_repository import (
    TrustedAssertionIssuerRepository,
)
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.grant_strategy import GrantStrategy
from oauth_lab.domain.model.errors import InvalidGrant, InvalidRequest, UnauthorizedClient
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.service.scope_validator import ScopeValidator


class JwtBearerGrant(GrantStrategy):
    grant_type: ClassVar[GrantType] = GrantType.JWT_BEARER

    def __init__(
        self,
        *,
        token_issuer: TokenIssuer,
        trusted_issuers: TrustedAssertionIssuerRepository,
        assertion_verifier: AssertionVerifier,
        scope_validator: ScopeValidator,
        expected_audience: str,
        access_token_ttl_seconds: int,
    ) -> None:
        self._token_issuer = token_issuer
        self._trusted_issuers = trusted_issuers
        self._verifier = assertion_verifier
        self._scope_validator = scope_validator
        self._expected_audience = expected_audience
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
        if request.assertion is None:
            raise InvalidRequest("assertion is required for jwt-bearer grant")

        claims = await self._verify_assertion(request.assertion)

        granted_scope = self._scope_validator.grantable(
            requested=request.scope,
            allowed=client.allowed_scopes,
        )

        audience = request.audience[0] if request.audience else client.default_audience

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
        )

    async def _verify_assertion(self, assertion: str) -> AssertionClaims:
        # Peek at `iss` to find the trusted-issuer record. PyJWT can decode
        # the unverified payload safely (no signature check) — we then look
        # up the key and re-decode with full verification.
        from jwt import InvalidTokenError, decode

        try:
            unverified = decode(assertion, options={"verify_signature": False})
        except InvalidTokenError as exc:
            raise InvalidGrant(f"assertion is not a valid JWT: {exc}") from exc

        iss = unverified.get("iss")
        if not isinstance(iss, str) or not iss:
            raise InvalidGrant("assertion is missing iss claim")

        trusted = await self._trusted_issuers.find_by_issuer(iss)
        if trusted is None:
            raise InvalidGrant(f"assertion issuer is not trusted: {iss}")

        return self._verifier.verify(
            assertion,
            trusted_issuer=trusted,
            expected_audience=self._expected_audience,
        )
