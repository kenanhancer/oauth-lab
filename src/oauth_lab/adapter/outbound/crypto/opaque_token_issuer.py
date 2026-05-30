"""Opaque access token issuer.

Returns a random URL-safe string. Validation requires `/introspect`
(RFC 7662). Cheapest to implement; useful when token revocation needs to
be immediate.
"""

from __future__ import annotations

from oauth_lab.application.port.outbound.random_source import RandomSource
from oauth_lab.application.port.outbound.token_issuer import IssuedToken
from oauth_lab.domain.model.scope import ScopeSet


class OpaqueTokenIssuer:
    def __init__(self, random_source: RandomSource) -> None:
        self._random = random_source

    async def issue(
        self,
        *,
        subject: str,
        client_id: str,
        scope: ScopeSet,
        audience: str | None,
        ttl_seconds: int,
    ) -> IssuedToken:
        # In a complete implementation we'd persist (token, subject, client_id,
        # scope, audience, expiry) so /introspect can answer questions about
        # this token. For the first grant we only need the value.
        del subject, client_id, scope, audience
        return IssuedToken(value=self._random.token_urlsafe(32), expires_in_seconds=ttl_seconds)
