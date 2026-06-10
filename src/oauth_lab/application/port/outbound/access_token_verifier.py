"""Outbound port — verifies an access token presented to a protected
resource endpoint (`/userinfo`).

The resource side of the AS: an access token arrives as an opaque
string in the `Authorization: Bearer` header. The verifier checks it
cryptographically (signature, temporal validity, issuer) and returns
the claims the application layer needs; invalid tokens raise the
RFC 6750 §3.1 `invalid_token` domain error.

The canonical lab implementation decodes JWT access tokens the AS
itself signed (`oauth_lab.adapter.outbound.crypto.jwt_access_token_verifier`).
An opaque-token deployment would swap in an introspecting verifier
(RFC 7662) behind the same port.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """Verified claims extracted from an access token.

    `sub` is optional at the port level: some token shapes (or future
    verifier implementations) may carry no subject. Callers that need a
    resource owner must treat `None` as `invalid_token`.
    `scope` is the parsed space-delimited `scope` claim; absent → empty.
    """

    sub: str | None
    scope: ScopeSet


class AccessTokenVerifier(Protocol):
    def verify(self, token: str) -> AccessTokenClaims:
        """Return the verified claims; raise `InvalidToken` if the token
        fails signature, temporal, issuer, or structural checks."""
        ...
