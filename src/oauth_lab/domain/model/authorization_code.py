"""AuthorizationCode entity — RFC 6749 § 4.1.2 + § 4.1.3.

A short-lived single-use credential issued at `/authorize` and exchanged
for tokens at `/token`. Carries every binding the AS must re-verify at
exchange time:

- `client_id` — only the client that obtained the code may redeem it
- `redirect_uri` — must match the URI used at `/authorize` exactly
- `pkce_challenge` — the code_verifier presented at `/token` must hash to this
- `scope` — what the user consented to (may be less than requested)
- `user_sub` — the resource owner the issued tokens will represent
- `expires_at` — RFC 9700 § 2.1.1 recommends ≤ 60 s

Immutable. `consume()` returns a new instance with `consumed_at` set; the
repository is responsible for the atomic check-and-set (replay protection).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidGrant
from oauth_lab.domain.model.pkce import PKCEChallenge
from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class AuthorizationCode:
    value: str
    client_id: ClientId
    user_sub: str
    redirect_uri: str
    scope: ScopeSet
    pkce_challenge: PKCEChallenge
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    nonce: str | None = None  # OIDC: bound into id_token

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def is_consumed(self) -> bool:
        return self.consumed_at is not None

    def consume(self, now: datetime) -> AuthorizationCode:
        """Return a new instance with `consumed_at` set.

        Raises `InvalidGrant` if the code is already consumed or has
        expired. The repository must use this method *under a lock* (or
        equivalent atomic SQL update) to prevent two concurrent token
        requests from both succeeding.
        """
        if self.is_consumed():
            raise InvalidGrant("authorization code has already been used")
        if self.is_expired(now):
            raise InvalidGrant("authorization code has expired")
        return replace(self, consumed_at=now)
