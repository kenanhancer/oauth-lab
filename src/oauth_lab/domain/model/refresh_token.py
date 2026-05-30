"""RefreshToken entity — RFC 6749 § 6 + RFC 9700 § 2.2.2 (rotation).

A refresh token is single-use: each `/token grant_type=refresh_token`
exchange consumes the presented token and issues a brand-new one. The
old token's `consumed_at` is set; presenting it a second time is a
replay attack and triggers revocation of the entire `family_id` chain.

Why family-based revocation? An attacker who stole a refresh token can
race the legitimate client. Whoever uses it first wins the rotation;
the loser then presents an already-consumed token. We can't tell which
of the two was the attacker, so RFC 9700 § 2.2.2 mandates: revoke the
whole chain and let the user re-authenticate.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class RefreshToken:
    value: str
    family_id: str                # groups the rotation chain
    client_id: ClientId
    user_sub: str
    scope: ScopeSet
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def is_consumed(self) -> bool:
        return self.consumed_at is not None

    def consume(self, now: datetime) -> RefreshToken:
        """Mark this token used. Re-consuming is allowed here at the
        entity level — replay detection lives in the repository's atomic
        `rotate()` and grant strategy."""
        return replace(self, consumed_at=now)
