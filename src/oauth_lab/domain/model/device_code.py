"""DeviceCode entity — RFC 8628 § 3.2.

Produced by `POST /device_authorization`; redeemed by `POST /token
grant_type=urn:ietf:params:oauth:grant-type:device_code` after the user
has approved on a *separate* device (the "verification URI" device).

Two identifiers in one entity:
- `device_code`: opaque, long, used by the device when polling /token.
- `user_code`: short, human-typable (e.g. "BCDF-GHJK"), shown on the
  device's screen so the user can enter it on their phone or laptop.

The device polls /token repeatedly. The state machine is:
    pending → approved | denied | expired
Plus `last_polled_at` enforces RFC 8628 § 3.5 polling interval (`slow_down`).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class DeviceCode:
    device_code: str
    user_code: str
    client_id: ClientId
    scope: ScopeSet
    issued_at: datetime
    expires_at: datetime
    interval: int  # seconds (RFC 8628 § 3.2)
    last_polled_at: datetime | None = None
    user_sub: str | None = None  # set on approval
    denied: bool = False
    redeemed_at: datetime | None = None  # set when tokens issued

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def is_pending(self) -> bool:
        return self.user_sub is None and not self.denied

    def is_approved(self) -> bool:
        return self.user_sub is not None and not self.denied

    def is_denied(self) -> bool:
        return self.denied

    def is_redeemed(self) -> bool:
        return self.redeemed_at is not None

    def can_poll_at(self, now: datetime) -> bool:
        """`True` if `now` is at or beyond `last_polled_at + interval`."""
        if self.last_polled_at is None:
            return True
        return now >= self.last_polled_at + timedelta(seconds=self.interval)

    def approve(self, user_sub: str) -> DeviceCode:
        return replace(self, user_sub=user_sub, denied=False)

    def deny(self) -> DeviceCode:
        return replace(self, denied=True, user_sub=None)

    def mark_polled(self, now: datetime) -> DeviceCode:
        return replace(self, last_polled_at=now)

    def redeem(self, now: datetime) -> DeviceCode:
        """Return a new instance marked as redeemed.

        A device code is single-use: once tokens have been issued, a
        re-poll must fail. The grant strategy persists the redeemed copy
        so subsequent polls observe `is_redeemed()`.
        """
        return replace(self, redeemed_at=now)
