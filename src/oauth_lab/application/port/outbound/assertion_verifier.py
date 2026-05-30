"""Outbound port — verifies a signed JWT assertion (RFC 7519 + RFC 7523).

Returns the decoded claim set on success; raises `InvalidAssertion`
(via `InvalidGrant`) on any verification failure.

The verifier knows nothing about OAuth — it just checks JWS signature
and standard JWT temporal claims. The caller (the grant strategy)
applies RFC 7523 §3 semantic rules on top (issuer trust, subject
shape, audience binding to AS).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from oauth_lab.domain.model.trusted_assertion_issuer import TrustedAssertionIssuer


@dataclass(frozen=True, slots=True)
class AssertionClaims:
    issuer: str
    subject: str
    audience: tuple[str, ...]
    expires_at: datetime
    not_before: datetime | None
    issued_at: datetime | None
    jwt_id: str | None


class AssertionVerifier(Protocol):
    def verify(
        self,
        assertion: str,
        *,
        trusted_issuer: TrustedAssertionIssuer,
        expected_audience: str,
    ) -> AssertionClaims: ...
