"""Outbound port — validates a subject (or actor) token presented to
the token-exchange endpoint (RFC 8693).

A `subject_token` arrives as an opaque string with a companion
`subject_token_type` URI declaring what it is. The validator returns
the verified claims; the grant strategy applies OAuth-level policy on
top (scope downscope, audience switch, etc.).

Different concrete validators handle different token types — the
canonical lab implementation only validates JWTs the AS itself
signed (a downscope/exchange of our own tokens). Federation across
servers would add a second validator that trusts external issuers,
analogous to `TrustedAssertionIssuerRepository` for jwt-bearer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class SubjectTokenClaims:
    subject: str
    client_id: str | None
    issuer: str
    audience: tuple[str, ...]
    scope: ScopeSet
    expires_at: datetime


class SubjectTokenValidator(Protocol):
    def validate(self, token: str, token_type: str) -> SubjectTokenClaims: ...
