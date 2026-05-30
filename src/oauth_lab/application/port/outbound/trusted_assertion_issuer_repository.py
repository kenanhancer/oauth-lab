"""Outbound port — registry of trusted JWT assertion issuers (RFC 7523)."""

from __future__ import annotations

from typing import Protocol

from oauth_lab.domain.model.trusted_assertion_issuer import TrustedAssertionIssuer


class TrustedAssertionIssuerRepository(Protocol):
    async def find_by_issuer(self, iss: str) -> TrustedAssertionIssuer | None: ...

    async def save(self, issuer: TrustedAssertionIssuer) -> None: ...
