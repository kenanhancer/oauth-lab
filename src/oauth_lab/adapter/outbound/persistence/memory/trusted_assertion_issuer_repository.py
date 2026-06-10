"""In-memory `TrustedAssertionIssuerRepository` — tests + lab mode."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from oauth_lab.domain.model.trusted_assertion_issuer import TrustedAssertionIssuer


class InMemoryTrustedAssertionIssuerRepository:
    def __init__(self, initial: Iterable[TrustedAssertionIssuer] = ()) -> None:
        """`initial` pre-populates the store synchronously — fixtures can
        seed issuers without an event loop (the async `save` needs one)."""
        self._by_iss: dict[str, TrustedAssertionIssuer] = {
            issuer.issuer: issuer for issuer in initial
        }
        self._lock = asyncio.Lock()

    async def find_by_issuer(self, iss: str) -> TrustedAssertionIssuer | None:
        async with self._lock:
            return self._by_iss.get(iss)

    async def save(self, issuer: TrustedAssertionIssuer) -> None:
        async with self._lock:
            self._by_iss[issuer.issuer] = issuer
