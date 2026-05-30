"""TokenIssuer port — abstracts opaque vs JWT access token issuance.

Concrete implementations live under `adapter/outbound/crypto/`. The Factory
in `adapter/outbound/crypto/token_issuer_factory.py` selects between them
based on AS policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class IssuedToken:
    value: str
    expires_in_seconds: int


class TokenIssuer(Protocol):
    async def issue(
        self,
        *,
        subject: str,
        client_id: str,
        scope: ScopeSet,
        audience: str | None,
        ttl_seconds: int,
    ) -> IssuedToken: ...
