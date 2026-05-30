"""Outbound port — OIDC id_token issuance.

Concrete implementation: `oauth_lab.adapter.outbound.crypto.id_token_issuer`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class IdTokenIssuer(Protocol):
    async def issue(
        self,
        *,
        subject: str,
        audience: str,
        access_token: str | None = None,
        nonce: str | None = None,
        auth_time: datetime | None = None,
        ttl_seconds: int = 300,
    ) -> str: ...
