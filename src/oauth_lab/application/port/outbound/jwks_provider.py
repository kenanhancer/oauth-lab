"""Outbound port — JWKS document provider.

Concrete implementation: `oauth_lab.adapter.outbound.crypto.jwks_provider`.
Used by the JWKS controller (`/jwks`) and the `/userinfo` controller
(for JWT verification against the public key).
"""

from __future__ import annotations

from typing import Any, Protocol


class JwksProvider(Protocol):
    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        """The JWKS JSON document — RFC 7517 §5."""
        ...

    def public_pem(self) -> bytes:
        """The signing key's public half in PEM form (for local verification)."""
        ...
