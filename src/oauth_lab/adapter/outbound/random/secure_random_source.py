"""SecureRandomSource — `RandomSource` adapter using `secrets`."""

from __future__ import annotations

import secrets


class SecureRandomSource:
    def token_urlsafe(self, n_bytes: int = 32) -> str:
        return secrets.token_urlsafe(n_bytes)
