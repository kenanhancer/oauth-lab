"""RandomSource port — abstracts secure random generation for tokens, codes, jti."""

from __future__ import annotations

from typing import Protocol


class RandomSource(Protocol):
    def token_urlsafe(self, n_bytes: int = 32) -> str: ...
