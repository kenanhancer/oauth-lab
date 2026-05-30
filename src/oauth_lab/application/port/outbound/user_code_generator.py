"""Outbound port — generates the short human-typable `user_code` for
the device flow (RFC 8628 § 6.1).

Concrete impl: `oauth_lab.adapter.outbound.random.user_code_generator`.
"""

from __future__ import annotations

from typing import Protocol


class UserCodeGenerator(Protocol):
    def generate(self) -> str:
        """Return a fresh user_code, e.g. ``"BCDF-GHJK"``."""
        ...
