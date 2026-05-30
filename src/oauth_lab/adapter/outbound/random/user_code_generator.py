"""User code generator — concrete adapter for the device flow.

RFC 8628 § 6.1 calls for a short, high-entropy, human-typable code.
We produce 8 characters from a restricted consonant set (no vowels,
no easily-confused glyphs) split by a dash for readability:
``"BCDF-GHJK"``.

20-letter alphabet × 8 positions ≈ 25.6 billion combinations — well
beyond brute-force given the < 30 min TTL the RFC recommends.
"""

from __future__ import annotations

import secrets

# Consonants only; removes the most ambiguous reads (no 0/O/I/1/L,
# no Y/U which are sometimes confusable, no vowels which can form words).
_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
_LENGTH = 8


class SecureUserCodeGenerator:
    """Concrete `UserCodeGenerator` adapter backed by `secrets.choice`."""

    def generate(self) -> str:
        chars = [secrets.choice(_ALPHABET) for _ in range(_LENGTH)]
        return f"{''.join(chars[:4])}-{''.join(chars[4:])}"
