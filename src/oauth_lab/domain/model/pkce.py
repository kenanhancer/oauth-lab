"""PKCE value object — RFC 7636 § 4.1–4.3, plus OAuth 2.1 § 4.8 (S256-only).

A `PKCEChallenge` carries the `code_challenge` and `code_challenge_method`
that arrive at `/authorize` and must later match the `code_verifier`
presented at `/token`. The verification itself lives in
`domain/service/pkce_verifier.py`.

OAuth 2.1 forbids `code_challenge_method=plain` (downgrade attack);
RFC 9700 § 4.8 reiterates this. We accept only `S256`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# RFC 7636 § 4.2: code_challenge / code_verifier ABNF
#   = 43*128 unreserved   where unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
_UNRESERVED_RE = re.compile(r"^[A-Za-z0-9\-._~]+$")

_MIN_LEN = 43
_MAX_LEN = 128


@dataclass(frozen=True, slots=True)
class PKCEChallenge:
    value: str
    method: str = "S256"

    def __post_init__(self) -> None:
        if self.method != "S256":
            raise ValueError(
                f"code_challenge_method must be 'S256' (OAuth 2.1 forbids 'plain'); "
                f"got {self.method!r}"
            )
        if not _MIN_LEN <= len(self.value) <= _MAX_LEN:
            raise ValueError(
                f"code_challenge length must be {_MIN_LEN}-{_MAX_LEN}; "
                f"got {len(self.value)}"
            )
        if not _UNRESERVED_RE.match(self.value):
            raise ValueError("code_challenge contains characters outside the unreserved set")


def is_valid_code_verifier(code_verifier: str) -> bool:
    """Surface-level shape check for an incoming `code_verifier`.

    Returns False instead of raising so the caller can use it as a guard
    inside an authentication path without try/except. Actual hash
    comparison is done by `PKCEVerifier`.
    """
    return _MIN_LEN <= len(code_verifier) <= _MAX_LEN and bool(
        _UNRESERVED_RE.match(code_verifier)
    )
