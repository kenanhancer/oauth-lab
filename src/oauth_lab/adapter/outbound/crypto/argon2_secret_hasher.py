"""Argon2id implementation of the `SecretHasher` outbound port.

Wraps `argon2.PasswordHasher` with its library defaults (the same
parameters the application services used before the port existed).
Hashes are returned/accepted as UTF-8 bytes to match how the domain
stores them.
"""

from __future__ import annotations

import contextlib

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError


class Argon2SecretHasher:
    def __init__(self) -> None:
        self._hasher = PasswordHasher()
        # Pre-computed throwaway hash so dummy_verify() costs the same
        # argon2 work as a real verify().
        self._dummy_hash = self._hasher.hash("dummy-secret-for-constant-time")

    def hash(self, secret: str) -> bytes:
        return self._hasher.hash(secret).encode("utf-8")

    def verify(self, hashed: bytes, candidate: str) -> bool:
        try:
            return self._hasher.verify(hashed, candidate)
        except (VerifyMismatchError, InvalidHashError):
            return False

    def dummy_verify(self) -> None:
        # The candidate never matches the throwaway hash; we only want the
        # constant-time work, not the result.
        with contextlib.suppress(VerifyMismatchError):
            self._hasher.verify(self._dummy_hash, "candidate-that-never-matches")
