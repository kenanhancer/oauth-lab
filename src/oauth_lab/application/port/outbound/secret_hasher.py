"""Outbound port — password / client-secret hashing.

Hashed values travel as `bytes` because that is how the domain stores
them (`Client.secret_hash`, `User.password_hash`). The concrete adapter
(Argon2id) lives under `oauth_lab.adapter.outbound.crypto`.
"""

from __future__ import annotations

from typing import Protocol


class SecretHasher(Protocol):
    def hash(self, secret: str) -> bytes: ...

    def verify(self, hashed: bytes, candidate: str) -> bool:
        """True if `candidate` matches `hashed`; False on mismatch (no exception)."""
        ...

    def dummy_verify(self) -> None:
        """Burn the same work as `verify()` and discard the result.

        Timing equalisation for unknown principals: when the client/user
        does not exist there is no stored hash to check, but the rejection
        must cost the same as a real verification — otherwise an attacker
        can enumerate principals by latency.
        """
        ...
