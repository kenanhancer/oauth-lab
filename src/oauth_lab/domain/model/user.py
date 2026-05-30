"""User entity — the resource owner.

`sub` is the OIDC subject (stable unique identifier — appears in the JWT
`sub` claim and the `/userinfo` response). `username` is what the user
types into the login form.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class User:
    sub: str
    username: str
    password_hash: bytes
    email: str | None = None
