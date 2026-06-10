"""Inbound port — the OIDC UserInfo endpoint (OIDC Core §5.3).

Takes the raw Bearer access token string; returns the standard claims
the token's scopes allow (OIDC Core §5.4 scope→claims policy). Invalid
or unresolvable tokens raise `InvalidToken` (RFC 6750 §3.1) — the REST
adapter renders that as a 401 Bearer challenge.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class UserInfoResult:
    """The UserInfo claims for one access token (OIDC Core §5.3.2).

    `sub` is always present; the optional fields are populated only when
    the token carried the corresponding scope (§5.4: `profile` →
    `preferred_username`, `email` → `email` + `email_verified`).
    """

    sub: str
    preferred_username: str | None = None
    email: str | None = None
    email_verified: bool | None = None


class GetUserInfoUseCase(Protocol):
    async def execute(self, access_token: str) -> UserInfoResult: ...
