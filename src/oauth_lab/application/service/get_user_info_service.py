"""GetUserInfoService — OIDC Core §5.3 UserInfo behind the hexagon.

Pipeline: verify the access token (outbound `AccessTokenVerifier`) →
resolve the resource owner (`UserRepository`) → release only the claims
the token's scopes allow (OIDC Core §5.4):

- `profile` → `preferred_username`
- `email`   → `email` + `email_verified`

A token without a resolvable subject cannot answer "who is this user",
so both a missing `sub` claim and an unknown subject raise
`InvalidToken` (RFC 6750 §3.1 — the protected-resource vocabulary).
"""

from __future__ import annotations

from oauth_lab.application.port.inbound.get_user_info_use_case import UserInfoResult
from oauth_lab.application.port.outbound.access_token_verifier import AccessTokenVerifier
from oauth_lab.application.port.outbound.user_repository import UserRepository
from oauth_lab.domain.model.errors import InvalidToken
from oauth_lab.domain.model.scope import Scope

_PROFILE = Scope("profile")
_EMAIL = Scope("email")


class GetUserInfoService:
    def __init__(self, *, token_verifier: AccessTokenVerifier, users: UserRepository) -> None:
        self._token_verifier = token_verifier
        self._users = users

    async def execute(self, access_token: str) -> UserInfoResult:
        claims = self._token_verifier.verify(access_token)

        if claims.sub is None:
            raise InvalidToken("access token has no `sub` claim")
        user = await self._users.find_by_sub(claims.sub)
        if user is None:
            raise InvalidToken("access token subject is not a known user")

        granted = claims.scope.scopes
        preferred_username = user.username if _PROFILE in granted else None
        email = user.email if _EMAIL in granted and user.email is not None else None
        return UserInfoResult(
            sub=user.sub,
            preferred_username=preferred_username,
            email=email,
            email_verified=True if email is not None else None,       # demo default
        )
