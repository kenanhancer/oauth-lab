"""JWT-backed `AccessTokenVerifier` — RFC 9068-style access tokens.

Verifies access tokens this AS itself signed: PyJWT checks the
signature (pinned to the configured algorithm — never the token
header's), temporal claims, and the `iss` claim pinned to this AS.
`exp` and `sub` are required to be present. `aud` is deliberately NOT
verified: an access token's audience names the protected *resource*,
not the AS, and `/userinfo` accepts tokens minted for any resource.

Every PyJWT failure maps to the domain `InvalidToken` (RFC 6750 §3.1).
"""

from __future__ import annotations

import jwt

from oauth_lab.application.port.outbound.access_token_verifier import AccessTokenClaims
from oauth_lab.domain.model.errors import InvalidToken
from oauth_lab.domain.model.scope import ScopeSet


class JwtAccessTokenVerifier:
    def __init__(self, *, issuer: str, public_key_pem: bytes, algorithm: str) -> None:
        self._issuer = issuer
        self._public_key = public_key_pem
        self._algorithm = algorithm

    def verify(self, token: str) -> AccessTokenClaims:
        try:
            decoded = jwt.decode(
                token,
                key=self._public_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                options={
                    "require": ["exp", "sub"],
                    "verify_aud": False,  # aud names the resource, not the AS
                },
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken(str(exc)) from exc

        sub = decoded.get("sub")
        raw_scope = decoded.get("scope")
        try:
            scope = ScopeSet.parse(raw_scope if isinstance(raw_scope, str) else None)
        except ValueError as exc:
            raise InvalidToken(f"malformed scope claim: {exc}") from exc

        return AccessTokenClaims(
            sub=sub if isinstance(sub, str) else None,
            scope=scope,
        )
