"""JWT access token issuer — RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens).

Self-contained tokens: the resource server can verify against the AS's JWKS
without an introspection call. Trade-off: revocation is harder.
"""

from __future__ import annotations

from datetime import timedelta

import jwt

from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.random_source import RandomSource
from oauth_lab.application.port.outbound.token_issuer import IssuedToken
from oauth_lab.domain.model.scope import ScopeSet


class JwtTokenIssuer:
    def __init__(
        self,
        *,
        issuer: str,
        signing_key_pem: bytes,
        key_id: str,
        algorithm: str,
        clock: Clock,
        random_source: RandomSource,
    ) -> None:
        self._issuer = issuer
        self._signing_key = signing_key_pem
        self._key_id = key_id
        self._algorithm = algorithm
        self._clock = clock
        self._random = random_source

    async def issue(
        self,
        *,
        subject: str,
        client_id: str,
        scope: ScopeSet,
        audience: str | None,
        ttl_seconds: int,
    ) -> IssuedToken:
        now = self._clock.now()
        claims: dict[str, object] = {
            "iss": self._issuer,
            "sub": subject,
            "client_id": client_id,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "jti": self._random.token_urlsafe(16),
        }
        if audience:
            claims["aud"] = audience
        if not scope.is_empty():
            claims["scope"] = scope.to_str()

        token = jwt.encode(
            claims,
            self._signing_key,
            algorithm=self._algorithm,
            headers={"kid": self._key_id, "typ": "at+jwt"},
        )
        return IssuedToken(value=token, expires_in_seconds=ttl_seconds)
