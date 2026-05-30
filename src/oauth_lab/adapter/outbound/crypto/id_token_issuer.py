"""ID Token issuer — OIDC Core 1.0 § 2.

Concrete adapter implementing `oauth_lab.application.port.outbound.id_token_issuer.IdTokenIssuer`.

An ID token is always a JWT. Required claims (OIDC Core § 2):
- `iss`: AS issuer URL
- `sub`: stable user identifier
- `aud`: client_id of the requesting client
- `exp`, `iat`: lifetime
- `auth_time` (when `max_age` was sent or `auth_time` essential claim)
- `nonce` (when sent by the client at `/authorize`)

Plus `at_hash` per OIDC Core § 3.1.3.6 to bind the id_token to the
issued access token.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta

import jwt

from oauth_lab.application.port.outbound.clock import Clock


class JwtIdTokenIssuer:
    """Concrete `IdTokenIssuer` adapter that mints JWT id_tokens."""

    def __init__(
        self,
        *,
        issuer: str,
        signing_key_pem: bytes,
        key_id: str,
        algorithm: str,
        clock: Clock,
    ) -> None:
        self._issuer = issuer
        self._signing_key = signing_key_pem
        self._key_id = key_id
        self._algorithm = algorithm
        self._clock = clock

    async def issue(
        self,
        *,
        subject: str,
        audience: str,
        access_token: str | None = None,
        nonce: str | None = None,
        auth_time: datetime | None = None,
        ttl_seconds: int = 300,
    ) -> str:
        now = self._clock.now()
        claims: dict[str, object] = {
            "iss": self._issuer,
            "sub": subject,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        }
        if auth_time is not None:
            claims["auth_time"] = int(auth_time.timestamp())
        if nonce is not None:
            claims["nonce"] = nonce
        if access_token is not None:
            claims["at_hash"] = _compute_at_hash(access_token, self._algorithm)

        return jwt.encode(
            claims,
            self._signing_key,
            algorithm=self._algorithm,
            headers={"kid": self._key_id, "typ": "JWT"},
        )


# OIDC Core § 3.1.3.6: the at_hash digest is the hash used by the id_token's
# signing algorithm — SHA-256 for *256 algs, SHA-384 for *384, SHA-512 for *512.
_AT_HASH_DIGEST: dict[str, str] = {
    "RS256": "sha256", "ES256": "sha256", "PS256": "sha256",
    "RS384": "sha384", "ES384": "sha384", "PS384": "sha384",
    "RS512": "sha512", "ES512": "sha512", "PS512": "sha512",
}


def _compute_at_hash(access_token: str, algorithm: str) -> str:
    """OIDC Core § 3.1.3.6 — base64url(left-half(H(access_token))).

    H is the hash function paired with the id_token signing `algorithm`
    (e.g. RS384 → SHA-384), not always SHA-256.
    """
    digest_name = _AT_HASH_DIGEST[algorithm]
    digest = hashlib.new(digest_name, access_token.encode("ascii")).digest()
    half = digest[: len(digest) // 2]
    return base64.urlsafe_b64encode(half).rstrip(b"=").decode("ascii")
