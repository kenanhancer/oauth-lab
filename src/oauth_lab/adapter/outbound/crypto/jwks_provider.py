"""JWKS provider — exposes the public half of the signing key as JWK JSON.

Concrete adapter implementing `oauth_lab.application.port.outbound.jwks_provider.JwksProvider`.

The format is RFC 7517 (JSON Web Key). For RSA keys with `kty=RSA` we
need `kid`, `use=sig`, `alg`, `n`, `e`. PyJWT's `RSAAlgorithm.to_jwk`
handles the (n, e) conversion correctly (base64url-encoded big-endian
without padding).
"""

from __future__ import annotations

import json
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization


class RsaJwksProvider:
    """Concrete `JwksProvider` for a single RSA keypair."""

    def __init__(self, *, private_key_pem: bytes, kid: str, algorithm: str) -> None:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        public_key = private_key.public_key()                                            # type: ignore[attr-defined]
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        jwk_str = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=False)          # type: ignore[arg-type]
        jwk: dict[str, Any] = json.loads(jwk_str)
        jwk["kid"] = kid
        jwk["use"] = "sig"
        jwk["alg"] = algorithm
        self._jwk = jwk
        self._public_pem = public_pem

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {"keys": [dict(self._jwk)]}

    def public_pem(self) -> bytes:
        return self._public_pem
