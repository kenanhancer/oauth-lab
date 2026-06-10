"""JWKS provider — exposes the public half of the signing key as JWK JSON.

Concrete adapter implementing `oauth_lab.application.port.outbound.jwks_provider.JwksProvider`.

The format is RFC 7517 (JSON Web Key). For RSA keys with `kty=RSA` we
need `kid`, `use=sig`, `alg`, `n`, `e`. PyJWT's `RSAAlgorithm.to_jwk`
handles the (n, e) conversion correctly (base64url-encoded big-endian
without padding).
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def rsa_jwk_thumbprint(private_key_pem: bytes) -> str:
    """RFC 7638 JWK Thumbprint (SHA-256) of an RSA public key, base64url.

    Derived from the *public* half so it is stable for a given keypair and
    safe to publish as `kid`. Per RFC 7638 §3.2 the required members for an
    RSA key are exactly `{"e", "kty", "n"}`, serialised as compact JSON with
    keys in lexicographic order and no whitespace, then SHA-256-hashed.

    Using the thumbprint as `kid` means every distinct (e.g. ephemeral,
    per-replica) signing key advertises a distinct `kid`, so a verifier can
    select the right JWKS entry even when several replicas publish keys —
    the static literal `kid` they used to share collided.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    public_key = cast(RSAPublicKey, private_key.public_key())
    jwk: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=False))
    canonical = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class RsaJwksProvider:
    """Concrete `JwksProvider` for a single RSA keypair."""

    def __init__(self, *, private_key_pem: bytes, kid: str, algorithm: str) -> None:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        public_key = cast(RSAPublicKey, private_key.public_key())
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        jwk_str = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=False)
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
