"""TrustedAssertionIssuer — an external party we trust to sign JWT
assertions on behalf of users (RFC 7523 §3).

When a caller posts `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`
with an `assertion=<JWT>`, the AS:

1. Decodes the JWT header + payload (without verifying yet)
2. Looks up the issuer by the JWT's `iss` claim
3. Verifies the signature using the registered public key + algorithm
4. Checks the `aud`, `exp`, `nbf`, `iat` claims

The trusted issuer's public key is stored in PEM form — verifying
adapters convert to whatever form their JWT library needs.
"""

from __future__ import annotations

from dataclasses import dataclass

# Asymmetric JWS algorithms only — `none` and HMAC (`HS*`) are rejected so a
# trusted issuer record can never be configured to accept a symmetric-key or
# unsigned assertion (RFC 7518 §3.1; the same allow-list as `Settings`).
_ALLOWED_ALGORITHMS: frozenset[str] = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
)


@dataclass(frozen=True, slots=True)
class TrustedAssertionIssuer:
    issuer: str
    public_key_pem: bytes
    algorithm: str  # e.g. "RS256", "ES256"
    allowed_audiences: frozenset[str]

    def __post_init__(self) -> None:
        if self.algorithm not in _ALLOWED_ALGORITHMS:
            raise ValueError(
                f"unsupported assertion algorithm {self.algorithm!r}; "
                f"must be one of {sorted(_ALLOWED_ALGORITHMS)}"
            )
        if not self.public_key_pem:
            raise ValueError("public_key_pem must not be empty")
        if not self.allowed_audiences:
            raise ValueError("allowed_audiences must not be empty")
