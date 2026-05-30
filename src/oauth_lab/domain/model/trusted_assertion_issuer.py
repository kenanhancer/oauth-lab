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


@dataclass(frozen=True, slots=True)
class TrustedAssertionIssuer:
    issuer: str
    public_key_pem: bytes
    algorithm: str                                                    # e.g. "RS256", "ES256"
    allowed_audiences: frozenset[str]
