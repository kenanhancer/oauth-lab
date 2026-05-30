"""PyJWT-backed `AssertionVerifier`.

Maps every PyJWT failure mode to a single `InvalidGrant` per RFC 7523
§3.1 — the spec does not define a dedicated error code; all JWT
verification problems collapse to `invalid_grant` at the token
endpoint.

Verifies, in this order:

1. JWS signature (algorithm pinned to the trusted-issuer record;
   prevents `alg=none` and `HS256` confusion attacks).
2. `exp` claim must be present and in the future.
3. `aud` claim must contain `expected_audience` (the AS token endpoint
   URL or another registered audience for the trusted issuer).
4. `iat` and `nbf` validated by PyJWT if present (`require=["exp"]`).

The verifier does NOT enforce `iss` / `sub` shape — those belong to
the grant strategy that called it (separation of concerns: this
adapter is a generic JWT verifier; OAuth semantics live above it).
"""

from __future__ import annotations

from datetime import UTC, datetime

import jwt

from oauth_lab.application.port.outbound.assertion_verifier import AssertionClaims
from oauth_lab.domain.model.errors import InvalidGrant
from oauth_lab.domain.model.trusted_assertion_issuer import TrustedAssertionIssuer


class PyJwtAssertionVerifier:
    def verify(
        self,
        assertion: str,
        *,
        trusted_issuer: TrustedAssertionIssuer,
        expected_audience: str,
    ) -> AssertionClaims:
        try:
            decoded = jwt.decode(
                assertion,
                key=trusted_issuer.public_key_pem,
                algorithms=[trusted_issuer.algorithm],
                audience=expected_audience,
                issuer=trusted_issuer.issuer,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidGrant("assertion has expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise InvalidGrant("assertion not yet valid (nbf in the future)") from exc
        except jwt.InvalidAudienceError as exc:
            raise InvalidGrant("assertion audience does not match this AS") from exc
        except jwt.InvalidIssuerError as exc:
            raise InvalidGrant("assertion issuer does not match trusted record") from exc
        except jwt.InvalidSignatureError as exc:
            raise InvalidGrant("assertion signature is invalid") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise InvalidGrant(f"assertion missing required claim: {exc.claim}") from exc
        except jwt.InvalidTokenError as exc:                                            # catch-all
            raise InvalidGrant(f"assertion is invalid: {exc}") from exc

        aud_claim = decoded["aud"]
        audience: tuple[str, ...]
        audience = (aud_claim,) if isinstance(aud_claim, str) else tuple(aud_claim)

        return AssertionClaims(
            issuer=decoded["iss"],
            subject=decoded["sub"],
            audience=audience,
            expires_at=datetime.fromtimestamp(decoded["exp"], tz=UTC),
            not_before=(
                datetime.fromtimestamp(decoded["nbf"], tz=UTC) if "nbf" in decoded else None
            ),
            issued_at=(
                datetime.fromtimestamp(decoded["iat"], tz=UTC) if "iat" in decoded else None
            ),
            jwt_id=decoded.get("jti"),
        )
