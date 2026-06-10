"""JWT-backed `SubjectTokenValidator`.

Validates `subject_token` values that this AS itself signed — the
common "exchange one of my own tokens for a narrower one" pattern.
PyJWT does the heavy lifting (sig + temporal checks); we map every
PyJWT exception to `InvalidGrant` per RFC 8693 §2.2.1.

Only token types we can actually decode as a JWT are accepted:
`:access_token` (when the AS runs in JWT mode), `:id_token`, `:jwt`.
For opaque-token mode the access-token URI is rejected, because we
cannot introspect an opaque token from a string alone.
"""

from __future__ import annotations

from datetime import UTC, datetime

import jwt

from oauth_lab.application.port.outbound.subject_token_validator import SubjectTokenClaims
from oauth_lab.domain.model.errors import InvalidGrant, InvalidRequest
from oauth_lab.domain.model.scope import Scope, ScopeSet
from oauth_lab.domain.model.token_type_uri import TokenTypeURI

_JWT_DECODABLE_TYPES: frozenset[str] = frozenset(
    {
        TokenTypeURI.ACCESS_TOKEN.value,  # AS in JWT mode
        TokenTypeURI.ID_TOKEN.value,
        TokenTypeURI.JWT.value,
    }
)


class JwtSubjectTokenValidator:
    def __init__(self, *, issuer: str, public_key_pem: bytes, algorithm: str) -> None:
        self._issuer = issuer
        self._public_key = public_key_pem
        self._algorithm = algorithm

    def validate(self, token: str, token_type: str) -> SubjectTokenClaims:
        if token_type not in _JWT_DECODABLE_TYPES:
            raise InvalidRequest(f"subject_token_type {token_type!r} is not supported by this AS")

        try:
            decoded = jwt.decode(
                token,
                key=self._public_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                options={
                    "require": ["exp", "iss", "sub"],
                    "verify_aud": False,  # checked at policy layer
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidGrant("subject_token has expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise InvalidGrant("subject_token issuer is not this AS") from exc
        except jwt.InvalidSignatureError as exc:
            raise InvalidGrant("subject_token signature is invalid") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise InvalidGrant(f"subject_token missing required claim: {exc.claim}") from exc
        except jwt.InvalidTokenError as exc:
            raise InvalidGrant(f"subject_token is invalid: {exc}") from exc

        aud_claim = decoded.get("aud")
        if aud_claim is None:
            audience: tuple[str, ...] = ()
        elif isinstance(aud_claim, str):
            audience = (aud_claim,)
        else:
            audience = tuple(aud_claim)

        scope_str = decoded.get("scope", "")
        scope = ScopeSet(frozenset(Scope(s) for s in scope_str.split() if s))

        return SubjectTokenClaims(
            subject=decoded["sub"],
            client_id=decoded.get("client_id"),
            issuer=decoded["iss"],
            audience=audience,
            scope=scope,
            expires_at=datetime.fromtimestamp(decoded["exp"], tz=UTC),
        )
