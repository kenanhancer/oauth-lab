"""TokenIssuerFactory — chooses opaque vs JWT issuer based on AS policy.

The Factory pattern fits here because the *choice* is config-driven (per AS,
optionally per client). A Strategy chosen at request time would be wrong
abstraction — the format is fixed by configuration, not by the request.
"""

from __future__ import annotations

from enum import StrEnum

from oauth_lab.adapter.outbound.crypto.jwt_token_issuer import JwtTokenIssuer
from oauth_lab.adapter.outbound.crypto.opaque_token_issuer import OpaqueTokenIssuer
from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.random_source import RandomSource
from oauth_lab.application.port.outbound.token_issuer import TokenIssuer


class TokenFormat(StrEnum):
    OPAQUE = "opaque"
    JWT = "jwt"


class TokenIssuerFactory:
    def __init__(
        self,
        *,
        token_format: TokenFormat,
        issuer: str,
        signing_key_pem: bytes | None,
        key_id: str | None,
        algorithm: str,
        clock: Clock,
        random_source: RandomSource,
    ) -> None:
        self._token_format = token_format
        self._issuer = issuer
        self._signing_key_pem = signing_key_pem
        self._key_id = key_id
        self._algorithm = algorithm
        self._clock = clock
        self._random = random_source

    def build(self) -> TokenIssuer:
        if self._token_format is TokenFormat.OPAQUE:
            return OpaqueTokenIssuer(random_source=self._random)
        if self._signing_key_pem is None or self._key_id is None:
            raise RuntimeError("OAUTH_LAB_TOKEN_FORMAT=jwt requires a signing key and key_id")
        return JwtTokenIssuer(
            issuer=self._issuer,
            signing_key_pem=self._signing_key_pem,
            key_id=self._key_id,
            algorithm=self._algorithm,
            clock=self._clock,
            random_source=self._random,
        )
