"""Outbound port — asymmetric keypair generation.

The demo seeder mints a fresh keypair per trusted assertion issuer
(RFC 7523 registrations): the public half is stored for verification,
the private half is handed to the operator for signing demo assertions.
PEM `bytes` match how `TrustedAssertionIssuer.public_key_pem` is stored.
The concrete adapter (RSA via `cryptography`) lives under
`oauth_lab.adapter.outbound.crypto`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class KeyPairPem:
    private_pem: bytes
    public_pem: bytes


class KeyPairGenerator(Protocol):
    def generate(self) -> KeyPairPem: ...
