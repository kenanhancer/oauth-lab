"""Inbound port — seed demo clients + users into the configured store.

Used by admin-facing inbound adapters (CLI, admin REST endpoint, scheduled
job). All of them call this single use case so the seeding behaviour
stays in one place.

Returns `SeedDemoDataResult` so each driving adapter can render the
plaintext credentials in whatever way it likes (CLI prints them; an
admin web page shows them in HTML; a Kafka response publishes them to
an audit topic). The plaintext lives in the result *only* for operator
display — the persisted form is always an Argon2 hash.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SeededClient:
    id: str
    secret: str | None
    auth_method: str
    grants: tuple[str, ...]
    scopes: tuple[str, ...]
    audience: str | None


@dataclass(frozen=True, slots=True)
class SeededUser:
    sub: str
    username: str
    password: str
    email: str | None


@dataclass(frozen=True, slots=True)
class SeededTrustedIssuer:
    """A trusted JWT-bearer assertion issuer (RFC 7523).

    The `private_key_pem` is included only for lab/demo purposes — in
    production the AS never sees the private key; the trusted party
    holds it offline and only ships the public key for registration.
    """

    issuer: str
    algorithm: str
    audiences: tuple[str, ...]
    public_key_pem: bytes
    private_key_pem: bytes


@dataclass(frozen=True, slots=True)
class SeedDemoDataResult:
    clients: tuple[SeededClient, ...]
    users: tuple[SeededUser, ...]
    trusted_issuers: tuple[SeededTrustedIssuer, ...] = ()


class SeedDemoDataUseCase(Protocol):
    async def execute(self) -> SeedDemoDataResult: ...
