"""SeedDemoDataService — implements `SeedDemoDataUseCase`.

The seeding *business* lives here: which demo clients to register, which
demo user to create, how to hash secrets. Driving adapters (CLI, admin
REST, scheduled job) only invoke `execute()` and render the result.

Idempotent — a second invocation updates existing rows (`save()` on
each repository is upsert-style).
"""

from __future__ import annotations

from dataclasses import dataclass

from argon2 import PasswordHasher

from oauth_lab.adapter.outbound.crypto.key_generator import (
    generate_rsa_keypair_pem,
    public_key_pem_from_private,
)
from oauth_lab.application.port.inbound.seed_demo_data_use_case import (
    SeedDemoDataResult,
    SeededClient,
    SeededTrustedIssuer,
    SeededUser,
)
from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.application.port.outbound.trusted_assertion_issuer_repository import (
    TrustedAssertionIssuerRepository,
)
from oauth_lab.application.port.outbound.user_repository import UserRepository
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import Scope, ScopeSet
from oauth_lab.domain.model.trusted_assertion_issuer import TrustedAssertionIssuer
from oauth_lab.domain.model.user import User


@dataclass(frozen=True, slots=True)
class _ClientSpec:
    id: str
    secret: str | None
    auth_method: ClientAuthMethod
    grants: frozenset[GrantType]
    scopes: tuple[str, ...]
    audience: str | None = None


@dataclass(frozen=True, slots=True)
class _UserSpec:
    sub: str
    username: str
    password: str
    email: str | None = None


@dataclass(frozen=True, slots=True)
class _TrustedIssuerSpec:
    issuer: str
    algorithm: str
    audiences: tuple[str, ...]


# Demo data — extend by adding to these tuples.
_DEMO_CLIENTS: tuple[_ClientSpec, ...] = (
    _ClientSpec(
        id="demo-client",
        secret="demo-secret",                                                            # noqa: S106
        auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        grants=frozenset({GrantType.CLIENT_CREDENTIALS}),
        scopes=("read", "write"),
        audience="https://api.example.com",
    ),
    _ClientSpec(
        id="demo-spa",
        secret=None,                                                                     # public
        auth_method=ClientAuthMethod.NONE,
        grants=frozenset({GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN}),
        scopes=("read", "write"),
        audience="https://api.example.com",
    ),
    _ClientSpec(
        id="demo-device",
        secret=None,                                                                     # public
        auth_method=ClientAuthMethod.NONE,
        grants=frozenset({GrantType.DEVICE_CODE, GrantType.REFRESH_TOKEN}),
        scopes=("read", "write"),
        audience="https://api.example.com",
    ),
    _ClientSpec(
        id="demo-jwt-bearer",
        secret="demo-jwt-bearer-secret",                                                 # noqa: S106
        auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        grants=frozenset({GrantType.JWT_BEARER}),
        scopes=("read", "write"),
        audience="https://api.example.com",
    ),
    _ClientSpec(
        id="demo-exchange",
        secret="demo-exchange-secret",                                                   # noqa: S106
        auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        grants=frozenset({GrantType.CLIENT_CREDENTIALS, GrantType.TOKEN_EXCHANGE}),
        scopes=("read", "write"),
        audience="https://api.example.com",
    ),
)

_DEMO_USERS: tuple[_UserSpec, ...] = (
    _UserSpec(
        sub="user-alice",
        username="alice",
        password="alice-password",                                                       # noqa: S106
        email="alice@example.com",
    ),
)

# Public SPA needs a registered redirect URI; without one /authorize would
# render an error page rather than redirect.
_PUBLIC_REDIRECT_URIS = frozenset({"http://localhost:8080/callback"})


# RFC 7523 trusted-issuer registrations. Each one gets a fresh RSA
# keypair generated at seed time — the private key is shown to the
# operator so they can sign demo assertions; in production the AS
# never holds the private key.
_DEMO_TRUSTED_ISSUERS: tuple[_TrustedIssuerSpec, ...] = (
    _TrustedIssuerSpec(
        issuer="https://idp.example.com",
        algorithm="RS256",
        audiences=("http://localhost:8000/token",),
    ),
)


class SeedDemoDataService:
    def __init__(
        self,
        *,
        clients: ClientRepository,
        users: UserRepository,
        trusted_issuers: TrustedAssertionIssuerRepository,
    ) -> None:
        self._clients = clients
        self._users = users
        self._trusted_issuers = trusted_issuers
        self._hasher = PasswordHasher()

    async def execute(self) -> SeedDemoDataResult:
        seeded_clients: list[SeededClient] = []
        for spec in _DEMO_CLIENTS:
            secret_hash: bytes | None = None
            if spec.secret is not None:
                secret_hash = self._hasher.hash(spec.secret).encode("utf-8")
            client = Client(
                id=ClientId(spec.id),
                secret_hash=secret_hash,
                token_endpoint_auth_method=spec.auth_method,
                allowed_grant_types=spec.grants,
                allowed_scopes=ScopeSet(frozenset(Scope(s) for s in spec.scopes)),
                redirect_uris=_PUBLIC_REDIRECT_URIS if spec.secret is None else frozenset(),
                default_audience=spec.audience,
            )
            await self._clients.save(client)
            seeded_clients.append(
                SeededClient(
                    id=spec.id,
                    secret=spec.secret,
                    auth_method=spec.auth_method.value,
                    grants=tuple(g.value for g in spec.grants),
                    scopes=spec.scopes,
                    audience=spec.audience,
                )
            )

        seeded_users: list[SeededUser] = []
        for u_spec in _DEMO_USERS:
            user = User(
                sub=u_spec.sub,
                username=u_spec.username,
                password_hash=self._hasher.hash(u_spec.password).encode("utf-8"),
                email=u_spec.email,
            )
            await self._users.save(user)
            seeded_users.append(
                SeededUser(
                    sub=u_spec.sub,
                    username=u_spec.username,
                    password=u_spec.password,
                    email=u_spec.email,
                )
            )

        seeded_issuers: list[SeededTrustedIssuer] = []
        for ti_spec in _DEMO_TRUSTED_ISSUERS:
            private_pem = generate_rsa_keypair_pem()
            public_pem = public_key_pem_from_private(private_pem)
            trusted = TrustedAssertionIssuer(
                issuer=ti_spec.issuer,
                public_key_pem=public_pem,
                algorithm=ti_spec.algorithm,
                allowed_audiences=frozenset(ti_spec.audiences),
            )
            await self._trusted_issuers.save(trusted)
            seeded_issuers.append(
                SeededTrustedIssuer(
                    issuer=ti_spec.issuer,
                    algorithm=ti_spec.algorithm,
                    audiences=ti_spec.audiences,
                    public_key_pem=public_pem,
                    private_key_pem=private_pem,
                )
            )

        return SeedDemoDataResult(
            clients=tuple(seeded_clients),
            users=tuple(seeded_users),
            trusted_issuers=tuple(seeded_issuers),
        )
