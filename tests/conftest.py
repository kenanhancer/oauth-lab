"""Shared pytest fixtures.

Integration tests use an `InMemoryClientRepository` injected into the
container — never touch a real database. Unit tests don't go through the
container at all.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from oauth_lab.adapter.outbound.crypto.argon2_secret_hasher import Argon2SecretHasher
from oauth_lab.adapter.outbound.crypto.key_generator import (
    generate_rsa_keypair_pem,
    public_key_pem_from_private,
)
from oauth_lab.adapter.outbound.persistence.memory.client_repository import (
    InMemoryClientRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.trusted_assertion_issuer_repository import (
    InMemoryTrustedAssertionIssuerRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.user_repository import InMemoryUserRepository
from oauth_lab.config import Settings
from oauth_lab.container import Container, build_container
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import Scope, ScopeSet
from oauth_lab.domain.model.trusted_assertion_issuer import TrustedAssertionIssuer
from oauth_lab.domain.model.user import User
from oauth_lab.main import create_app

DEMO_CLIENT_ID = "demo-client"
DEMO_CLIENT_SECRET = "demo-secret"
DEMO_PUBLIC_CLIENT_ID = "demo-spa"
DEMO_PUBLIC_CLIENT_REDIRECT_URI = "http://localhost:8080/callback"
DEMO_DEVICE_CLIENT_ID = "demo-device"
DEMO_JWT_BEARER_CLIENT_ID = "demo-jwt-bearer"
DEMO_JWT_BEARER_CLIENT_SECRET = "demo-jwt-bearer-secret"
DEMO_EXCHANGE_CLIENT_ID = "demo-exchange"
DEMO_EXCHANGE_CLIENT_SECRET = "demo-exchange-secret"
DEMO_TRUSTED_ISSUER = "https://idp.example.com"
DEMO_TOKEN_AUDIENCE = "http://localhost:8000/token"                  # AS issuer + /token

DEMO_USER_SUB = "user-alice"
DEMO_USERNAME = "alice"
DEMO_USER_PASSWORD = "alice-password"


@pytest.fixture
def demo_clients() -> InMemoryClientRepository:
    """Three fixture clients: confidential M2M + public SPA (browser) + public device."""
    hasher = Argon2SecretHasher()
    confidential = Client(
        id=ClientId(DEMO_CLIENT_ID),
        secret_hash=hasher.hash(DEMO_CLIENT_SECRET),
        token_endpoint_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        allowed_grant_types=frozenset({GrantType.CLIENT_CREDENTIALS}),
        allowed_scopes=ScopeSet(frozenset({Scope("read"), Scope("write")})),
        default_audience="https://api.example.com",
    )
    public_spa = Client(
        id=ClientId(DEMO_PUBLIC_CLIENT_ID),
        secret_hash=None,                                          # public — no secret
        token_endpoint_auth_method=ClientAuthMethod.NONE,
        allowed_grant_types=frozenset(
            {GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN}
        ),
        allowed_scopes=ScopeSet(frozenset({Scope("read"), Scope("write")})),
        redirect_uris=frozenset({DEMO_PUBLIC_CLIENT_REDIRECT_URI}),
        default_audience="https://api.example.com",
    )
    public_device = Client(
        id=ClientId(DEMO_DEVICE_CLIENT_ID),
        secret_hash=None,                                          # public — no secret
        token_endpoint_auth_method=ClientAuthMethod.NONE,
        allowed_grant_types=frozenset(
            {GrantType.DEVICE_CODE, GrantType.REFRESH_TOKEN}
        ),
        allowed_scopes=ScopeSet(frozenset({Scope("read"), Scope("write")})),
        default_audience="https://api.example.com",
    )
    jwt_bearer_client = Client(
        id=ClientId(DEMO_JWT_BEARER_CLIENT_ID),
        secret_hash=hasher.hash(DEMO_JWT_BEARER_CLIENT_SECRET),
        token_endpoint_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        allowed_grant_types=frozenset({GrantType.JWT_BEARER}),
        allowed_scopes=ScopeSet(frozenset({Scope("read"), Scope("write")})),
        default_audience="https://api.example.com",
    )
    exchange_client = Client(
        id=ClientId(DEMO_EXCHANGE_CLIENT_ID),
        secret_hash=hasher.hash(DEMO_EXCHANGE_CLIENT_SECRET),
        token_endpoint_auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC,
        allowed_grant_types=frozenset(
            {GrantType.CLIENT_CREDENTIALS, GrantType.TOKEN_EXCHANGE}
        ),
        allowed_scopes=ScopeSet(frozenset({Scope("read"), Scope("write")})),
        default_audience="https://api.example.com",
    )
    return InMemoryClientRepository(
        {
            confidential.id: confidential,
            public_spa.id: public_spa,
            public_device.id: public_device,
            jwt_bearer_client.id: jwt_bearer_client,
            exchange_client.id: exchange_client,
        }
    )


@pytest.fixture(scope="session")
def jwt_bearer_keypair() -> tuple[bytes, bytes]:
    """A single RSA keypair for signing/verifying jwt-bearer assertions in tests."""
    private_pem = generate_rsa_keypair_pem()
    public_pem = public_key_pem_from_private(private_pem)
    return private_pem, public_pem


@pytest.fixture
def trusted_issuers(
    jwt_bearer_keypair: tuple[bytes, bytes],
) -> InMemoryTrustedAssertionIssuerRepository:
    _private_pem, public_pem = jwt_bearer_keypair
    repo = InMemoryTrustedAssertionIssuerRepository()
    # Seed synchronously by writing to the internal dict — the test event
    # loop isn't running yet at fixture collection time.
    repo._by_iss[DEMO_TRUSTED_ISSUER] = TrustedAssertionIssuer(
        issuer=DEMO_TRUSTED_ISSUER,
        public_key_pem=public_pem,
        algorithm="RS256",
        allowed_audiences=frozenset({DEMO_TOKEN_AUDIENCE}),
    )
    return repo


@pytest.fixture
def demo_users() -> InMemoryUserRepository:
    hasher = Argon2SecretHasher()
    alice = User(
        sub=DEMO_USER_SUB,
        username=DEMO_USERNAME,
        password_hash=hasher.hash(DEMO_USER_PASSWORD),
        email="alice@example.com",
    )
    return InMemoryUserRepository({alice.sub: alice})


@pytest.fixture
async def container(
    demo_clients: InMemoryClientRepository,
    demo_users: InMemoryUserRepository,
    trusted_issuers: InMemoryTrustedAssertionIssuerRepository,
) -> Container:
    settings = Settings(
        database_url="memory://",
        token_format="opaque",
        session_secret_key="test-secret-stable-across-runs",
    )
    return await build_container(
        settings,
        clients_override=demo_clients,
        users_override=demo_users,
        trusted_issuers_override=trusted_issuers,
    )


@pytest.fixture
def app(container: Container) -> FastAPI:
    fastapi_app = create_app(settings=container.settings)
    fastapi_app.state.container = container
    return fastapi_app


@pytest.fixture
async def http_client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
