"""Composition root — wires every port to its adapter.

Called once at startup (`main.py` lifespan). Returns a `Container` with
everything already constructed; the API layer pulls services from it via
FastAPI's `Depends`. No service locator, no globals — explicit DI.

Type annotations are PORTS (Protocols); assigned values are ADAPTERS
(concrete classes). This is canonical Hexagonal: the container is the
*only* place where ports and adapters meet.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Adapter — inbound (driving) helpers
from oauth_lab.adapter.inbound.web.template_renderer import TemplateRenderer

# Adapter — outbound (driven) implementations
from oauth_lab.adapter.outbound.crypto.argon2_secret_hasher import Argon2SecretHasher
from oauth_lab.adapter.outbound.crypto.id_token_issuer import JwtIdTokenIssuer
from oauth_lab.adapter.outbound.crypto.jwks_provider import RsaJwksProvider, rsa_jwk_thumbprint
from oauth_lab.adapter.outbound.crypto.jwt_access_token_verifier import JwtAccessTokenVerifier
from oauth_lab.adapter.outbound.crypto.jwt_subject_token_validator import (
    JwtSubjectTokenValidator,
)
from oauth_lab.adapter.outbound.crypto.key_generator import (
    RsaKeyPairGenerator,
    generate_rsa_keypair_pem,
    load_or_create_keypair,
    public_key_pem_from_private,
)
from oauth_lab.adapter.outbound.crypto.pyjwt_assertion_verifier import PyJwtAssertionVerifier
from oauth_lab.adapter.outbound.crypto.token_issuer_factory import TokenFormat, TokenIssuerFactory
from oauth_lab.adapter.outbound.persistence.memory.authorization_code_repository import (
    InMemoryAuthorizationCodeRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.client_repository import InMemoryClientRepository
from oauth_lab.adapter.outbound.persistence.memory.device_code_repository import (
    InMemoryDeviceCodeRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.refresh_token_repository import (
    InMemoryRefreshTokenRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.trusted_assertion_issuer_repository import (
    InMemoryTrustedAssertionIssuerRepository,
)
from oauth_lab.adapter.outbound.persistence.memory.user_repository import InMemoryUserRepository
from oauth_lab.adapter.outbound.persistence.orm.models import Base
from oauth_lab.adapter.outbound.persistence.postgres.authorization_code_repository import (
    PostgresAuthorizationCodeRepository,
)
from oauth_lab.adapter.outbound.persistence.postgres.client_repository import (
    PostgresClientRepository,
)
from oauth_lab.adapter.outbound.persistence.postgres.device_code_repository import (
    PostgresDeviceCodeRepository,
)
from oauth_lab.adapter.outbound.persistence.postgres.refresh_token_repository import (
    PostgresRefreshTokenRepository,
)
from oauth_lab.adapter.outbound.persistence.postgres.trusted_assertion_issuer_repository import (
    PostgresTrustedAssertionIssuerRepository,
)
from oauth_lab.adapter.outbound.persistence.postgres.user_repository import PostgresUserRepository
from oauth_lab.adapter.outbound.persistence.sqlite.authorization_code_repository import (
    SQLiteAuthorizationCodeRepository,
)
from oauth_lab.adapter.outbound.persistence.sqlite.client_repository import SQLiteClientRepository
from oauth_lab.adapter.outbound.persistence.sqlite.device_code_repository import (
    SQLiteDeviceCodeRepository,
)
from oauth_lab.adapter.outbound.persistence.sqlite.refresh_token_repository import (
    SQLiteRefreshTokenRepository,
)
from oauth_lab.adapter.outbound.persistence.sqlite.trusted_assertion_issuer_repository import (
    SQLiteTrustedAssertionIssuerRepository,
)
from oauth_lab.adapter.outbound.persistence.sqlite.user_repository import SQLiteUserRepository
from oauth_lab.adapter.outbound.random.secure_random_source import SecureRandomSource
from oauth_lab.adapter.outbound.random.user_code_generator import SecureUserCodeGenerator
from oauth_lab.adapter.outbound.session.itsdangerous_session_signer import ItsdangerousSessionSigner
from oauth_lab.adapter.outbound.time.system_clock import SystemClock

# Application — inbound ports + service implementations
from oauth_lab.application.port.inbound.authorize_use_case import AuthorizeUseCase
from oauth_lab.application.port.inbound.consent_use_case import ConsentUseCase
from oauth_lab.application.port.inbound.device_consent_use_case import DeviceConsentUseCase
from oauth_lab.application.port.inbound.get_user_info_use_case import GetUserInfoUseCase
from oauth_lab.application.port.inbound.issue_token_use_case import IssueTokenUseCase
from oauth_lab.application.port.inbound.login_use_case import LoginUseCase
from oauth_lab.application.port.inbound.lookup_device_code_use_case import (
    LookupDeviceCodeUseCase,
)
from oauth_lab.application.port.inbound.request_device_authorization_use_case import (
    RequestDeviceAuthorizationUseCase,
)
from oauth_lab.application.port.inbound.seed_demo_data_use_case import SeedDemoDataUseCase

# Application — outbound ports
from oauth_lab.application.port.outbound.access_token_verifier import AccessTokenVerifier
from oauth_lab.application.port.outbound.assertion_verifier import AssertionVerifier
from oauth_lab.application.port.outbound.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.application.port.outbound.device_code_repository import DeviceCodeRepository
from oauth_lab.application.port.outbound.id_token_issuer import IdTokenIssuer
from oauth_lab.application.port.outbound.jwks_provider import JwksProvider
from oauth_lab.application.port.outbound.key_pair_generator import KeyPairGenerator
from oauth_lab.application.port.outbound.refresh_token_repository import RefreshTokenRepository
from oauth_lab.application.port.outbound.secret_hasher import SecretHasher
from oauth_lab.application.port.outbound.session_signer import SessionSigner
from oauth_lab.application.port.outbound.subject_token_validator import SubjectTokenValidator
from oauth_lab.application.port.outbound.trusted_assertion_issuer_repository import (
    TrustedAssertionIssuerRepository,
)
from oauth_lab.application.port.outbound.user_code_generator import UserCodeGenerator
from oauth_lab.application.port.outbound.user_repository import UserRepository

# Application — services (concrete) + strategies
from oauth_lab.application.service.authorize_service import AuthorizeService
from oauth_lab.application.service.client_auth.client_authenticator import (
    ClientCredentialsPipeline,
)
from oauth_lab.application.service.client_auth.client_secret_basic_authenticator import (
    ClientSecretBasicAuthenticator,
)
from oauth_lab.application.service.client_auth.client_secret_post_authenticator import (
    ClientSecretPostAuthenticator,
)
from oauth_lab.application.service.client_auth.none_authenticator import NoneAuthenticator
from oauth_lab.application.service.consent_service import ConsentService
from oauth_lab.application.service.device_consent_service import DeviceConsentService
from oauth_lab.application.service.get_user_info_service import GetUserInfoService
from oauth_lab.application.service.grant.authorization_code_grant import AuthorizationCodeGrant
from oauth_lab.application.service.grant.client_credentials_grant import ClientCredentialsGrant
from oauth_lab.application.service.grant.device_code_grant import DeviceCodeGrant
from oauth_lab.application.service.grant.grant_registry import GrantRegistry
from oauth_lab.application.service.grant.jwt_bearer_grant import JwtBearerGrant
from oauth_lab.application.service.grant.refresh_token_grant import RefreshTokenGrant
from oauth_lab.application.service.grant.token_exchange_grant import TokenExchangeGrant
from oauth_lab.application.service.issue_token_service import IssueTokenService
from oauth_lab.application.service.login_service import LoginService
from oauth_lab.application.service.lookup_device_code_service import LookupDeviceCodeService
from oauth_lab.application.service.request_device_authorization_service import (
    RequestDeviceAuthorizationService,
)
from oauth_lab.application.service.seed_demo_data_service import SeedDemoDataService
from oauth_lab.config import Settings

# Domain — pure services (no I/O)
from oauth_lab.domain.service.pkce_verifier import PKCEVerifier
from oauth_lab.domain.service.scope_validator import ScopeValidator

_TEMPLATES_DIR = Path(__file__).parent / "adapter" / "inbound" / "web" / "templates"

_logger = logging.getLogger("oauth_lab")

_DEV_SESSION_SECRET = "dev-only-change-me"                 # noqa: S105 — matches Settings default (not a real secret)
_LOCALHOST_ISSUER_PREFIXES = ("http://localhost", "http://127.0.0.1")


def _is_localhost_issuer(issuer: str) -> bool:
    return issuer.startswith(_LOCALHOST_ISSUER_PREFIXES)


def _check_session_secret(settings: Settings) -> None:
    """Fail closed if the default session secret is used off localhost.

    The default `session_secret_key` is publicly known, so anyone could forge
    a signed session cookie (login/consent state). On a non-localhost issuer
    that is a live auth bypass — refuse to start. On localhost we allow it for
    zero-config dev, but warn loudly.
    """
    if settings.session_secret_key != _DEV_SESSION_SECRET:
        return
    if _is_localhost_issuer(settings.issuer):
        _logger.warning(
            "OAUTH_LAB_SESSION_SECRET_KEY is the built-in default %r; sessions "
            "are forgeable. Acceptable for localhost dev only — set a real "
            "secret before exposing this server.",
            _DEV_SESSION_SECRET,
        )
        return
    raise RuntimeError(
        "Refusing to start: OAUTH_LAB_SESSION_SECRET_KEY is still the built-in "
        f"default {_DEV_SESSION_SECRET!r} but the issuer ({settings.issuer!r}) is "
        "not localhost. The default key is public, so session cookies would be "
        "forgeable. Set OAUTH_LAB_SESSION_SECRET_KEY to a strong random value."
    )


@dataclass(slots=True)
class Container:
    settings: Settings

    # Outbound ports (types are Protocols; values are concrete adapters)
    clients: ClientRepository
    auth_codes: AuthorizationCodeRepository
    refresh_tokens: RefreshTokenRepository
    device_codes: DeviceCodeRepository
    users: UserRepository
    trusted_issuers: TrustedAssertionIssuerRepository
    session_signer: SessionSigner
    jwks: JwksProvider
    user_code_generator: UserCodeGenerator
    assertion_verifier: AssertionVerifier
    subject_token_validator: SubjectTokenValidator

    # Inbound ports (types are Protocols; values are concrete services)
    issue_token: IssueTokenUseCase
    authorize: AuthorizeUseCase
    login: LoginUseCase
    consent: ConsentUseCase
    request_device_authorization: RequestDeviceAuthorizationUseCase
    lookup_device_code: LookupDeviceCodeUseCase
    device_consent: DeviceConsentUseCase
    get_user_info: GetUserInfoUseCase
    seed_demo_data: SeedDemoDataUseCase

    # Inbound-adapter shared tooling (not port-abstracted — only used by adapter/in/web/)
    templates: TemplateRenderer

    # Composition detail (exposed for adapter/out/crypto consumers)
    signing_key_pem: bytes
    signing_kid: str


@dataclass(slots=True)
class _Repositories:
    clients: ClientRepository
    auth_codes: AuthorizationCodeRepository
    refresh_tokens: RefreshTokenRepository
    device_codes: DeviceCodeRepository
    users: UserRepository
    trusted_issuers: TrustedAssertionIssuerRepository


async def build_container(
    settings: Settings,
    *,
    clients_override: ClientRepository | None = None,
    auth_codes_override: AuthorizationCodeRepository | None = None,
    refresh_tokens_override: RefreshTokenRepository | None = None,
    device_codes_override: DeviceCodeRepository | None = None,
    users_override: UserRepository | None = None,
    trusted_issuers_override: TrustedAssertionIssuerRepository | None = None,
) -> Container:
    """Build the container.

    `*_override` parameters let tests inject in-memory repositories
    pre-populated with fixture data, bypassing the database entirely.
    """
    _check_session_secret(settings)

    clock = SystemClock()
    random_source = SecureRandomSource()
    # One shared instance: it precomputes the dummy-verify hash once.
    secret_hasher: SecretHasher = Argon2SecretHasher()
    key_pair_generator: KeyPairGenerator = RsaKeyPairGenerator()
    user_code_generator: UserCodeGenerator = SecureUserCodeGenerator()
    assertion_verifier: AssertionVerifier = PyJwtAssertionVerifier()
    # subject_token_validator constructed below — needs the signing key

    repos = await _build_repositories(
        settings,
        clients_override=clients_override,
        auth_codes_override=auth_codes_override,
        refresh_tokens_override=refresh_tokens_override,
        device_codes_override=device_codes_override,
        users_override=users_override,
        trusted_issuers_override=trusted_issuers_override,
    )

    session_signer: SessionSigner = ItsdangerousSessionSigner(
        secret_key=settings.session_secret_key,
        ttl_seconds=settings.session_ttl_seconds,
    )

    templates = TemplateRenderer(_TEMPLATES_DIR)

    # Always provide a signing key (used by JWT access tokens AND id_tokens).
    if settings.jwt_private_key_path is not None:
        signing_key_pem = load_or_create_keypair(settings.jwt_private_key_path)
    else:
        signing_key_pem = generate_rsa_keypair_pem()
        _logger.warning(
            "No OAUTH_LAB_JWT_PRIVATE_KEY_PATH set: generated an ephemeral RSA "
            "signing key. Issued JWTs/id_tokens will not verify after a restart, "
            "and replicas will each sign with a different key. Set a key path for "
            "stable, shared signing."
        )
    # Default `kid` to the RFC 7638 JWK thumbprint of the public key. Unlike a
    # static literal, the thumbprint is unique per key, so replicas with
    # different (e.g. ephemeral) keys advertise distinct `kid`s and a verifier
    # can pick the matching JWKS entry instead of seeing a single colliding id.
    signing_kid = settings.jwt_key_id or rsa_jwk_thumbprint(signing_key_pem)

    jwks_provider: JwksProvider = RsaJwksProvider(
        private_key_pem=signing_key_pem, kid=signing_kid, algorithm=settings.jwt_algorithm
    )

    token_issuer = TokenIssuerFactory(
        token_format=TokenFormat(settings.token_format),
        issuer=settings.issuer,
        signing_key_pem=signing_key_pem,
        key_id=signing_kid,
        algorithm=settings.jwt_algorithm,
        clock=clock,
        random_source=random_source,
    ).build()

    id_token_issuer: IdTokenIssuer = JwtIdTokenIssuer(
        issuer=settings.issuer,
        signing_key_pem=signing_key_pem,
        key_id=signing_kid,
        algorithm=settings.jwt_algorithm,
        clock=clock,
    )

    subject_token_validator: SubjectTokenValidator = JwtSubjectTokenValidator(
        issuer=settings.issuer,
        public_key_pem=public_key_pem_from_private(signing_key_pem),
        algorithm=settings.jwt_algorithm,
    )

    access_token_verifier: AccessTokenVerifier = JwtAccessTokenVerifier(
        issuer=settings.issuer,
        public_key_pem=public_key_pem_from_private(signing_key_pem),
        algorithm=settings.jwt_algorithm,
    )

    scope_validator = ScopeValidator()
    pkce_verifier = PKCEVerifier()

    grants = GrantRegistry([
        ClientCredentialsGrant(
            token_issuer=token_issuer,
            scope_validator=scope_validator,
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
        ),
        AuthorizationCodeGrant(
            token_issuer=token_issuer,
            id_token_issuer=id_token_issuer,
            auth_codes=repos.auth_codes,
            refresh_tokens=repos.refresh_tokens,
            random_source=random_source,
            pkce_verifier=pkce_verifier,
            clock=clock,
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
            refresh_token_ttl_seconds=settings.refresh_token_ttl_seconds,
        ),
        RefreshTokenGrant(
            token_issuer=token_issuer,
            refresh_tokens=repos.refresh_tokens,
            random_source=random_source,
            clock=clock,
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
            refresh_token_ttl_seconds=settings.refresh_token_ttl_seconds,
        ),
        DeviceCodeGrant(
            token_issuer=token_issuer,
            device_codes=repos.device_codes,
            refresh_tokens=repos.refresh_tokens,
            random_source=random_source,
            clock=clock,
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
            refresh_token_ttl_seconds=settings.refresh_token_ttl_seconds,
        ),
        JwtBearerGrant(
            token_issuer=token_issuer,
            trusted_issuers=repos.trusted_issuers,
            assertion_verifier=assertion_verifier,
            scope_validator=scope_validator,
            expected_audience=f"{settings.issuer.rstrip('/')}/token",
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
        ),
        TokenExchangeGrant(
            token_issuer=token_issuer,
            subject_token_validator=subject_token_validator,
            scope_validator=scope_validator,
            access_token_ttl_seconds=settings.access_token_ttl_seconds,
        ),
    ])

    client_auth = ClientCredentialsPipeline(
        authenticators=[
            ClientSecretBasicAuthenticator(repos.clients, secret_hasher),
            ClientSecretPostAuthenticator(repos.clients, secret_hasher),
            NoneAuthenticator(repos.clients),
        ],
        clients=repos.clients,
    )

    issue_token: IssueTokenUseCase = IssueTokenService(
        client_auth=client_auth, grants=grants
    )
    authorize: AuthorizeUseCase = AuthorizeService(
        clients=repos.clients,
        users=repos.users,
        session_signer=session_signer,
    )
    login: LoginUseCase = LoginService(
        users=repos.users, session_signer=session_signer, secret_hasher=secret_hasher
    )
    consent: ConsentUseCase = ConsentService(
        clients=repos.clients,
        auth_codes=repos.auth_codes,
        random_source=random_source,
        clock=clock,
        code_ttl_seconds=settings.authorization_code_ttl_seconds,
        issuer=settings.issuer,
    )
    request_device_authorization: RequestDeviceAuthorizationUseCase = (
        RequestDeviceAuthorizationService(
            clients=repos.clients,
            device_codes=repos.device_codes,
            random_source=random_source,
            user_code_generator=user_code_generator,
            clock=clock,
            issuer=settings.issuer,
            device_code_ttl_seconds=settings.device_code_ttl_seconds,
            polling_interval_seconds=settings.device_code_polling_interval_seconds,
        )
    )
    lookup_device_code: LookupDeviceCodeUseCase = LookupDeviceCodeService(
        device_codes=repos.device_codes,
        clock=clock,
    )
    device_consent: DeviceConsentUseCase = DeviceConsentService(
        device_codes=repos.device_codes,
        clock=clock,
    )
    get_user_info: GetUserInfoUseCase = GetUserInfoService(
        token_verifier=access_token_verifier,
        users=repos.users,
    )
    seed_demo_data: SeedDemoDataUseCase = SeedDemoDataService(
        clients=repos.clients,
        users=repos.users,
        trusted_issuers=repos.trusted_issuers,
        secret_hasher=secret_hasher,
        key_pair_generator=key_pair_generator,
    )

    return Container(
        settings=settings,
        clients=repos.clients,
        auth_codes=repos.auth_codes,
        refresh_tokens=repos.refresh_tokens,
        device_codes=repos.device_codes,
        users=repos.users,
        trusted_issuers=repos.trusted_issuers,
        session_signer=session_signer,
        jwks=jwks_provider,
        user_code_generator=user_code_generator,
        assertion_verifier=assertion_verifier,
        subject_token_validator=subject_token_validator,
        issue_token=issue_token,
        authorize=authorize,
        login=login,
        consent=consent,
        request_device_authorization=request_device_authorization,
        lookup_device_code=lookup_device_code,
        device_consent=device_consent,
        get_user_info=get_user_info,
        seed_demo_data=seed_demo_data,
        templates=templates,
        signing_key_pem=signing_key_pem,
        signing_kid=signing_kid,
    )


async def _build_repositories(
    settings: Settings,
    *,
    clients_override: ClientRepository | None,
    auth_codes_override: AuthorizationCodeRepository | None,
    refresh_tokens_override: RefreshTokenRepository | None,
    device_codes_override: DeviceCodeRepository | None,
    users_override: UserRepository | None,
    trusted_issuers_override: TrustedAssertionIssuerRepository | None,
) -> _Repositories:
    url = settings.database_url

    if url.startswith("memory://"):
        return _Repositories(
            clients=clients_override or InMemoryClientRepository(),
            auth_codes=auth_codes_override or InMemoryAuthorizationCodeRepository(),
            refresh_tokens=refresh_tokens_override or InMemoryRefreshTokenRepository(),
            device_codes=device_codes_override or InMemoryDeviceCodeRepository(),
            users=users_override or InMemoryUserRepository(),
            trusted_issuers=trusted_issuers_override or InMemoryTrustedAssertionIssuerRepository(),
        )

    engine = create_async_engine(url, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    if url.startswith("sqlite"):
        return _Repositories(
            clients=clients_override or SQLiteClientRepository(session_factory),
            auth_codes=auth_codes_override or SQLiteAuthorizationCodeRepository(session_factory),
            refresh_tokens=refresh_tokens_override
            or SQLiteRefreshTokenRepository(session_factory),
            device_codes=device_codes_override or SQLiteDeviceCodeRepository(session_factory),
            users=users_override or SQLiteUserRepository(session_factory),
            trusted_issuers=trusted_issuers_override
            or SQLiteTrustedAssertionIssuerRepository(session_factory),
        )
    if url.startswith("postgresql"):
        return _Repositories(
            clients=clients_override or PostgresClientRepository(session_factory),
            auth_codes=auth_codes_override
            or PostgresAuthorizationCodeRepository(session_factory),
            refresh_tokens=refresh_tokens_override
            or PostgresRefreshTokenRepository(session_factory),
            device_codes=device_codes_override or PostgresDeviceCodeRepository(session_factory),
            users=users_override or PostgresUserRepository(session_factory),
            trusted_issuers=trusted_issuers_override
            or PostgresTrustedAssertionIssuerRepository(session_factory),
        )
    raise RuntimeError(f"unsupported OAUTH_LAB_DATABASE_URL: {url}")
