# oauth-lab

A production-grade OAuth 2.1 authorization server, built against the
[`oauth-openapi`](https://github.com/kenanhancer/oauth-openapi) specification
with hexagonal architecture, SOLID principles, and standard GoF design
patterns.

This is the **runnable implementation** of the contract defined in
`oauth-openapi.yaml`. The spec is the canvas; this is the painting.

## Status

| Grant | Status |
|---|---|
| `client_credentials` | ✅ implemented end-to-end |
| `authorization_code` + PKCE | ✅ implemented end-to-end |
| `refresh_token` | ✅ implemented end-to-end |
| `urn:ietf:params:oauth:grant-type:device_code` | ✅ implemented end-to-end |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | ✅ implemented end-to-end |
| `urn:ietf:params:oauth:grant-type:token-exchange` | ✅ implemented end-to-end |

## Architecture — Canonical Hexagonal (Ports and Adapters)

Three top-level packages. Dependencies point inward only.

```
adapter/inbound/    ← Driving adapters: REST API, Web UI, CLI
adapter/outbound/   ← Driven adapters: persistence (memory/sqlite/postgres),
                      crypto (JWT, JWKS, id_token), session, time, random
application/
├── port/inbound/   ← Use case Protocols (REST/Web call these)
├── port/outbound/  ← Repository, clock, crypto, session Protocols
└── service/        ← Use case implementations + grant strategies + client-auth
domain/
├── model/          ← Entities, value objects, errors
└── service/        ← Pure domain services (PKCEVerifier, ScopeValidator)
```

Reading any file's path tells you its layer + responsibility:
`adapter/outbound/persistence/sqlite/client_repository.py` →
*"outbound adapter, persistence, SQLite implementation of ClientRepository."*

### Hexagonal hallmarks

- **Inbound ports** (use case Protocols) in `application/port/inbound/` — what the application *offers*
- **Outbound ports** (repository/clock/crypto Protocols) in `application/port/outbound/` — what the application *requires*
- **Mappers stay in adapters** (`adapter/outbound/persistence/sqlalchemy/`) — domain stays ORM-free
- **Container is the only place ports meet adapters** — `container.py` composition root
- **Domain knows nothing of HTTP, SQL, or JWT** — pure types only
- **Secret hashing and key generation sit behind ports** (`SecretHasher`, `KeyPairGenerator`) and HTTP status mapping lives in the REST adapter (`exception_handler.py`) — domain errors carry only RFC error codes

### Design patterns

| Pattern | Where it lives |
|---|---|
| Strategy | `application/service/grant/`, `application/service/client_auth/` |
| Repository | `application/port/outbound/*_repository.py` → 3 adapters (memory, sqlite, postgres) |
| Factory | `adapter/outbound/crypto/token_issuer_factory.py` (opaque vs JWT) |
| Chain of Responsibility | Validators in `application/service/authorize_service.py` |
| Value Object | `Scope`, `ClientId`, `GrantType`, `PKCEChallenge`, `SessionData` |
| Null Object | `NoneAuthenticator` for public clients (RFC 6749 §2.3) |
| Composition Root | `container.py` — explicit DI graph wired at startup |

## Repository layout

The full map — every port, adapter, and service, and the rule it obeys
(`tests/` has its own tree under [Test layout](#test-layout)):

```
oauth-lab/
├── Justfile                          dev commands (install / dev / seed / test / lint)
├── pyproject.toml                    deps + ruff / mypy --strict / pytest config
├── openapi.yaml                      vendored contract snapshot from oauth-openapi
├── openapitools.json                 openapi-generator pin (7.14.0)
├── Dockerfile / docker-compose.yaml  app image + Postgres for `just dev-prod`
├── .env.example                      OAUTH_LAB_* settings template
├── .tool-versions / .python-version  Python 3.12.7 pin
├── tests/                            unit + integration, by OAuth scenario
└── src/oauth_lab/
    ├── main.py                       HTTP composition root — mounts every router via its
    │                                 build_router() factory; only place touching app.state
    ├── container.py                  composition root — the only place ports meet adapters
    ├── config.py                     pydantic-settings (env prefix OAUTH_LAB_)
    │
    ├── domain/                       pure protocol rules — imports stdlib only
    │   ├── model/
    │   │   ├── client.py · user.py · authorization_code.py · refresh_token.py
    │   │   ├── device_code.py · trusted_assertion_issuer.py        entities
    │   │   ├── client_id.py · scope.py · pkce.py · grant_type.py
    │   │   ├── client_auth_method.py · token_type_uri.py           value objects
    │   │   └── errors.py             OAuthError hierarchy — RFC error codes, no HTTP
    │   └── service/
    │       ├── pkce_verifier.py      RFC 7636 S256 check, constant-time
    │       └── scope_validator.py
    │
    ├── application/
    │   ├── port/
    │   │   ├── inbound/              what the application OFFERS — one contract per use
    │   │   │   │                     case; each port owns its request/result DTOs
    │   │   │   ├── authorize_use_case.py            AuthorizeResult outcome union
    │   │   │   ├── consent_use_case.py              ConsentGranted | ConsentDenied
    │   │   │   ├── issue_token_use_case.py          TokenRequest / TokenIssuanceResult
    │   │   │   ├── login_use_case.py
    │   │   │   ├── get_user_info_use_case.py
    │   │   │   ├── get_server_metadata_use_case.py
    │   │   │   ├── request_device_authorization_use_case.py
    │   │   │   ├── lookup_device_code_use_case.py
    │   │   │   ├── device_consent_use_case.py
    │   │   │   └── seed_demo_data_use_case.py
    │   │   └── outbound/             what the application REQUIRES — driven Protocols
    │   │       ├── authorization_code_repository.py  atomic consume()
    │   │       ├── refresh_token_repository.py       atomic rotate() + revoke_family()
    │   │       ├── device_code_repository.py         atomic redeem()
    │   │       ├── client_repository.py · user_repository.py
    │   │       ├── trusted_assertion_issuer_repository.py
    │   │       ├── token_issuer.py · id_token_issuer.py · jwks_provider.py
    │   │       ├── access_token_verifier.py · assertion_verifier.py
    │   │       ├── subject_token_validator.py
    │   │       ├── secret_hasher.py                  hash / verify / dummy_verify (timing)
    │   │       ├── key_pair_generator.py · session_signer.py
    │   │       └── clock.py · random_source.py · user_code_generator.py
    │   └── service/                  use-case implementations (one per inbound port)
    │       ├── authorize_service.py · consent_service.py · login_service.py
    │       ├── issue_token_service.py                authenticate → resolve grant → execute
    │       ├── get_user_info_service.py              OIDC §5.4 scope→claims policy
    │       ├── server_metadata_service.py            metadata derived from the registries
    │       ├── request_device_authorization_service.py
    │       ├── lookup_device_code_service.py · device_consent_service.py
    │       ├── seed_demo_data_service.py
    │       ├── client_auth/                          Strategy — RFC 6749 §2.3
    │       │   ├── client_authenticator.py           pipeline + AuthenticatedClient
    │       │   ├── client_secret_basic_authenticator.py
    │       │   ├── client_secret_post_authenticator.py
    │       │   └── none_authenticator.py             public clients (PKCE only)
    │       └── grant/                                Strategy — one per grant_type
    │           ├── grant_strategy.py · grant_registry.py
    │           ├── authorization_code_grant.py       PKCE verify + code consume
    │           ├── refresh_token_grant.py            rotation + family revocation
    │           ├── device_code_grant.py              RFC 8628 polling outcomes
    │           ├── client_credentials_grant.py
    │           ├── jwt_bearer_grant.py               RFC 7523
    │           └── token_exchange_grant.py           RFC 8693
    │
    └── adapter/
        ├── inbound/                  driving adapters — translate transport ↔ ports
        │   ├── rest/
        │   │   ├── token_controller.py · jwks_controller.py · userinfo_controller.py
        │   │   ├── discovery_controller.py · device_authorization_controller.py
        │   │   └── exception_handler.py    error_code → HTTP status map (RFC 6749 §5.2)
        │   ├── web/
        │   │   ├── authorize_controller.py · login_controller.py
        │   │   ├── consent_controller.py · device_controller.py
        │   │   ├── authorization_response.py   redirect builder — RFC 9207 iss lives here
        │   │   ├── session_guard.py            shared session + CSRF gate
        │   │   ├── session_constants.py · template_renderer.py
        │   │   └── templates/                  base / login / consent / device_* / error
        │   └── cli/
        │       └── __main__.py · seed_command.py    python -m …inbound.cli seed
        └── outbound/                 driven adapters — implement the outbound ports
            ├── crypto/
            │   ├── jwt_token_issuer.py             RFC 9068 at+jwt
            │   ├── opaque_token_issuer.py · token_issuer_factory.py
            │   ├── id_token_issuer.py · jwks_provider.py
            │   ├── jwt_access_token_verifier.py · pyjwt_assertion_verifier.py
            │   ├── jwt_subject_token_validator.py
            │   ├── argon2_secret_hasher.py         the only argon2 import in the codebase
            │   └── key_generator.py
            ├── persistence/
            │   ├── orm/models.py                   SQLAlchemy tables — domain stays ORM-free
            │   ├── memory/                         dict + asyncio.Lock (tests, memory://)
            │   ├── sqlalchemy/                     shared async impls; conditional-UPDATE
            │   │                                   consume / rotate / redeem
            │   ├── sqlite/                         thin named subclasses of sqlalchemy/
            │   └── postgres/                       (6 repository files each)
            ├── session/itsdangerous_session_signer.py
            ├── random/secure_random_source.py · user_code_generator.py
            └── time/system_clock.py
```

## Process model — one binary per inbound adapter type

Hexagonal Architecture is silent on how inbound adapters are packaged into
OS processes — that is a deployment concern, not an architectural one.
`oauth-lab` follows the **separate-binary-per-adapter** pattern (sometimes
called *mode-per-process*): each inbound adapter type has its own entry
point, its own executable, and its own deployment.

```
src/oauth_lab/adapter/inbound/
├── rest/                       ← Mounted by main.py — no separate entry point
├── web/                        ← Mounted by main.py — no separate entry point
├── cli/
│   └── __main__.py             → python -m oauth_lab.adapter.inbound.cli <subcommand>
├── messaging/                  (hypothetical future Kafka consumer)
│   ├── __main__.py             → python -m oauth_lab.adapter.inbound.messaging
│   └── kafka_consumer.py
├── scheduler/                  (hypothetical future cron-style job)
│   └── __main__.py             → python -m oauth_lab.adapter.inbound.scheduler
└── desktop/                    (hypothetical future native GUI)
    └── __main__.py             → python -m oauth_lab.adapter.inbound.desktop
```

Each `__main__.py` builds its own `Container` via the same
`build_container()` and starts only the adapter it owns:

```python
# adapter/inbound/messaging/__main__.py
import asyncio

from oauth_lab.adapter.inbound.messaging.kafka_consumer import KafkaConsumer
from oauth_lab.config import Settings
from oauth_lab.container import build_container


async def main() -> None:
    settings = Settings()
    container = await build_container(settings)
    consumer = KafkaConsumer(use_case=container.process_message)
    await consumer.run_forever()


if __name__ == "__main__":
    asyncio.run(main())
```

### Deployment

Each adapter is scaled and operated independently:

```bash
# Server pod (replicas = 5)
uvicorn oauth_lab.main:app

# Kafka worker pod (replicas = 10)
python -m oauth_lab.adapter.inbound.messaging

# Scheduler pod (replicas = 1)
python -m oauth_lab.adapter.inbound.scheduler

# CLI — ephemeral; invoked manually for seeding, maintenance, etc.
python -m oauth_lab.adapter.inbound.cli seed
```

### Why this pattern

| Benefit | Why it matters |
|---|---|
| Independent scaling | REST and Kafka rarely need the same number of replicas. |
| Fault isolation | A backpressure bug in the Kafka consumer cannot take down `/token`. |
| Slim images | Each container only ships the libraries that adapter needs. |
| Operational clarity | `kubectl get pods` reads like a feature list — each pod owns one channel. |

### Tradeoff

Multiple deployment manifests instead of one. Acceptable for any
non-trivial system; the operational gain dwarfs the build/CI cost.

### Always-on adapters share a process

`main.py` mounts REST + Web (and would mount WebSocket / in-process
scheduled jobs if they existed) in the same `uvicorn` process — they
share resources and have similar load profiles. Only **heavy or
independently-scaling** adapters (message consumers, background workers,
native desktop apps) need their own entry point.

## Quick start

```bash
just install              # create venv, install deps
just gen                  # regenerate FastAPI stubs from oauth-openapi.yaml
just dev                  # start the server against SQLite (no Docker needed)
just seed                 # insert the demo-client into SQLite (idempotent)
just smoke                # hit /token with client_credentials
just test                 # run unit + integration tests
```

After `just seed`, you have one demo client registered:

| Field | Value |
|---|---|
| `client_id` | `demo-client` |
| `client_secret` | `demo-secret` |
| `token_endpoint_auth_method` | `client_secret_basic` |
| `grant_types` | `client_credentials` |
| `scopes` | `read write` |
| `audience` | `https://api.example.com` |

Then in another terminal:

```bash
curl -sS -u 'demo-client:demo-secret' \
  -d 'grant_type=client_credentials&scope=read' \
  http://localhost:8000/token | python3 -m json.tool
```

Expected response (the default `OAUTH_LAB_TOKEN_FORMAT=jwt` issues RFC 9068
`at+jwt` access tokens; set it to `opaque` for random-string tokens):

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6Ii4uLiJ9.eyJpc3MiOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read"
}
```

## Test layout

Tests are organized on **two orthogonal axes**, both visible in the folder path:

1. **Structural axis** — `tests/unit/` vs. `tests/integration/`. Tells you *what kind of test* it is (pure domain vs. through the HTTP layer).
2. **OAuth scenario axis** — subfolder name (`m2m_flow`, `browser_flow`, `device_flow`, `federation`, `delegation`, or `shared` for scenario-agnostic). Tells you *which OAuth use case* the test belongs to.

```
tests/
├── conftest.py                             # shared fixtures
├── unit/
│   ├── shared/                             # scenario-agnostic — value objects, CLI
│   │   ├── test_scope.py
│   │   └── test_cli_seed.py
│   ├── m2m_flow/                           # ✅ implemented (client_credentials)
│   │   └── test_client_credentials_grant.py
│   ├── browser_flow/                       # ✅ implemented (authorization_code + PKCE, refresh)
│   │   ├── test_authorization_code.py
│   │   ├── test_pkce.py
│   │   └── test_refresh_token.py
│   ├── device_flow/                        # ✅ implemented (device_code)
│   │   ├── test_device_code.py
│   │   └── test_device_code_grant.py
│   ├── jwt_bearer_flow/                    # ✅ implemented (federation — jwt-bearer)
│   │   └── test_jwt_bearer_grant.py
│   └── token_exchange_flow/                # ✅ implemented (delegation — token-exchange)
│       └── test_token_exchange_grant.py
└── integration/
    ├── m2m_flow/                           # ✅ implemented
    │   └── test_token_client_credentials.py
    ├── browser_flow/                       # ✅ implemented
    │   ├── test_discovery.py
    │   ├── test_full_flow.py
    │   ├── test_jwks_and_jwt.py
    │   ├── test_oidc.py
    │   ├── test_refresh_token_rotation.py
    │   └── test_token_authorization_code.py
    ├── device_flow/                        # ✅ implemented
    │   ├── test_full_device_flow.py
    │   └── test_sqlalchemy_redeem.py
    ├── jwt_bearer_flow/                    # ✅ implemented
    │   └── test_jwt_bearer.py
    └── token_exchange_flow/                # ✅ implemented
        └── test_token_exchange.py
```

The `federation` and `delegation` names live on as pytest markers (see below);
the test folders that realize those scenarios are `jwt_bearer_flow`
(RFC 7523 `jwt-bearer`) and `token_exchange_flow` (RFC 8693 `token-exchange`).

Reading any path tells you everything: `tests/integration/m2m_flow/test_token_client_credentials.py` ⇒ integration test, M2M scenario, exercises `/token` with `client_credentials`.

### OAuth scenario reference

| Folder | Scenario | Grants covered |
|---|---|---|
| `m2m_flow` | Machine-to-machine — no user, no browser | `client_credentials` |
| `browser_flow` | User-via-browser delegation | `authorization_code` + PKCE, `refresh_token` |
| `device_flow` | Keyboardless device (smart TV, CLI) | `device_code` |
| `federation` | IdP federation / service-account assertion | `jwt-bearer`, `saml2-bearer` |
| `delegation` | Token exchange / identity propagation | `token-exchange` |
| `shared` | Not tied to any scenario | `Scope` value object, CLI seed, errors |

The same five names are also defined as pytest markers in `pyproject.toml` — the canonical list of OAuth scenarios in one place. Tests don't apply them (the folder name already carries the signal), but the marker definitions stay as a reference.

### Running by scenario

```bash
just test                  # everything (169 tests today)
just test-m2m              # M2M scenario — client_credentials (11 tests)
just test-browser          # browser scenario — authorization_code + PKCE, refresh (81 tests)
just test-device           # device scenario — device_code (30 tests)
just test-shared           # scenario-agnostic tests — value objects, CLI (13 tests)
just test-unit             # all unit tests (any scenario) — 103 today
just test-integration      # all integration tests — 66 today
```

The `federation` and `delegation` grants are implemented and tested under the
`jwt_bearer_flow` (16 tests) and `token_exchange_flow` (18 tests) folders. Run
them directly, e.g. `just test-unit` / `just test-integration`, or point pytest
at those paths.

## Storage adapters

Three backends behind one `ClientRepository` port:

- **Memory** — tests and ephemeral dev
- **SQLite** — solo dev, no Docker required (`just dev`)
- **Postgres** — production-like via Docker Compose (`just db-up && just dev-prod`)

Selection is driven by `OAUTH_LAB_DATABASE_URL`:

| URL scheme | Adapter |
|---|---|
| `memory://` | `InMemoryClientRepository` |
| `sqlite+aiosqlite://` | `SQLiteClientRepository` |
| `postgresql+asyncpg://` | `PostgresClientRepository` |

## Regenerating from the spec

`.openapi-generator-ignore` lists every file the generator must preserve.
After editing `../oauth-openapi/oauth-openapi.yaml`:

```bash
just gen
```

This regenerates `src/openapi_server/` from the spec. **That package is a
throwaway reference, not part of the shipped application.** It is:

- **Not committed / not shipped** — only `src/oauth_lab/` is packaged into the
  wheel (see `[tool.hatch.build.targets.wheel]` in `pyproject.toml`). Regenerate
  it on demand; never depend on it.
- **Not mounted** — `oauth_lab.main` never imports it. The generated routers'
  security stubs are incomplete, so we implement every endpoint ourselves under
  `src/oauth_lab/adapter/inbound/{rest,web}/`.
- **Possibly import-broken until regenerated** — the `python-fastapi` generator
  emits model files with invalid imports (e.g. `from openapi_server.models.object
  import object`) and a duplicated security dependency. It exists to read
  alongside our hand-written handlers as a reference, not to run.

Our real, runnable code lives entirely in `src/oauth_lab/`.
