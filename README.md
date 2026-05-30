# oauth-lab

A production-grade OAuth 2.1 authorization server, generated from the
[`oauth-openapi`](../oauth-openapi/) specification and built with hexagonal
architecture, SOLID principles, and standard GoF design patterns.

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

Expected response:

```json
{
  "access_token": "rZWvrxIW9BhFcflCCUfjoPTfe8tzx_Utq2TdXBkB4no",
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
│   ├── m2m_flow/                           # ✅ implemented
│   │   └── test_client_credentials_grant.py
│   ├── browser_flow/                       # ⏳ placeholder for next grant
│   ├── device_flow/                        # ⏳
│   ├── federation/                         # ⏳
│   └── delegation/                         # ⏳
└── integration/
    ├── m2m_flow/                           # ✅ implemented
    │   └── test_token_client_credentials.py
    ├── browser_flow/                       # ⏳
    ├── device_flow/                        # ⏳
    ├── federation/                         # ⏳
    └── delegation/                         # ⏳
```

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
just test                  # everything (23 tests today)
just test-m2m              # only the M2M scenario (11 tests today)
just test-shared           # only the scenario-agnostic tests (12 today)
just test-browser          # 0 today — `authorization_code` not implemented yet
just test-unit             # all unit tests (any scenario)
just test-integration      # all integration tests
```

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

Generated code lives in `src/openapi_server/`; our code lives in
`src/oauth_lab/`. The generated routers are not mounted (their security
stubs are incomplete) — we implement each endpoint ourselves under
`src/oauth_lab/adapter/inbound/{rest,web}/`.
