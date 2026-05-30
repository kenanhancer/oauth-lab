# oauth-lab development commands. Install `just` via `brew install just`.

set dotenv-load := true

default:
    @just --list

# Install runtime + dev deps into a local venv
install:
    python3.12 -m venv .venv
    .venv/bin/pip install -U pip
    .venv/bin/pip install -e ".[dev]"

# Regenerate FastAPI stubs from oauth-openapi.yaml (preserves our code via .openapi-generator-ignore)
gen:
    npx --yes @openapitools/openapi-generator-cli generate \
      -i ../oauth-openapi/oauth-openapi.yaml \
      -g python-fastapi \
      -o . \
      --skip-validate-spec \
      --additional-properties=packageName=openapi_server,sourceFolder=src

# Run the server against SQLite (no Docker needed)
dev:
    OAUTH_LAB_DATABASE_URL=sqlite+aiosqlite:///./oauth_lab.db \
        .venv/bin/uvicorn oauth_lab.main:app --reload --port 8000

# Run the server against Postgres (requires docker-compose up)
dev-prod:
    OAUTH_LAB_DATABASE_URL=postgresql+asyncpg://oauth:oauth@localhost:5432/oauth_lab \
        .venv/bin/uvicorn oauth_lab.main:app --reload --port 8000

# Seed demo clients into the configured database (idempotent — safe to re-run).
# Defaults to the same SQLite URL as `just dev` so the two stay in sync.
seed:
    OAUTH_LAB_DATABASE_URL="${OAUTH_LAB_DATABASE_URL:-sqlite+aiosqlite:///./oauth_lab.db}" \
        .venv/bin/python -m oauth_lab.adapter.inbound.cli seed

# Seed against Postgres (matches `just dev-prod`)
seed-prod:
    OAUTH_LAB_DATABASE_URL=postgresql+asyncpg://oauth:oauth@localhost:5432/oauth_lab \
        .venv/bin/python -m oauth_lab.adapter.inbound.cli seed

# Start the Postgres service for dev-prod
db-up:
    docker compose up -d db

db-down:
    docker compose down

# Tests — by structural axis (unit vs integration)
test:
    .venv/bin/pytest

test-unit:
    .venv/bin/pytest tests/unit

test-integration:
    .venv/bin/pytest tests/integration

# Tests — by OAuth scenario axis. Folders under tests/unit/ and tests/integration/
# carry the scenario name; canonical list lives in pyproject.toml `markers`.
test-m2m:
    .venv/bin/pytest tests/unit/m2m_flow tests/integration/m2m_flow

test-browser:
    .venv/bin/pytest tests/unit/browser_flow tests/integration/browser_flow

test-device:
    .venv/bin/pytest tests/unit/device_flow tests/integration/device_flow

test-federation:
    .venv/bin/pytest tests/unit/federation tests/integration/federation

test-delegation:
    .venv/bin/pytest tests/unit/delegation tests/integration/delegation

# Scenario-agnostic tests (domain primitives, value objects, CLI seed).
test-shared:
    .venv/bin/pytest tests/unit/shared

# Lint + type check
lint:
    .venv/bin/ruff check src tests
    .venv/bin/ruff format --check src tests
    .venv/bin/mypy src

fmt:
    .venv/bin/ruff format src tests
    .venv/bin/ruff check --fix src tests

# Smoke test: hit /token with client_credentials
smoke:
    curl -sS -X POST http://localhost:8000/token \
      -u 'demo-client:demo-secret' \
      -d 'grant_type=client_credentials&scope=read' | python3 -m json.tool
