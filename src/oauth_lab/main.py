"""FastAPI application entrypoint.

Wires the composition root (`Container`) at startup via the `lifespan`
hook, then mounts the inbound REST + Web adapters (driving side of the
Hexagonal application).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from oauth_lab.adapter.inbound.rest.device_authorization_controller import (
    router as device_authorization_router,
)
from oauth_lab.adapter.inbound.rest.discovery_controller import router as discovery_router
from oauth_lab.adapter.inbound.rest.exception_handler import register_oauth_exception_handler
from oauth_lab.adapter.inbound.rest.jwks_controller import router as jwks_router
from oauth_lab.adapter.inbound.rest.token_controller import router as token_router
from oauth_lab.adapter.inbound.rest.userinfo_controller import router as userinfo_router
from oauth_lab.adapter.inbound.web.authorize_controller import router as authorize_router
from oauth_lab.adapter.inbound.web.consent_controller import router as consent_router
from oauth_lab.adapter.inbound.web.device_controller import router as device_web_router
from oauth_lab.adapter.inbound.web.login_controller import router as login_router
from oauth_lab.config import Settings
from oauth_lab.container import build_container


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = Settings()
    app.state.container = await build_container(settings)
    yield


def create_app(*, settings: Settings | None = None) -> FastAPI:
    app = FastAPI(
        title="oauth-lab",
        description="OAuth 2.1 authorization server — canonical Hexagonal reference",
        version="0.1.0",
        lifespan=lifespan if settings is None else None,
    )

    register_oauth_exception_handler(app)

    # Inbound (driving) REST adapters
    app.include_router(token_router)
    app.include_router(jwks_router)
    app.include_router(userinfo_router)
    app.include_router(discovery_router)
    app.include_router(device_authorization_router)

    # Inbound (driving) Web (browser) adapters
    app.include_router(authorize_router)
    app.include_router(login_router)
    app.include_router(consent_router)
    app.include_router(device_web_router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return app


app = create_app()
