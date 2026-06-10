"""FastAPI application entrypoint.

The HTTP composition root: builds the `Container` at startup via the
`lifespan` hook and mounts every inbound REST + Web router through its
`build_router` factory. Each router receives exactly the ports it
drives — as lazy providers (`Callable[[], Port]`) resolved per request,
so tests can inject a pre-built container onto `app.state` after
`create_app()` and startup stays idempotent. This module is the only
place that touches `app.state.container`.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from oauth_lab.adapter.inbound.rest import (
    device_authorization_controller,
    discovery_controller,
    jwks_controller,
    token_controller,
    userinfo_controller,
)
from oauth_lab.adapter.inbound.rest.exception_handler import register_oauth_exception_handler
from oauth_lab.adapter.inbound.web import (
    authorize_controller,
    consent_controller,
    device_controller,
    login_controller,
)
from oauth_lab.adapter.inbound.web.template_renderer import TEMPLATES_DIR, TemplateRenderer
from oauth_lab.config import Settings
from oauth_lab.container import Container, build_container


def _make_lifespan(settings: Settings) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """Build a lifespan that wires the container at startup.

    If `app.state.container` is already set (tests inject one directly after
    `create_app`), we keep it — startup stays idempotent and test-friendly.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(level=settings.log_level)
        if getattr(app.state, "container", None) is None:
            app.state.container = await build_container(settings)
        yield

    return lifespan


def create_app(*, settings: Settings | None = None) -> FastAPI:
    resolved = settings if settings is not None else Settings()

    app = FastAPI(
        title="oauth-lab",
        description="OAuth 2.1 authorization server — canonical Hexagonal reference",
        version="0.1.0",
        lifespan=_make_lifespan(resolved),
    )

    register_oauth_exception_handler(app)

    def container() -> Container:
        return app.state.container                                                # type: ignore[no-any-return]

    # The Jinja wrapper is an inbound-adapter concern — constructed here,
    # never carried by the Container.
    templates = TemplateRenderer(TEMPLATES_DIR)

    # Inbound (driving) REST adapters
    app.include_router(
        token_controller.build_router(issue_token=lambda: container().issue_token)
    )
    app.include_router(jwks_controller.build_router(jwks=lambda: container().jwks))
    app.include_router(
        userinfo_controller.build_router(get_user_info=lambda: container().get_user_info)
    )
    app.include_router(
        discovery_controller.build_router(server_metadata=lambda: container().server_metadata)
    )
    app.include_router(
        device_authorization_controller.build_router(
            request_device_authorization=lambda: container().request_device_authorization
        )
    )

    # Inbound (driving) Web (browser) adapters
    app.include_router(
        authorize_controller.build_router(
            authorize=lambda: container().authorize,
            templates=templates,
            issuer=resolved.issuer,
        )
    )
    app.include_router(
        login_controller.build_router(
            login=lambda: container().login,
            templates=templates,
            cookie_secure=resolved.issuer.startswith("https"),
            cookie_max_age_seconds=resolved.session_ttl_seconds,
        )
    )
    app.include_router(
        consent_controller.build_router(
            consent=lambda: container().consent,
            session_signer=lambda: container().session_signer,
            issuer=resolved.issuer,
        )
    )
    app.include_router(
        device_controller.build_router(
            lookup_device_code=lambda: container().lookup_device_code,
            device_consent=lambda: container().device_consent,
            session_signer=lambda: container().session_signer,
            templates=templates,
        )
    )

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return app


app = create_app()
