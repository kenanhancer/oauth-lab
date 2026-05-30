"""Inbound port — `/authorize` endpoint contract.

Implementation: `oauth_lab.application.service.authorize_service`.
"""

from __future__ import annotations

from typing import Protocol

from oauth_lab.application.service.authorize_service import (
    AuthorizeRequest,
    AuthorizeResult,
)


class AuthorizeUseCase(Protocol):
    async def execute(
        self,
        *,
        request: AuthorizeRequest,
        session_cookie: str | None,
        full_request_url: str,
    ) -> AuthorizeResult: ...
