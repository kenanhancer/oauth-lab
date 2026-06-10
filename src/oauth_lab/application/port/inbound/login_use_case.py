"""Inbound port — `/login` POST contract.

Implementation: `oauth_lab.application.service.login_service`.
"""

from __future__ import annotations

from typing import Protocol

from oauth_lab.domain.model.errors import OAuthError


class InvalidCredentials(OAuthError):
    """Wrong username/password. The `/login` route renders the form again
    with an error message; it doesn't return a JSON envelope."""

    error_code = "invalid_credentials"
    http_status = 401


class LoginUseCase(Protocol):
    async def execute(self, *, username: str, password: str) -> str: ...
