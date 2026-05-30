"""Inbound port — `/login` POST contract.

Implementation: `oauth_lab.application.service.login_service`.
"""

from __future__ import annotations

from typing import Protocol


class LoginUseCase(Protocol):
    async def execute(self, *, username: str, password: str) -> str: ...
