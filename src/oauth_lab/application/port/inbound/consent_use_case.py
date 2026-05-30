"""Inbound port — `/consent` POST contract.

Implementation: `oauth_lab.application.service.consent_service`.
"""

from __future__ import annotations

from typing import Protocol

from oauth_lab.application.service.consent_service import ConsentDecision


class ConsentUseCase(Protocol):
    async def execute(self, decision: ConsentDecision) -> str: ...
