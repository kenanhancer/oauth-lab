"""Inbound port — `/consent` POST contract.

Implementation: `oauth_lab.application.service.consent_service`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ConsentDecision:
    approved: bool
    user_sub: str                                                 # comes from verified session
    client_id: str
    redirect_uri: str
    scope: str | None
    state: str | None
    code_challenge: str
    code_challenge_method: str


class ConsentUseCase(Protocol):
    async def execute(self, decision: ConsentDecision) -> str: ...
