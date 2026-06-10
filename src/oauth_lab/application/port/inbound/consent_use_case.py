"""Inbound port — `/consent` POST contract.

The port owns the `ConsentResult` union: the application reports the
*outcome* of the decision (granted with a fresh code, or denied); how
that outcome travels back to the client — the redirect URL, its query
encoding, the RFC 9207 `iss` parameter — is the driving adapter's job.

Implementation: `oauth_lab.application.service.consent_service`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Protocol


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


@dataclass(frozen=True, slots=True)
class ConsentGranted:
    """User approved: an authorization code was minted and persisted."""

    redirect_uri: str
    code: str
    state: str | None


@dataclass(frozen=True, slots=True)
class ConsentDenied:
    """User denied the request.

    The error code is fixed by RFC 6749 §4.1.2.1: a resource owner
    denying access is always `access_denied` — hence a class constant,
    not a per-instance field.
    """

    redirect_uri: str
    error_description: str
    state: str | None

    ERROR_CODE: ClassVar[str] = "access_denied"


ConsentResult = ConsentGranted | ConsentDenied


class ConsentUseCase(Protocol):
    async def execute(self, decision: ConsentDecision) -> ConsentResult: ...
