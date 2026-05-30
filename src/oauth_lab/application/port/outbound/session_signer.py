"""Outbound port — browser session cookie signer.

`SessionData` is the application-level value object the session represents.
The concrete adapter (`oauth_lab.adapter.outbound.session.itsdangerous_session_signer`)
implements the Protocol using `itsdangerous` for signed cookies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SessionData:
    user_sub: str


class SessionSigner(Protocol):
    def sign(self, data: SessionData) -> str: ...

    def verify(self, token: str | None) -> SessionData | None: ...
