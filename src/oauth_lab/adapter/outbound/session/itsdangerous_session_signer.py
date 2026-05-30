"""Stateless browser session via signed cookie (`itsdangerous`).

Concrete adapter implementing `oauth_lab.application.port.outbound.session_signer.SessionSigner`.

The cookie value is `URLSafeTimedSerializer.dumps({"sub": "..."})`. On
every request the route decodes it, verifies the signature, and checks
the age. No server-side session table.

Trade-off: cannot revoke a session before its TTL elapses — a hardening
pass can swap this for a server-side store behind the same Protocol.
"""

from __future__ import annotations

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from oauth_lab.application.port.outbound.session_signer import SessionData


class ItsdangerousSessionSigner:
    """Concrete `SessionSigner` adapter using `itsdangerous`."""

    def __init__(
        self,
        *,
        secret_key: str,
        ttl_seconds: int,
        salt: str = "oauth-lab.session",
    ) -> None:
        self._serializer = URLSafeTimedSerializer(secret_key=secret_key, salt=salt)
        self._ttl = ttl_seconds

    def sign(self, data: SessionData) -> str:
        return self._serializer.dumps({"sub": data.user_sub, "csrf": data.csrf_token})

    def verify(self, token: str | None) -> SessionData | None:
        if not token:
            return None
        try:
            payload = self._serializer.loads(token, max_age=self._ttl)
        except (BadSignature, SignatureExpired):
            return None
        if not isinstance(payload, dict):
            return None
        sub = payload.get("sub")
        csrf = payload.get("csrf")
        if not isinstance(sub, str) or not sub:
            return None
        if not isinstance(csrf, str) or not csrf:
            return None
        return SessionData(user_sub=sub, csrf_token=csrf)
