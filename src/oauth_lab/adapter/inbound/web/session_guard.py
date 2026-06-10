"""Session + CSRF gate shared by the browser POST endpoints.

Every state-changing browser form (`POST /consent`, `POST /device/consent`)
must run the same two checks before acting:

1. a valid signed session cookie — otherwise 303 back to `/login` to
   start the flow again;
2. the form's synchronizer `csrf_token` must match the one minted into
   the session at login (constant-time compare) — a mismatch raises
   `InvalidRequest` (RFC 6749 §5.2 `invalid_request`).
"""

from __future__ import annotations

import secrets

from fastapi.responses import RedirectResponse, Response

from oauth_lab.application.port.outbound.session_signer import SessionData, SessionSigner
from oauth_lab.domain.model.errors import InvalidRequest


def require_session_with_csrf(
    *,
    session_signer: SessionSigner,
    session_cookie: str | None,
    csrf_token: str,
) -> SessionData | Response:
    """Return the verified `SessionData`, or the `Response` to send instead.

    No valid session → 303 redirect to `/login`. CSRF token mismatch →
    raises `InvalidRequest` (rendered by the OAuth exception handler).
    """
    session = session_signer.verify(session_cookie)
    if session is None:
        # No valid session — start the flow again.
        return RedirectResponse(url="/login", status_code=303)

    if not secrets.compare_digest(csrf_token, session.csrf_token):
        raise InvalidRequest("CSRF token mismatch")

    return session
