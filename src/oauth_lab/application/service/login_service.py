"""LoginService — implements `LoginUseCase`. Verifies credentials and
issues a session cookie value.

Argon2id verification using the hash stored on `User`. On success
returns the *cookie value* — the route handler sets it on the HTTP
response.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from oauth_lab.application.port.outbound.session_signer import SessionData, SessionSigner
from oauth_lab.application.port.outbound.user_repository import UserRepository
from oauth_lab.domain.model.errors import OAuthError


class InvalidCredentials(OAuthError):
    """Wrong username/password. The `/login` route renders the form again
    with an error message; it doesn't return a JSON envelope."""

    error_code = "invalid_credentials"
    http_status = 401


class LoginService:
    def __init__(self, *, users: UserRepository, session_signer: SessionSigner) -> None:
        self._users = users
        self._session_signer = session_signer
        self._hasher = PasswordHasher()

    async def execute(self, *, username: str, password: str) -> str:
        """Returns the signed session cookie value. Raises `InvalidCredentials` on failure."""
        user = await self._users.find_by_username(username)
        if user is None:
            # Run the hasher anyway to keep the timing constant — attackers can't
            # distinguish "unknown user" from "wrong password" by latency.
            self._hasher.hash(password)
            raise InvalidCredentials("invalid username or password")
        try:
            self._hasher.verify(user.password_hash.decode("utf-8"), password)
        except VerifyMismatchError as exc:
            raise InvalidCredentials("invalid username or password") from exc
        return self._session_signer.sign(SessionData(user_sub=user.sub))
