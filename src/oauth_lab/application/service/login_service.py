"""LoginService — implements `LoginUseCase`. Verifies credentials and
issues a session cookie value.

Password verification goes through the `SecretHasher` outbound port
(Argon2id adapter in production) against the hash stored on `User`.
On success returns the *cookie value* — the route handler sets it on
the HTTP response.
"""

from __future__ import annotations

import secrets

from oauth_lab.application.port.inbound.login_use_case import InvalidCredentialsError
from oauth_lab.application.port.outbound.secret_hasher import SecretHasher
from oauth_lab.application.port.outbound.session_signer import SessionData, SessionSigner
from oauth_lab.application.port.outbound.user_repository import UserRepository


class LoginService:
    def __init__(
        self,
        *,
        users: UserRepository,
        session_signer: SessionSigner,
        secret_hasher: SecretHasher,
    ) -> None:
        self._users = users
        self._session_signer = session_signer
        self._hasher = secret_hasher

    async def execute(self, *, username: str, password: str) -> str:
        """Returns the signed session cookie value. Raises `InvalidCredentialsError` on failure."""
        user = await self._users.find_by_username(username)
        if user is None:
            # Burn the same hashing work as a real verification to keep the
            # timing constant — attackers can't distinguish "unknown user"
            # from "wrong password" by latency.
            self._hasher.dummy_verify()
            raise InvalidCredentialsError("invalid username or password")
        if not self._hasher.verify(user.password_hash, password):
            raise InvalidCredentialsError("invalid username or password")
        # Synchronizer CSRF token, minted with the session and carried inside the
        # signed cookie. Consent forms echo it back in a hidden field; the POST
        # handlers compare the two with `secrets.compare_digest`.
        return self._session_signer.sign(
            SessionData(user_sub=user.sub, csrf_token=secrets.token_urlsafe(32))
        )
