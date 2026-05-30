"""HTTP Basic client authentication — RFC 6749 §2.3.1."""

from __future__ import annotations

import base64
import binascii
from urllib.parse import unquote

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.application.service.client_auth.client_authenticator import (
    AuthenticatedClient,
    ClientAuthenticator,
    ClientCredentials,
)
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidClient


class ClientSecretBasicAuthenticator(ClientAuthenticator):
    def __init__(self, clients: ClientRepository) -> None:
        self._clients = clients
        self._hasher = PasswordHasher()

    def can_handle(self, creds: ClientCredentials) -> bool:
        return creds.basic_auth_header is not None

    async def authenticate(self, creds: ClientCredentials) -> AuthenticatedClient:
        assert creds.basic_auth_header is not None
        client_id_str, client_secret = self._decode(creds.basic_auth_header)

        client = await self._clients.find_by_id(ClientId(client_id_str))
        if client is None:
            raise InvalidClient("unknown client_id")
        if client.token_endpoint_auth_method != ClientAuthMethod.CLIENT_SECRET_BASIC:
            raise InvalidClient("client is not configured for client_secret_basic")
        self._verify_secret(client, client_secret)

        return AuthenticatedClient(client=client, auth_method=ClientAuthMethod.CLIENT_SECRET_BASIC)

    @staticmethod
    def _decode(header_value: str) -> tuple[str, str]:
        try:
            raw = base64.b64decode(header_value, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise InvalidClient("malformed Basic credentials") from exc
        if ":" not in raw:
            raise InvalidClient("malformed Basic credentials")
        client_id_pct, secret_pct = raw.split(":", 1)
        return unquote(client_id_pct), unquote(secret_pct)

    def _verify_secret(self, client: Client, secret_plaintext: str) -> None:
        if client.secret_hash is None:
            raise InvalidClient("client has no secret configured")
        try:
            self._hasher.verify(client.secret_hash.decode("utf-8"), secret_plaintext)
        except VerifyMismatchError as exc:
            raise InvalidClient("client authentication failed") from exc
