"""Form-body client authentication — RFC 6749 §2.3.1 (NOT RECOMMENDED variant)."""

from __future__ import annotations

from oauth_lab.application.port.inbound.issue_token_use_case import ClientCredentials
from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.application.port.outbound.secret_hasher import SecretHasher
from oauth_lab.application.service.client_auth.client_authenticator import (
    AuthenticatedClient,
    ClientAuthenticator,
)
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidClient


class ClientSecretPostAuthenticator(ClientAuthenticator):
    method = ClientAuthMethod.CLIENT_SECRET_POST

    def __init__(self, clients: ClientRepository, secret_hasher: SecretHasher) -> None:
        self._clients = clients
        self._hasher = secret_hasher

    def can_handle(self, creds: ClientCredentials) -> bool:
        return (
            creds.basic_auth_header is None
            and creds.form_client_id is not None
            and creds.form_client_secret is not None
        )

    async def authenticate(self, creds: ClientCredentials) -> AuthenticatedClient:
        assert creds.form_client_id is not None
        assert creds.form_client_secret is not None

        client = await self._clients.find_by_id(ClientId(creds.form_client_id))
        if client is None:
            # Verify against a throwaway hash to keep the timing constant —
            # an attacker must not be able to distinguish "unknown client"
            # from "wrong secret" by latency.
            self._hasher.dummy_verify()
            raise InvalidClient("unknown client_id")
        if client.token_endpoint_auth_method != self.method:
            raise InvalidClient("client is not configured for client_secret_post")
        self._verify_secret(client, creds.form_client_secret)

        return AuthenticatedClient(client=client, auth_method=self.method)

    def _verify_secret(self, client: Client, secret_plaintext: str) -> None:
        if client.secret_hash is None:
            raise InvalidClient("client has no secret configured")
        if not self._hasher.verify(client.secret_hash, secret_plaintext):
            raise InvalidClient("client authentication failed")
