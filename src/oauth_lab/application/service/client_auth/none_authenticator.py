"""Null Object — public client authentication (`token_endpoint_auth_method=none`).

Per RFC 6749 §2.3, public clients have no credentials. The Null Object
keeps the pipeline uniform: it identifies the client by `client_id`
alone and returns an `AuthenticatedClient` with `auth_method=none`.

PKCE is the actual security control for public clients in the
`authorization_code` flow, not client authentication.
"""

from __future__ import annotations

from oauth_lab.application.port.inbound.issue_token_use_case import ClientCredentials
from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.application.service.client_auth.client_authenticator import (
    AuthenticatedClient,
    ClientAuthenticator,
)
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidClient


class NoneAuthenticator(ClientAuthenticator):
    method = ClientAuthMethod.NONE

    def __init__(self, clients: ClientRepository) -> None:
        self._clients = clients

    def can_handle(self, creds: ClientCredentials) -> bool:
        return (
            creds.basic_auth_header is None
            and creds.form_client_secret is None
            and creds.client_assertion is None
            and creds.form_client_id is not None
        )

    async def authenticate(self, creds: ClientCredentials) -> AuthenticatedClient:
        assert creds.form_client_id is not None
        client = await self._clients.find_by_id(ClientId(creds.form_client_id))
        if client is None:
            raise InvalidClient("unknown client_id")
        if client.token_endpoint_auth_method != self.method:
            raise InvalidClient("client requires authentication")
        return AuthenticatedClient(client=client, auth_method=self.method)
