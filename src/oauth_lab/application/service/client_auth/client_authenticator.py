"""Client authentication — RFC 6749 §2.3 + RFC 7521/7523/8705.

Each method (HTTP Basic, form-body, JWT assertion, mTLS, none) is a
Strategy. The `ClientCredentialsPipeline` selects the appropriate
authenticator by inspecting which credentials the request carried.

`AuthenticatedClient` is an application-layer value object: it represents
a `Client` that has successfully cleared the auth pipeline. We define it
here (next to the authenticator strategies) because that is where it
acquires meaning — the domain `Client` knows nothing of authentication.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass

from oauth_lab.application.port.inbound.issue_token_use_case import ClientCredentials
from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.domain.model.client import Client
from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidClient
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class AuthenticatedClient:
    """A `Client` that has cleared the client-authentication pipeline."""

    client: Client
    auth_method: ClientAuthMethod

    @property
    def id(self) -> ClientId:
        return self.client.id

    @property
    def allowed_scopes(self) -> ScopeSet:
        return self.client.allowed_scopes

    @property
    def default_audience(self) -> str | None:
        return self.client.default_audience

    def supports_grant(self, grant_type: GrantType) -> bool:
        return self.client.supports_grant(grant_type)


class ClientAuthenticator(ABC):
    """Strategy interface for one specific token_endpoint_auth_method."""

    @abstractmethod
    def can_handle(self, creds: ClientCredentials) -> bool: ...

    @abstractmethod
    async def authenticate(self, creds: ClientCredentials) -> AuthenticatedClient: ...


class ClientCredentialsPipeline:
    """Selects the first authenticator that can handle the request."""

    def __init__(
        self,
        authenticators: Iterable[ClientAuthenticator],
        clients: ClientRepository,
    ) -> None:
        self._authenticators = list(authenticators)
        self._clients = clients

    async def authenticate(self, creds: ClientCredentials) -> AuthenticatedClient:
        for auth in self._authenticators:
            if auth.can_handle(creds):
                return await auth.authenticate(creds)
        raise InvalidClient("no recognised client authentication method was used")
