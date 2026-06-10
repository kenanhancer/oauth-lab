"""Grant Strategy — the abstract algorithm for issuing a token.

One subclass per OAuth grant type. Each strategy receives:
- An `AuthenticatedClient` (the client-auth pipeline has already run)
- A `TokenRequest` carrying grant-specific parameters

…and produces a `TokenIssuanceResult` (or raises an `OAuthError`).
`TokenRequest` / `TokenIssuanceResult` are owned by the inbound port
(`issue_token_use_case`) — they are the use-case contract, not a detail
of the strategies.

This is the canonical Strategy pattern: 6+ algorithms with one shape,
dispatched by `grant_type`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from oauth_lab.application.port.inbound.issue_token_use_case import (
    TokenIssuanceResult,
    TokenRequest,
)
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.domain.model.grant_type import GrantType


class GrantStrategy(ABC):
    grant_type: ClassVar[GrantType]

    @abstractmethod
    async def execute(
        self,
        request: TokenRequest,
        client: AuthenticatedClient,
    ) -> TokenIssuanceResult: ...
