"""IssueTokenService — orchestrates `/token` from a single entry point.

Implements the `IssueTokenUseCase` inbound port. Pipeline:
    1. Authenticate the client (Strategy chosen by what creds it carried).
    2. Resolve the grant strategy by `grant_type`.
    3. Execute the grant.
    4. Return a `TokenIssuanceResult`.

This is the application-layer seam — REST controllers call this exactly
once per `/token` request. Everything below it is pure.
"""

from __future__ import annotations

from oauth_lab.application.service.client_auth.client_authenticator import (
    ClientCredentials,
    ClientCredentialsPipeline,
)
from oauth_lab.application.service.grant.grant_registry import GrantRegistry
from oauth_lab.application.service.grant.grant_strategy import (
    TokenIssuanceResult,
    TokenRequest,
)


class IssueTokenService:
    def __init__(
        self,
        client_auth: ClientCredentialsPipeline,
        grants: GrantRegistry,
    ) -> None:
        self._client_auth = client_auth
        self._grants = grants

    async def execute(
        self,
        creds: ClientCredentials,
        request: TokenRequest,
    ) -> TokenIssuanceResult:
        client = await self._client_auth.authenticate(creds)
        strategy = self._grants.resolve(request.grant_type.value)
        return await strategy.execute(request, client)
