"""Inbound port — the `/token` endpoint's contract with the application.

A driving adapter (REST controller) calls this exactly once per `/token`
request. The implementation lives in
`oauth_lab.application.service.issue_token_service`.
"""

from __future__ import annotations

from typing import Protocol

from oauth_lab.application.service.client_auth.client_authenticator import ClientCredentials
from oauth_lab.application.service.grant.grant_strategy import (
    TokenIssuanceResult,
    TokenRequest,
)


class IssueTokenUseCase(Protocol):
    async def execute(
        self,
        creds: ClientCredentials,
        request: TokenRequest,
    ) -> TokenIssuanceResult: ...
