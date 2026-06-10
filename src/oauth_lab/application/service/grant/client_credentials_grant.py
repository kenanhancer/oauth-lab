"""Client Credentials grant — RFC 6749 §4.4.

Machine-to-machine. No user, no browser, no refresh token (per OAuth 2.1
§4.3 — refresh tokens are not issued for `client_credentials`).
"""

from __future__ import annotations

from typing import ClassVar

from oauth_lab.application.port.inbound.issue_token_use_case import (
    TokenIssuanceResult,
    TokenRequest,
)
from oauth_lab.application.port.outbound.token_issuer import TokenIssuer
from oauth_lab.application.service.client_auth.client_authenticator import AuthenticatedClient
from oauth_lab.application.service.grant.grant_strategy import GrantStrategy
from oauth_lab.domain.model.errors import UnauthorizedClient
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.service.scope_validator import ScopeValidator


class ClientCredentialsGrant(GrantStrategy):
    grant_type: ClassVar[GrantType] = GrantType.CLIENT_CREDENTIALS

    def __init__(
        self,
        token_issuer: TokenIssuer,
        scope_validator: ScopeValidator,
        access_token_ttl_seconds: int,
    ) -> None:
        self._token_issuer = token_issuer
        self._scope_validator = scope_validator
        self._ttl = access_token_ttl_seconds

    async def execute(
        self,
        request: TokenRequest,
        client: AuthenticatedClient,
    ) -> TokenIssuanceResult:
        if not client.supports_grant(self.grant_type):
            raise UnauthorizedClient(
                f"client is not allowed to use grant_type={self.grant_type.value}"
            )

        granted_scope = self._scope_validator.grantable(
            requested=request.scope,
            allowed=client.allowed_scopes,
        )

        audience = request.audience[0] if request.audience else client.default_audience

        issued = await self._token_issuer.issue(
            subject=str(client.id),
            client_id=str(client.id),
            scope=granted_scope,
            audience=audience,
            ttl_seconds=self._ttl,
        )

        return TokenIssuanceResult(
            access_token=issued.value,
            token_type="Bearer",  # noqa: S106 — RFC 6749 §7.1 token type, not a credential
            expires_in=issued.expires_in_seconds,
            scope=granted_scope,
        )
