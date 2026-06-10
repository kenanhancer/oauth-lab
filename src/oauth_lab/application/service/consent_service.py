"""ConsentService — implements `ConsentUseCase` for `POST /consent`.

Approve: mint an `AuthorizationCode`, persist it bound to user + client
+ scope + redirect_uri + PKCE challenge, return `ConsentGranted`.

Deny: return `ConsentDenied` (RFC 6749 §4.1.2.1 — the adapter encodes
it as an `error=access_denied` redirect).

Re-validates client + redirect_uri because the consent form fields are
user-controllable.
"""

from __future__ import annotations

from datetime import timedelta

from oauth_lab.application.port.inbound.consent_use_case import (
    ConsentDecision,
    ConsentDenied,
    ConsentGranted,
    ConsentResult,
)
from oauth_lab.application.port.outbound.authorization_code_repository import (
    AuthorizationCodeRepository,
)
from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.random_source import RandomSource
from oauth_lab.domain.model.authorization_code import AuthorizationCode
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.errors import InvalidRequest, InvalidScope
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.pkce import PKCEChallenge
from oauth_lab.domain.model.scope import ScopeSet


class ConsentService:
    def __init__(
        self,
        *,
        clients: ClientRepository,
        auth_codes: AuthorizationCodeRepository,
        random_source: RandomSource,
        clock: Clock,
        code_ttl_seconds: int,
    ) -> None:
        self._clients = clients
        self._auth_codes = auth_codes
        self._random = random_source
        self._clock = clock
        self._code_ttl = code_ttl_seconds

    async def execute(self, decision: ConsentDecision) -> ConsentResult:
        # Re-validate client + redirect_uri — the form is user-controllable.
        client = await self._clients.find_by_id(ClientId(decision.client_id))
        if client is None:
            raise InvalidRequest("unknown client_id")
        if decision.redirect_uri not in client.redirect_uris:
            raise InvalidRequest("redirect_uri does not match a registered URI")
        if not client.supports_grant(GrantType.AUTHORIZATION_CODE):
            raise InvalidRequest("client is not allowed to use authorization_code grant")

        # User denied — RFC 6749 §4.1.2.1 access_denied.
        if not decision.approved:
            return ConsentDenied(
                redirect_uri=decision.redirect_uri,
                error_description="user denied the authorization request",
                state=decision.state,
            )

        # User approved — mint a code.
        pkce_challenge = PKCEChallenge(
            value=decision.code_challenge, method=decision.code_challenge_method or "S256"
        )
        # The scope field is user-controllable — a confused or malicious
        # user-agent could request more than the client is registered for.
        # Re-validate the subset relation here, mirroring /authorize.
        requested_scope = ScopeSet.parse(decision.scope)
        if not requested_scope.is_empty():
            if not requested_scope.is_subset_of(client.allowed_scopes):
                raise InvalidScope("requested scope exceeds the client's allowed scopes")
            granted_scope = requested_scope
        else:
            granted_scope = client.allowed_scopes

        now = self._clock.now()
        code = AuthorizationCode(
            value=self._random.token_urlsafe(32),
            client_id=client.id,
            user_sub=decision.user_sub,
            redirect_uri=decision.redirect_uri,
            scope=granted_scope,
            pkce_challenge=pkce_challenge,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._code_ttl),
        )
        await self._auth_codes.save(code)

        return ConsentGranted(
            redirect_uri=decision.redirect_uri,
            code=code.value,
            state=decision.state,
        )
