"""RequestDeviceAuthorizationService — RFC 8628 § 3.1 + 3.2.

Handles the device's initial `POST /device_authorization` call:

1. Authenticate the client by `client_id` (public client; PKCE-style —
   we do NOT require a secret on this endpoint per RFC 8628 § 3.1).
2. Verify the client is allowed to use `device_code`.
3. Validate requested scopes.
4. Mint a fresh `device_code` (opaque, long) + `user_code` (short,
   human-typable).
5. Persist `DeviceCode` and return the response payload.
"""

from __future__ import annotations

from datetime import timedelta

from oauth_lab.application.port.inbound.request_device_authorization_use_case import (
    DeviceAuthorizationRequest,
    DeviceAuthorizationResponse,
)
from oauth_lab.application.port.outbound.client_repository import ClientRepository
from oauth_lab.application.port.outbound.clock import Clock
from oauth_lab.application.port.outbound.device_code_repository import DeviceCodeRepository
from oauth_lab.application.port.outbound.random_source import RandomSource
from oauth_lab.application.port.outbound.user_code_generator import UserCodeGenerator
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.device_code import DeviceCode
from oauth_lab.domain.model.errors import (
    InvalidClient,
    InvalidRequest,
    InvalidScope,
    UnauthorizedClient,
)
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import ScopeSet


class RequestDeviceAuthorizationService:
    def __init__(
        self,
        *,
        clients: ClientRepository,
        device_codes: DeviceCodeRepository,
        random_source: RandomSource,
        user_code_generator: UserCodeGenerator,
        clock: Clock,
        issuer: str,
        device_code_ttl_seconds: int,
        polling_interval_seconds: int,
    ) -> None:
        self._clients = clients
        self._device_codes = device_codes
        self._random = random_source
        self._user_codes = user_code_generator
        self._clock = clock
        self._issuer = issuer.rstrip("/")
        self._ttl = device_code_ttl_seconds
        self._interval = polling_interval_seconds

    async def execute(
        self, request: DeviceAuthorizationRequest
    ) -> DeviceAuthorizationResponse:
        if not request.client_id:
            raise InvalidRequest("client_id is required")

        client = await self._clients.find_by_id(ClientId(request.client_id))
        if client is None:
            raise InvalidClient("unknown client_id")
        if not client.supports_grant(GrantType.DEVICE_CODE):
            raise UnauthorizedClient(
                "client is not allowed to use the device_code grant"
            )

        requested_scope = ScopeSet.parse(request.scope)
        if (
            not requested_scope.is_empty()
            and not requested_scope.is_subset_of(client.allowed_scopes)
        ):
            raise InvalidScope("requested scope contains values not allowed for this client")
        scope = requested_scope if not requested_scope.is_empty() else client.allowed_scopes

        now = self._clock.now()
        device_code_value = self._random.token_urlsafe(32)
        user_code_value = self._user_codes.generate()

        code = DeviceCode(
            device_code=device_code_value,
            user_code=user_code_value,
            client_id=client.id,
            scope=scope,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._ttl),
            interval=self._interval,
        )
        await self._device_codes.save(code)

        return DeviceAuthorizationResponse(
            device_code=device_code_value,
            user_code=user_code_value,
            verification_uri=f"{self._issuer}/device",
            verification_uri_complete=(
                f"{self._issuer}/device?user_code={user_code_value}"
            ),
            expires_in=self._ttl,
            interval=self._interval,
        )
