"""`POST /token` — token endpoint adapter.

Hosts both:

- The `CoreHandler` thin adapter that maps raw HTTP form parameters to
  the `IssueTokenUseCase` (domain types in, domain types out).
- The FastAPI route that wires request parsing to `CoreHandler` and
  renders the RFC 6749 §5.1 JSON response.

The generated `core_api.py` declares the route but never forwards the
Authorization header to the handler. We register our own route on the
same path *before* the generated router, so ours wins.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Header, Request
from fastapi.responses import JSONResponse

from oauth_lab.application.port.inbound.issue_token_use_case import IssueTokenUseCase
from oauth_lab.application.service.client_auth.client_authenticator import ClientCredentials
from oauth_lab.application.service.grant.grant_strategy import TokenIssuanceResult, TokenRequest
from oauth_lab.container import Container
from oauth_lab.domain.model.errors import InvalidRequest, UnsupportedGrantType
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import ScopeSet

# RFC 6749 §5.1 — successful token responses must not be cached.
_NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class CoreHandler:
    """Thin adapter from HTTP form parameters to the use case.

    Lives at the API boundary. Knows about FastAPI types only on its input
    side (raw header strings, form values); below it everything is domain
    types. Trivially unit-testable.
    """

    def __init__(self, issue_token: IssueTokenUseCase) -> None:
        self._issue_token = issue_token

    async def token(
        self,
        *,
        authorization_header: str | None,
        form_client_id: str | None,
        form_client_secret: str | None,
        form_client_assertion: str | None,
        form_client_assertion_type: str | None,
        grant_type: str | None,
        scope: str | None,
        audience: list[str] | None,
        resource: list[str] | None,
        code: str | None = None,
        redirect_uri: str | None = None,
        code_verifier: str | None = None,
        refresh_token: str | None = None,
        device_code: str | None = None,
        assertion: str | None = None,
        subject_token: str | None = None,
        subject_token_type: str | None = None,
        actor_token: str | None = None,
        actor_token_type: str | None = None,
        requested_token_type: str | None = None,
    ) -> TokenIssuanceResult:
        creds = self._extract_credentials(
            authorization_header=authorization_header,
            form_client_id=form_client_id,
            form_client_secret=form_client_secret,
            form_client_assertion=form_client_assertion,
            form_client_assertion_type=form_client_assertion_type,
        )
        request = self._build_token_request(
            grant_type=grant_type,
            scope=scope,
            audience=audience,
            resource=resource,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            refresh_token=refresh_token,
            device_code=device_code,
            assertion=assertion,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            requested_token_type=requested_token_type,
        )
        return await self._issue_token.execute(creds, request)

    @staticmethod
    def _extract_credentials(
        *,
        authorization_header: str | None,
        form_client_id: str | None,
        form_client_secret: str | None,
        form_client_assertion: str | None,
        form_client_assertion_type: str | None,
    ) -> ClientCredentials:
        basic_value: str | None = None
        if authorization_header:
            scheme, _, value = authorization_header.partition(" ")
            if scheme.lower() == "basic" and value:
                basic_value = value.strip()
        return ClientCredentials(
            basic_auth_header=basic_value,
            form_client_id=form_client_id,
            form_client_secret=form_client_secret,
            client_assertion=form_client_assertion,
            client_assertion_type=form_client_assertion_type,
        )

    @staticmethod
    def _build_token_request(
        *,
        grant_type: str | None,
        scope: str | None,
        audience: list[str] | None,
        resource: list[str] | None,
        code: str | None = None,
        redirect_uri: str | None = None,
        code_verifier: str | None = None,
        refresh_token: str | None = None,
        device_code: str | None = None,
        assertion: str | None = None,
        subject_token: str | None = None,
        subject_token_type: str | None = None,
        actor_token: str | None = None,
        actor_token_type: str | None = None,
        requested_token_type: str | None = None,
    ) -> TokenRequest:
        if grant_type is None:
            raise InvalidRequest("grant_type is required")
        try:
            gt = GrantType(grant_type)
        except ValueError as exc:
            raise UnsupportedGrantType(f"unknown grant_type: {grant_type}") from exc
        return TokenRequest(
            grant_type=gt,
            scope=ScopeSet.parse(scope),
            audience=tuple(audience or ()),
            resource=tuple(resource or ()),
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            refresh_token=refresh_token,
            device_code=device_code,
            assertion=assertion,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            requested_token_type=requested_token_type,
        )


router = APIRouter()


def _container(request: Request) -> Container:
    return request.app.state.container                                              # type: ignore[no-any-return]


def _handler(container: Annotated[Container, Depends(_container)]) -> CoreHandler:
    return CoreHandler(issue_token=container.issue_token)


@router.post("/token", tags=["Core"])
async def token(
    *,
    handler: Annotated[CoreHandler, Depends(_handler)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    grant_type: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
    client_assertion: Annotated[str | None, Form()] = None,
    client_assertion_type: Annotated[str | None, Form()] = None,
    scope: Annotated[str | None, Form()] = None,
    audience: Annotated[list[str] | None, Form()] = None,
    resource: Annotated[list[str] | None, Form()] = None,
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    device_code: Annotated[str | None, Form()] = None,
    assertion: Annotated[str | None, Form()] = None,
    subject_token: Annotated[str | None, Form()] = None,
    subject_token_type: Annotated[str | None, Form()] = None,
    actor_token: Annotated[str | None, Form()] = None,
    actor_token_type: Annotated[str | None, Form()] = None,
    requested_token_type: Annotated[str | None, Form()] = None,
) -> JSONResponse:
    result = await handler.token(
        authorization_header=authorization,
        form_client_id=client_id,
        form_client_secret=client_secret,
        form_client_assertion=client_assertion,
        form_client_assertion_type=client_assertion_type,
        grant_type=grant_type,
        scope=scope,
        audience=audience,
        resource=resource,
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        refresh_token=refresh_token,
        device_code=device_code,
        assertion=assertion,
        subject_token=subject_token,
        subject_token_type=subject_token_type,
        actor_token=actor_token,
        actor_token_type=actor_token_type,
        requested_token_type=requested_token_type,
    )
    body: dict[str, object] = {
        "access_token": result.access_token,
        "token_type": result.token_type,
        "expires_in": result.expires_in,
    }
    if result.scope is not None and not result.scope.is_empty():
        body["scope"] = result.scope.to_str()
    if result.refresh_token is not None:
        body["refresh_token"] = result.refresh_token
    if result.id_token is not None:
        body["id_token"] = result.id_token
    if result.issued_token_type is not None:
        body["issued_token_type"] = result.issued_token_type
    return JSONResponse(content=body, headers=_NO_STORE_HEADERS)
