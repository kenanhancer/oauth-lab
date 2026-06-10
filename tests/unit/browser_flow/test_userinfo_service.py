"""GetUserInfoService — OIDC Core §5.4 scope→claims policy.

Scenario: browser flow (OIDC). Pure application-layer test with a
stubbed `AccessTokenVerifier`; no HTTP, no JWT.

Location: `tests/unit/browser_flow/` — folder carries the scenario.
"""

from __future__ import annotations

import pytest

from oauth_lab.adapter.outbound.persistence.memory.user_repository import InMemoryUserRepository
from oauth_lab.application.port.outbound.access_token_verifier import AccessTokenClaims
from oauth_lab.application.service.get_user_info_service import GetUserInfoService
from oauth_lab.domain.model.errors import InvalidToken
from oauth_lab.domain.model.scope import ScopeSet
from oauth_lab.domain.model.user import User

_ALICE = User(
    sub="user-alice",
    username="alice",
    password_hash=b"irrelevant",
    email="alice@example.com",
)


class _StubVerifier:
    def __init__(self, claims: AccessTokenClaims) -> None:
        self._claims = claims

    def verify(self, token: str) -> AccessTokenClaims:
        return self._claims


def _service(claims: AccessTokenClaims) -> GetUserInfoService:
    users = InMemoryUserRepository({_ALICE.sub: _ALICE})
    return GetUserInfoService(token_verifier=_StubVerifier(claims), users=users)


async def test_scopes_gate_the_released_claims() -> None:
    # `profile` only → preferred_username but no email claims (§5.4).
    claims = AccessTokenClaims(sub="user-alice", scope=ScopeSet.parse("openid profile"))
    result = await _service(claims).execute("any-token")
    assert result.sub == "user-alice"
    assert result.preferred_username == "alice"
    assert result.email is None
    assert result.email_verified is None

    # `email` added → email + email_verified appear.
    claims = AccessTokenClaims(sub="user-alice", scope=ScopeSet.parse("openid profile email"))
    result = await _service(claims).execute("any-token")
    assert result.email == "alice@example.com"
    assert result.email_verified is True


async def test_unknown_sub_raises_invalid_token() -> None:
    claims = AccessTokenClaims(sub="no-such-user", scope=ScopeSet.parse("openid"))
    with pytest.raises(InvalidToken):
        await _service(claims).execute("any-token")


async def test_missing_sub_raises_invalid_token() -> None:
    claims = AccessTokenClaims(sub=None, scope=ScopeSet.parse("openid"))
    with pytest.raises(InvalidToken):
        await _service(claims).execute("any-token")
