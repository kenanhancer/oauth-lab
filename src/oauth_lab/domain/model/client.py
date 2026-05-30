"""Client entity — the OAuth registered client (RFC 6749 §2).

`Client` is the aggregate root: it owns its registered credentials, grants,
scopes, and redirect URIs. The `secret_hash` is an Argon2id digest; the
plaintext secret never lives in the entity.

Note: `AuthenticatedClient` (the auth-pipeline wrapper) lives at the
application layer (`application/service/client_auth/`) — that concept is
about authentication, not about the client aggregate itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from oauth_lab.domain.model.client_auth_method import ClientAuthMethod
from oauth_lab.domain.model.client_id import ClientId
from oauth_lab.domain.model.grant_type import GrantType
from oauth_lab.domain.model.scope import ScopeSet


@dataclass(frozen=True, slots=True)
class Client:
    id: ClientId
    secret_hash: bytes | None                    # None for public clients
    token_endpoint_auth_method: ClientAuthMethod
    allowed_grant_types: frozenset[GrantType]
    allowed_scopes: ScopeSet
    redirect_uris: frozenset[str] = field(default_factory=frozenset)
    default_audience: str | None = None

    def is_public(self) -> bool:
        return self.secret_hash is None

    def is_confidential(self) -> bool:
        return self.secret_hash is not None

    def supports_grant(self, grant_type: GrantType) -> bool:
        return grant_type in self.allowed_grant_types
