"""ServerMetadataService — discovery derived from what the AS actually runs.

The capability lists are introspected, not transcribed: grants come
from the `GrantRegistry`, client-auth methods from the
`ClientCredentialsPipeline`. Registering a new grant or authenticator
updates discovery automatically — the documents can never drift from
the token endpoint's behaviour.

Endpoint URLs are derived from the configured issuer: the published
endpoint locations are part of the AS's announced identity (RFC 8414
§2 defines them all relative to the issuer the document is fetched
under).
"""

from __future__ import annotations

from oauth_lab.application.service.client_auth.client_authenticator import (
    ClientCredentialsPipeline,
)
from oauth_lab.application.service.grant.grant_registry import GrantRegistry


class ServerMetadataService:
    def __init__(
        self,
        *,
        issuer: str,
        grants: GrantRegistry,
        client_auth: ClientCredentialsPipeline,
        scopes_supported: list[str],
        id_token_signing_alg: str,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._grants = grants
        self._client_auth = client_auth
        self._scopes_supported = list(scopes_supported)
        self._id_token_signing_alg = id_token_signing_alg

    def oauth_metadata(self) -> dict[str, object]:
        issuer = self._issuer
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
            "device_authorization_endpoint": f"{issuer}/device_authorization",    # RFC 8628 §4
            "response_types_supported": ["code"],                                 # OAuth 2.1
            "grant_types_supported": self._grants.supported_grant_types(),
            "code_challenge_methods_supported": ["S256"],                        # plain is rejected
            "token_endpoint_auth_methods_supported": self._client_auth.supported_methods(),
            "scopes_supported": self._scopes_supported,
            # RFC 9207 §3: an AS that emits `iss` in authorization responses
            # (ConsentService does, on both success and error redirects) MUST
            # advertise it so clients know to validate the parameter.
            "authorization_response_iss_parameter_supported": True,
        }

    def openid_metadata(self) -> dict[str, object]:
        issuer = self._issuer
        metadata = self.oauth_metadata()
        metadata.update(
            {
                "userinfo_endpoint": f"{issuer}/userinfo",
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": [self._id_token_signing_alg],
                "claims_supported": [
                    "sub",
                    "iss",
                    "aud",
                    "exp",
                    "iat",
                    "auth_time",
                    "nonce",
                    "at_hash",
                    "preferred_username",
                    "email",
                    "email_verified",
                ],
            }
        )
        return metadata
