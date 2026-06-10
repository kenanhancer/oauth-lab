"""Token-type URIs — RFC 8693 §3.

The token-exchange grant identifies tokens by URI rather than by name;
this enum gathers the standard set so the codebase compares against
strongly-typed values, not magic strings.
"""

from __future__ import annotations

from enum import StrEnum


class TokenTypeURI(StrEnum):
    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105
    REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"  # noqa: S105
    ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"  # noqa: S105
    JWT = "urn:ietf:params:oauth:token-type:jwt"
    SAML1 = "urn:ietf:params:oauth:token-type:saml1"
    SAML2 = "urn:ietf:params:oauth:token-type:saml2"
