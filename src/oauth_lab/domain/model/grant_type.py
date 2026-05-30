"""GrantType value object — RFC 6749 §1.3 + extension grants."""

from __future__ import annotations

from enum import StrEnum


class GrantType(StrEnum):
    """The `grant_type` form parameter value at the `/token` endpoint."""

    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
