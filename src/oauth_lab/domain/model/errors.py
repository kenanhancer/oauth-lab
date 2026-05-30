"""OAuth 2.0 error hierarchy — RFC 6749 §5.2.

Every error rendered to the client at `/token`, `/revoke`, `/introspect`,
etc. derives from `OAuthError`. A single FastAPI exception handler maps
these to the RFC 6749 §5.2 JSON envelope.
"""

from __future__ import annotations


class OAuthError(Exception):
    """Base for all OAuth-defined errors."""

    error_code: str = "server_error"
    http_status: int = 500

    def __init__(self, description: str | None = None, uri: str | None = None) -> None:
        self.description = description
        self.uri = uri
        super().__init__(description or self.error_code)


class InvalidRequest(OAuthError):
    error_code = "invalid_request"
    http_status = 400


class InvalidClient(OAuthError):
    error_code = "invalid_client"
    http_status = 401


class InvalidGrant(OAuthError):
    error_code = "invalid_grant"
    http_status = 400


class UnauthorizedClient(OAuthError):
    error_code = "unauthorized_client"
    http_status = 400


class UnsupportedGrantType(OAuthError):
    error_code = "unsupported_grant_type"
    http_status = 400


class InvalidScope(OAuthError):
    error_code = "invalid_scope"
    http_status = 400


class ServerError(OAuthError):
    error_code = "server_error"
    http_status = 500


class TemporarilyUnavailable(OAuthError):
    error_code = "temporarily_unavailable"
    http_status = 503


# RFC 6749 § 4.1.2.1 — user explicitly denied authorization (browser flow);
# also RFC 8628 § 3.5 for device flow.
class AccessDenied(OAuthError):
    error_code = "access_denied"
    http_status = 400


# RFC 8628 § 3.5 — device flow polling responses.
class AuthorizationPending(OAuthError):
    """User has not yet approved (or denied) the device authorization."""

    error_code = "authorization_pending"
    http_status = 400


class SlowDown(OAuthError):
    """Device is polling faster than the AS-mandated interval."""

    error_code = "slow_down"
    http_status = 400


class ExpiredToken(OAuthError):
    """The `device_code` has expired before the user approved."""

    error_code = "expired_token"
    http_status = 400
