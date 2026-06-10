"""OAuth 2.0 error hierarchy — RFC 6749 §5.2.

Every error rendered to the client at `/token`, `/device_authorization`,
`/userinfo`, etc. derives from `OAuthError`. A single FastAPI exception
handler maps these to the RFC 6749 §5.2 JSON envelope.

The domain speaks only the RFC error vocabulary (`error_code`); the HTTP
status binding is a transport concern and lives in the REST adapter's
exception handler.
"""

from __future__ import annotations


class OAuthError(Exception):
    """Base for all OAuth-defined errors."""

    error_code: str = "server_error"

    def __init__(self, description: str | None = None, uri: str | None = None) -> None:
        self.description = description
        self.uri = uri
        super().__init__(description or self.error_code)


class InvalidRequest(OAuthError):
    error_code = "invalid_request"


class InvalidClient(OAuthError):
    error_code = "invalid_client"


class InvalidGrant(OAuthError):
    error_code = "invalid_grant"


class UnauthorizedClient(OAuthError):
    error_code = "unauthorized_client"


class UnsupportedGrantType(OAuthError):
    error_code = "unsupported_grant_type"


class InvalidScope(OAuthError):
    error_code = "invalid_scope"


class ServerError(OAuthError):
    error_code = "server_error"


class TemporarilyUnavailable(OAuthError):
    error_code = "temporarily_unavailable"


# RFC 6749 § 4.1.2.1 — user explicitly denied authorization (browser flow);
# also RFC 8628 § 3.5 for device flow.
class AccessDenied(OAuthError):
    error_code = "access_denied"


# RFC 6750 §3.1 — protected-resource error vocabulary (not RFC 6749 §5.2).
class InvalidToken(OAuthError):                               # noqa: N818 — RFC error vocabulary
    """The access token presented to a protected resource is expired,
    revoked, malformed, or otherwise invalid (RFC 6750 §3.1).

    Raised by resource endpoints (`/userinfo`), never by the token
    endpoint — there a bad *grant* is `invalid_grant` and bad *client
    credentials* are `invalid_client`.
    """

    error_code = "invalid_token"


# RFC 8628 § 3.5 — device flow polling responses.
class AuthorizationPending(OAuthError):
    """User has not yet approved (or denied) the device authorization."""

    error_code = "authorization_pending"


class SlowDown(OAuthError):
    """Device is polling faster than the AS-mandated interval."""

    error_code = "slow_down"


class ExpiredToken(OAuthError):
    """The `device_code` has expired before the user approved."""

    error_code = "expired_token"
