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
    """Missing, repeated, or otherwise malformed request parameter (RFC 6749 §5.2)."""

    error_code = "invalid_request"


class InvalidClient(OAuthError):
    """Client authentication failed (RFC 6749 §5.2) — answered 401 with a challenge."""

    error_code = "invalid_client"


class InvalidGrant(OAuthError):
    """The grant (code, refresh token, assertion, device code) is invalid,
    expired, revoked, already used, or bound to another client (RFC 6749 §5.2)."""

    error_code = "invalid_grant"


class UnauthorizedClient(OAuthError):
    """The authenticated client is not allowed to use this grant type (RFC 6749 §5.2)."""

    error_code = "unauthorized_client"


class UnsupportedGrantType(OAuthError):
    """`grant_type` is not supported by this authorization server (RFC 6749 §5.2)."""

    error_code = "unsupported_grant_type"


class InvalidScope(OAuthError):
    """Requested scope is invalid, unknown, or exceeds what was granted (RFC 6749 §5.2)."""

    error_code = "invalid_scope"


class ServerError(OAuthError):
    """Unexpected authorization-server failure (RFC 6749 §4.1.2.1)."""

    error_code = "server_error"


class TemporarilyUnavailable(OAuthError):
    """The AS is overloaded or under maintenance (RFC 6749 §4.1.2.1)."""

    error_code = "temporarily_unavailable"


class AccessDenied(OAuthError):
    """The resource owner or AS refused the request — RFC 6749 §4.1.2.1
    (browser flow) and RFC 8628 §3.5 (device flow denial)."""

    error_code = "access_denied"


# RFC 6750 §3.1 — protected-resource error vocabulary (not RFC 6749 §5.2).
class InvalidToken(OAuthError):
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
