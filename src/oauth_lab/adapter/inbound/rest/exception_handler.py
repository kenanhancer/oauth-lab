"""Single FastAPI exception handler for the OAuthError hierarchy.

Renders the RFC 6749 §5.2 JSON envelope:
    { "error": "...", "error_description": "...", "error_uri": "..." }

Headers per RFC 6749 §5.2: `Cache-Control: no-store`, `Pragma: no-cache`.
For `invalid_client` at the token endpoint, RFC 6749 §5.2 requires a
`WWW-Authenticate: Basic` response when the client used HTTP Basic.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from oauth_lab.domain.model.errors import InvalidClient, OAuthError

# HTTP binding of the RFC 6749 §5.2 error vocabulary. The spec defines 400
# as the default token-endpoint error status and singles out invalid_client
# for 401 (with a WWW-Authenticate challenge when HTTP auth was used);
# server_error / temporarily_unavailable mirror 500 / 503. The domain only
# carries `error_code` — this transport mapping belongs to the REST adapter.
_HTTP_STATUS_BY_ERROR_CODE: dict[str, int] = {
    "invalid_client": 401,
    "server_error": 500,
    "temporarily_unavailable": 503,
}
_DEFAULT_HTTP_STATUS = 400


def register_oauth_exception_handler(app: FastAPI) -> None:
    @app.exception_handler(OAuthError)
    async def handle(_: Request, exc: OAuthError) -> JSONResponse:
        body: dict[str, str] = {"error": exc.error_code}
        if exc.description:
            body["error_description"] = exc.description
        if exc.uri:
            body["error_uri"] = exc.uri

        headers: dict[str, str] = {
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
        if isinstance(exc, InvalidClient):
            headers["WWW-Authenticate"] = 'Basic realm="oauth-lab"'

        status = _HTTP_STATUS_BY_ERROR_CODE.get(exc.error_code, _DEFAULT_HTTP_STATUS)
        return JSONResponse(status_code=status, content=body, headers=headers)
