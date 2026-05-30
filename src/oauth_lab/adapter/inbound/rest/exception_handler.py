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

        return JSONResponse(status_code=exc.http_status, content=body, headers=headers)
