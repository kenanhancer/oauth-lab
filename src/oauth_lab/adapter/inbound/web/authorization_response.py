"""Authorization-response redirect encoding — the web adapter's wire format.

Single home for serializing an authorization response (success or error)
onto the client's `redirect_uri` query string, appending the `iss`
parameter required by RFC 9207 §2 so clients can detect mix-up attacks.
Both `authorize_controller` (error redirects) and `consent_controller`
(granted / denied) build their `Location` values here.
"""

from __future__ import annotations

from urllib.parse import quote, urlencode


def encode_authorization_response(
    redirect_uri: str,
    params: dict[str, str],
    *,
    state: str | None,
    issuer: str,
) -> str:
    """Append `params` (+ `state` if present, + `iss` per RFC 9207 §2) to
    `redirect_uri` as query parameters and return the full URL."""
    query = dict(params)
    if state:
        query["state"] = state
    query["iss"] = issuer                                                # RFC 9207
    separator = "&" if "?" in redirect_uri else "?"
    return redirect_uri + separator + urlencode(query, quote_via=quote)
