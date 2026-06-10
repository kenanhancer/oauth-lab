"""End-to-end browser flow — `authorization_code` + PKCE.

Walks the full HTTP zigzag of the spec:

    1. GET /authorize?...         → 303 to /login?next=...
    2. POST /login                → 303 to /authorize... (Set-Cookie)
    3. GET /authorize?... (auth'd) → 200 consent HTML
    4. POST /consent (approve)    → 303 to redirect_uri?code=...&state=...
    5. POST /token + code+verifier → 200 access_token

Edge cases also exercised:
- POST /login with wrong password → 401, no cookie
- POST /consent (deny) → 303 to redirect_uri?error=access_denied
- GET /authorize with unknown client_id → 400 HTML error page (NOT a redirect)
- GET /authorize with bad redirect_uri → 400 HTML error page
- GET /authorize without PKCE → 303 redirect with error=invalid_request

Location: `tests/integration/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from httpx import AsyncClient

from tests.conftest import (
    DEMO_PUBLIC_CLIENT_ID,
    DEMO_PUBLIC_CLIENT_REDIRECT_URI,
    DEMO_USER_PASSWORD,
    DEMO_USERNAME,
)

# RFC 7636 Appendix B PKCE pair
_PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
_PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _authorize_qs(**overrides: str) -> str:
    params = {
        "response_type": "code",
        "client_id": DEMO_PUBLIC_CLIENT_ID,
        "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
        "scope": "read",
        "state": "test-state-xyz",
        "code_challenge": _PKCE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return urlencode(params)


def _csrf(html: str) -> str:
    """Scrape the synchronizer CSRF token rendered into the consent page."""
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "csrf_token hidden field not found in rendered page"
    return match.group(1)


class TestEndToEndBrowserFlow:
    async def test_full_happy_path(self, http_client: AsyncClient) -> None:
        # Step 1 — GET /authorize without a session ⇒ redirect to /login
        resp = await http_client.get(f"/authorize?{_authorize_qs()}")
        assert resp.status_code == 303
        login_location = resp.headers["location"]
        assert login_location.startswith("/login?next=")

        # Step 2 — POST /login with correct credentials ⇒ session cookie + redirect back
        resp = await http_client.post(
            "/login",
            data={
                "username": DEMO_USERNAME,
                "password": DEMO_USER_PASSWORD,
                "next": f"/authorize?{_authorize_qs()}",
            },
        )
        assert resp.status_code == 303
        assert "oauth_lab_session" in resp.cookies
        session_cookie = resp.cookies["oauth_lab_session"]

        # Step 3 — GET /authorize WITH the session cookie ⇒ 200 consent HTML
        resp = await http_client.get(
            f"/authorize?{_authorize_qs()}",
            cookies={"oauth_lab_session": session_cookie},
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Authorize" in resp.text
        assert DEMO_PUBLIC_CLIENT_ID in resp.text
        assert "read" in resp.text  # requested scope rendered
        csrf = _csrf(resp.text)

        # Step 4 — POST /consent (approve) ⇒ 303 to redirect_uri?code=...&state=...
        resp = await http_client.post(
            "/consent",
            data={
                "decision": "approve",
                "csrf_token": csrf,
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "scope": "read",
                "state": "test-state-xyz",
                "code_challenge": _PKCE_CHALLENGE,
                "code_challenge_method": "S256",
            },
            cookies={"oauth_lab_session": session_cookie},
        )
        assert resp.status_code == 303
        callback = urlparse(resp.headers["location"])
        assert f"{callback.scheme}://{callback.netloc}{callback.path}" == (
            DEMO_PUBLIC_CLIENT_REDIRECT_URI
        )
        params = parse_qs(callback.query)
        assert "code" in params
        assert params["state"] == ["test-state-xyz"]
        code = params["code"][0]

        # Step 5 — POST /token ⇒ access_token
        resp = await http_client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "code": code,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "code_verifier": _PKCE_VERIFIER,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert body["scope"] == "read"
        assert isinstance(body["access_token"], str)


class TestLoginEdgeCases:
    async def test_wrong_password_returns_401_no_cookie(self, http_client: AsyncClient) -> None:
        resp = await http_client.post(
            "/login",
            data={
                "username": DEMO_USERNAME,
                "password": "wrong-password",
                "next": "/",
            },
        )
        assert resp.status_code == 401
        assert "oauth_lab_session" not in resp.cookies
        assert "Invalid username or password" in resp.text

    async def test_get_login_renders_form(self, http_client: AsyncClient) -> None:
        resp = await http_client.get("/login")
        assert resp.status_code == 200
        assert "Sign in" in resp.text
        assert "<input" in resp.text


class TestConsentEdgeCases:
    async def _sign_in(self, http_client: AsyncClient) -> str:
        resp = await http_client.post(
            "/login",
            data={
                "username": DEMO_USERNAME,
                "password": DEMO_USER_PASSWORD,
                "next": "/",
            },
        )
        return resp.cookies["oauth_lab_session"]

    async def test_deny_redirects_with_access_denied(self, http_client: AsyncClient) -> None:
        cookie = await self._sign_in(http_client)
        # Render the consent page (with the session) to obtain the CSRF token.
        page = await http_client.get(
            f"/authorize?{_authorize_qs(state='abc')}",
            cookies={"oauth_lab_session": cookie},
        )
        assert page.status_code == 200
        csrf = _csrf(page.text)
        resp = await http_client.post(
            "/consent",
            data={
                "decision": "deny",
                "csrf_token": csrf,
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "scope": "read",
                "state": "abc",
                "code_challenge": _PKCE_CHALLENGE,
                "code_challenge_method": "S256",
            },
            cookies={"oauth_lab_session": cookie},
        )
        assert resp.status_code == 303
        callback = urlparse(resp.headers["location"])
        params = parse_qs(callback.query)
        assert params["error"] == ["access_denied"]
        assert params["state"] == ["abc"]
        assert "code" not in params

    async def test_consent_without_session_redirects_to_login(
        self, http_client: AsyncClient
    ) -> None:
        resp = await http_client.post(
            "/consent",
            data={
                "decision": "approve",
                "client_id": DEMO_PUBLIC_CLIENT_ID,
                "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                "scope": "read",
                "state": "abc",
                "code_challenge": _PKCE_CHALLENGE,
                "code_challenge_method": "S256",
            },
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"


class TestAuthorizeValidation:
    async def test_unknown_client_renders_error_page_not_redirect(
        self, http_client: AsyncClient
    ) -> None:
        # RFC 6749 §4.1.2.1: invalid client_id MUST NOT redirect.
        resp = await http_client.get(f"/authorize?{_authorize_qs(client_id='does-not-exist')}")
        assert resp.status_code == 400
        assert "text/html" in resp.headers["content-type"]
        assert "invalid_client" in resp.text or "unknown client_id" in resp.text

    async def test_bad_redirect_uri_renders_error_page_not_redirect(
        self, http_client: AsyncClient
    ) -> None:
        # RFC 6749 §4.1.2.1 + RFC 9700 §4.1.3: invalid redirect_uri MUST NOT redirect.
        resp = await http_client.get(
            f"/authorize?{_authorize_qs(redirect_uri='http://evil.example.com/callback')}"
        )
        assert resp.status_code == 400
        assert "text/html" in resp.headers["content-type"]

    async def test_missing_pkce_redirects_with_error(self, http_client: AsyncClient) -> None:
        # PKCE is mandatory in OAuth 2.1; missing → redirect to client with error.
        resp = await http_client.get(
            "/authorize?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": DEMO_PUBLIC_CLIENT_ID,
                    "redirect_uri": DEMO_PUBLIC_CLIENT_REDIRECT_URI,
                    "scope": "read",
                    "state": "s",
                }
            )
        )
        assert resp.status_code == 303
        callback = urlparse(resp.headers["location"])
        params = parse_qs(callback.query)
        assert params["error"] == ["invalid_request"]
        assert params["state"] == ["s"]

    async def test_implicit_response_type_redirects_with_error(
        self, http_client: AsyncClient
    ) -> None:
        # Implicit (`response_type=token`) is removed in OAuth 2.1.
        resp = await http_client.get(f"/authorize?{_authorize_qs(response_type='token')}")
        assert resp.status_code == 303
        callback = urlparse(resp.headers["location"])
        params = parse_qs(callback.query)
        assert params["error"] == ["unsupported_response_type"]


@pytest.mark.parametrize("http_method", ["GET", "POST"])
class TestRoutesExist:
    async def test_login_route_responds(self, http_client: AsyncClient, http_method: str) -> None:
        if http_method == "GET":
            resp = await http_client.get("/login")
            assert resp.status_code == 200
        else:
            resp = await http_client.post("/login", data={"username": "x", "password": "y"})
            assert resp.status_code in (200, 303, 401)
