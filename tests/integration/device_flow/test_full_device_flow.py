"""End-to-end device authorization flow — RFC 8628.

Walks the full zig-zag of the spec:

    Device → POST /device_authorization
                                    → returns (device_code, user_code, verification_uri, ...)
    Device → POST /token grant_type=device_code device_code=...
                                    → 400 authorization_pending  (user has not approved yet)
    User   → POST /login           (browser side)
    User   → POST /device user_code=...
                                    → renders consent HTML
    User   → POST /device/consent decision=approve
                                    → renders "done" page
    Device → POST /token grant_type=device_code device_code=...
                                    → 200 + access_token

Location: `tests/integration/device_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

import re

from httpx import AsyncClient

from tests.conftest import (
    DEMO_DEVICE_CLIENT_ID,
    DEMO_USER_PASSWORD,
    DEMO_USERNAME,
)


def _csrf(html: str) -> str:
    """Scrape the synchronizer CSRF token rendered into the device-consent page."""
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "csrf_token hidden field not found in rendered page"
    return match.group(1)


async def _start_device_flow(http_client: AsyncClient) -> dict:
    resp = await http_client.post(
        "/device_authorization",
        data={"client_id": DEMO_DEVICE_CLIENT_ID, "scope": "read"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestDeviceAuthorizationEndpoint:
    async def test_happy_path_returns_rfc8628_fields(
        self, http_client: AsyncClient
    ) -> None:
        body = await _start_device_flow(http_client)
        assert "device_code" in body
        assert "user_code" in body
        assert body["verification_uri"].endswith("/device")
        assert body["verification_uri_complete"].endswith(
            f"/device?user_code={body['user_code']}"
        )
        assert body["expires_in"] >= 60
        assert body["interval"] >= 1

    async def test_unknown_client_returns_invalid_client(
        self, http_client: AsyncClient
    ) -> None:
        resp = await http_client.post(
            "/device_authorization", data={"client_id": "ghost", "scope": "read"}
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"

    async def test_client_not_allowed_for_device_code(
        self, http_client: AsyncClient
    ) -> None:
        # demo-client is the M2M confidential client; not allowed device_code.
        resp = await http_client.post(
            "/device_authorization",
            data={"client_id": "demo-client", "scope": "read"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "unauthorized_client"


class TestDevicePolling:
    async def test_pending_then_approved(self, http_client: AsyncClient) -> None:
        # 1. Device starts the flow
        start = await _start_device_flow(http_client)
        device_code = start["device_code"]
        user_code = start["user_code"]

        # 2. Device polls — pending
        poll1 = await http_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": DEMO_DEVICE_CLIENT_ID,
                "device_code": device_code,
            },
        )
        assert poll1.status_code == 400
        assert poll1.json()["error"] == "authorization_pending"

        # 3. User logs in (browser side)
        login = await http_client.post(
            "/login",
            data={
                "username": DEMO_USERNAME,
                "password": DEMO_USER_PASSWORD,
                "next": "/",
            },
        )
        session = login.cookies["oauth_lab_session"]

        # 4. User submits the user_code → renders consent
        consent_page = await http_client.post(
            "/device",
            data={"user_code": user_code},
            cookies={"oauth_lab_session": session},
        )
        assert consent_page.status_code == 200
        assert user_code in consent_page.text
        assert DEMO_DEVICE_CLIENT_ID in consent_page.text
        csrf = _csrf(consent_page.text)

        # 5. User clicks Approve
        consent_post = await http_client.post(
            "/device/consent",
            data={"user_code": user_code, "decision": "approve", "csrf_token": csrf},
            cookies={"oauth_lab_session": session},
        )
        assert consent_post.status_code == 200
        assert "complete" in consent_post.text.lower() or "close" in consent_post.text.lower()

        # 6. Device polls again — success (must wait > interval since first poll)
        # Patch: in production a device sleeps `interval` seconds. In tests we
        # fast-forward by setting last_polled_at to None via the repo. But the
        # last poll already set it. So sleep — or use a smaller fixture. Here
        # we accept slow_down on poll2 and poll3 success.
        import asyncio
        await asyncio.sleep(start["interval"] + 0.1)
        poll_final = await http_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": DEMO_DEVICE_CLIENT_ID,
                "device_code": device_code,
            },
        )
        assert poll_final.status_code == 200, poll_final.text
        body = poll_final.json()
        assert body["token_type"] == "Bearer"
        assert isinstance(body["access_token"], str)
        assert isinstance(body["refresh_token"], str)               # demo-device supports refresh

    async def test_polling_too_fast_returns_slow_down(
        self, http_client: AsyncClient
    ) -> None:
        start = await _start_device_flow(http_client)
        device_code = start["device_code"]

        # First poll — pending (no last_polled_at yet, so this one is allowed)
        first = await http_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": DEMO_DEVICE_CLIENT_ID,
                "device_code": device_code,
            },
        )
        assert first.status_code == 400
        assert first.json()["error"] == "authorization_pending"

        # Immediate second poll — must say slow_down
        second = await http_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": DEMO_DEVICE_CLIENT_ID,
                "device_code": device_code,
            },
        )
        assert second.status_code == 400
        assert second.json()["error"] == "slow_down"

    async def test_user_denial_returns_access_denied(
        self, http_client: AsyncClient
    ) -> None:
        start = await _start_device_flow(http_client)
        device_code = start["device_code"]
        user_code = start["user_code"]

        # User logs in
        login = await http_client.post(
            "/login",
            data={"username": DEMO_USERNAME, "password": DEMO_USER_PASSWORD, "next": "/"},
        )
        session = login.cookies["oauth_lab_session"]

        # User opens the verification page (to obtain the CSRF token), then denies
        consent_page = await http_client.post(
            "/device",
            data={"user_code": user_code},
            cookies={"oauth_lab_session": session},
        )
        csrf = _csrf(consent_page.text)
        await http_client.post(
            "/device/consent",
            data={"user_code": user_code, "decision": "deny", "csrf_token": csrf},
            cookies={"oauth_lab_session": session},
        )

        # Device polls → access_denied (no prior poll, so the interval gate is open)
        import asyncio
        await asyncio.sleep(0.1)
        poll = await http_client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": DEMO_DEVICE_CLIENT_ID,
                "device_code": device_code,
            },
        )
        assert poll.status_code == 400
        assert poll.json()["error"] == "access_denied"


class TestDeviceWebEntry:
    async def test_get_device_renders_entry_form(self, http_client: AsyncClient) -> None:
        resp = await http_client.get("/device")
        assert resp.status_code == 200
        assert "Enter the code" in resp.text or "code" in resp.text.lower()

    async def test_post_device_unknown_code_shows_error(
        self, http_client: AsyncClient
    ) -> None:
        # Need a logged-in session so /device proceeds past the lookup
        login = await http_client.post(
            "/login",
            data={"username": DEMO_USERNAME, "password": DEMO_USER_PASSWORD, "next": "/"},
        )
        session = login.cookies["oauth_lab_session"]

        resp = await http_client.post(
            "/device",
            data={"user_code": "ZZZZ-ZZZZ"},
            cookies={"oauth_lab_session": session},
        )
        assert resp.status_code == 404
        assert "Unknown code" in resp.text or "try again" in resp.text.lower()
