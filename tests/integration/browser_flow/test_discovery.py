"""Discovery endpoints — RFC 8414 + OIDC Discovery 1.0.

Verifies the two `.well-known` JSON documents:
- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`

These let any OAuth/OIDC client discover the AS's capabilities without
prior configuration — `curl <issuer>/.well-known/openid-configuration`
is how MCP clients, OIDC RPs, and IdP federations bootstrap.

Location: `tests/integration/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

from httpx import AsyncClient


class TestOAuthAuthorizationServerMetadata:
    async def test_returns_required_fields(self, http_client: AsyncClient) -> None:
        resp = await http_client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        body = resp.json()

        # RFC 8414 §2 required / strongly recommended fields:
        assert body["issuer"]
        assert body["authorization_endpoint"].endswith("/authorize")
        assert body["token_endpoint"].endswith("/token")
        assert body["jwks_uri"].endswith("/jwks")
        assert "code" in body["response_types_supported"]
        assert "authorization_code" in body["grant_types_supported"]
        assert "client_credentials" in body["grant_types_supported"]
        assert "refresh_token" in body["grant_types_supported"]
        # Every grant the AS actually implements must be advertised (RFC 8414 §2).
        assert "urn:ietf:params:oauth:grant-type:device_code" in body["grant_types_supported"]
        assert "urn:ietf:params:oauth:grant-type:jwt-bearer" in body["grant_types_supported"]
        assert (
            "urn:ietf:params:oauth:grant-type:token-exchange"
            in body["grant_types_supported"]
        )
        # Device flow is implemented, so its endpoint is discoverable (RFC 8628 §4).
        assert body["device_authorization_endpoint"].endswith("/device_authorization")
        assert body["code_challenge_methods_supported"] == ["S256"]                # OAuth 2.1
        assert "none" in body["token_endpoint_auth_methods_supported"]
        assert "client_secret_basic" in body["token_endpoint_auth_methods_supported"]


class TestOpenIDConnectMetadata:
    async def test_includes_oidc_specific_fields(self, http_client: AsyncClient) -> None:
        resp = await http_client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        body = resp.json()

        # Same as OAuth metadata above:
        assert body["issuer"]
        assert body["authorization_endpoint"].endswith("/authorize")
        assert body["token_endpoint"].endswith("/token")
        assert body["jwks_uri"].endswith("/jwks")

        # OIDC Discovery 1.0 additions:
        assert body["userinfo_endpoint"].endswith("/userinfo")
        assert "public" in body["subject_types_supported"]
        assert "RS256" in body["id_token_signing_alg_values_supported"]
        assert "openid" in body["scopes_supported"]
        assert "sub" in body["claims_supported"]
        assert "nonce" in body["claims_supported"]
        assert "at_hash" in body["claims_supported"]
