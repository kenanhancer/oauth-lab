"""Application settings — pydantic-settings, 12-factor, env-driven."""

from __future__ import annotations

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Asymmetric JWS algorithms only. `none` (unsigned) and `HS*` (HMAC) are
# rejected: a public `/jwks` cannot publish a verifiable key for a symmetric
# secret, and `none` would let anyone forge tokens (RFC 7518 §3.1, RFC 8725 §3.1).
_ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OAUTH_LAB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    issuer: str = "http://localhost:8000"
    database_url: str = "memory://"

    # Demo seeding writes publicly-known credentials (demo-client/demo-secret,
    # alice/alice-password). The CLI refuses to seed a non-localhost issuer
    # unless this is set, so they cannot leak into a real deployment.
    allow_demo_seed: bool = False

    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 30 * 24 * 3600  # 30 days (RFC 9700 §2.2.2 rotation)
    authorization_code_ttl_seconds: int = 60  # RFC 9700 §2.1.1 recommends ≤60s
    device_code_ttl_seconds: int = 1800  # 30 min (RFC 8628 §3.2 example)
    device_code_polling_interval_seconds: int = 5  # RFC 8628 §3.2 default
    session_ttl_seconds: int = 3600  # browser session cookie max age
    session_secret_key: str = "dev-only-change-me"  # itsdangerous signing key
    token_format: str = "jwt"  # "opaque" | "jwt"; jwt default so /userinfo works

    jwt_private_key_path: Path | None = None
    jwt_key_id: str | None = None
    jwt_algorithm: str = "RS256"

    log_level: str = "INFO"

    @field_validator("jwt_algorithm")
    @classmethod
    def _validate_jwt_algorithm(cls, value: str) -> str:
        if value not in _ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"OAUTH_LAB_JWT_ALGORITHM={value!r} is not allowed; "
                f"must be one of {sorted(_ALLOWED_JWT_ALGORITHMS)} "
                "(`none` and HS* are rejected for security)"
            )
        return value

    def jwt_private_key_pem(self) -> bytes | None:
        if self.jwt_private_key_path is None:
            return None
        return self.jwt_private_key_path.read_bytes()
