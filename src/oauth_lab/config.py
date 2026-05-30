"""Application settings — pydantic-settings, 12-factor, env-driven."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OAUTH_LAB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    issuer: str = "http://localhost:8000"
    database_url: str = "memory://"

    access_token_ttl_seconds: int = 3600
    refresh_token_ttl_seconds: int = 30 * 24 * 3600           # 30 days (RFC 9700 §2.2.2 rotation)
    authorization_code_ttl_seconds: int = 60                  # RFC 9700 §2.1.1 recommends ≤60s
    device_code_ttl_seconds: int = 1800                       # 30 min (RFC 8628 §3.2 example)
    device_code_polling_interval_seconds: int = 5             # RFC 8628 §3.2 default
    session_ttl_seconds: int = 3600                           # browser session cookie max age
    session_secret_key: str = "dev-only-change-me"            # itsdangerous signing key
    token_format: str = "opaque"                          # "opaque" | "jwt"

    jwt_private_key_path: Path | None = None
    jwt_key_id: str | None = None
    jwt_algorithm: str = "RS256"

    log_level: str = "INFO"

    def jwt_private_key_pem(self) -> bytes | None:
        if self.jwt_private_key_path is None:
            return None
        return self.jwt_private_key_path.read_bytes()
