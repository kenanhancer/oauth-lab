"""SQLAlchemy ORM models shared by the SQLite and Postgres adapters.

The ORM model is an *adapter* between rows and the domain entities.
The domain never sees these classes — translation happens in the
repository adapter.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ClientRow(Base):
    __tablename__ = "clients"

    client_id: Mapped[str] = mapped_column(primary_key=True, index=True)
    secret_hash: Mapped[bytes | None] = mapped_column(nullable=True)
    token_endpoint_auth_method: Mapped[str]
    allowed_grant_types: Mapped[str]                  # space-separated
    allowed_scopes: Mapped[str]                       # space-separated
    redirect_uris: Mapped[str]                        # space-separated, may be empty
    default_audience: Mapped[str | None] = mapped_column(nullable=True)


class AuthorizationCodeRow(Base):
    __tablename__ = "authorization_codes"

    value: Mapped[str] = mapped_column(primary_key=True)
    client_id: Mapped[str] = mapped_column(index=True)
    user_sub: Mapped[str]
    redirect_uri: Mapped[str]
    scope: Mapped[str]                                # space-separated
    pkce_challenge_value: Mapped[str]
    pkce_challenge_method: Mapped[str]                # always "S256"
    issued_at: Mapped[datetime]
    expires_at: Mapped[datetime] = mapped_column(index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)
    nonce: Mapped[str | None] = mapped_column(nullable=True)             # OIDC


class UserRow(Base):
    __tablename__ = "users"

    sub: Mapped[str] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True, index=True)
    password_hash: Mapped[bytes]
    email: Mapped[str | None] = mapped_column(nullable=True)


class RefreshTokenRow(Base):
    __tablename__ = "refresh_tokens"

    value: Mapped[str] = mapped_column(primary_key=True)
    family_id: Mapped[str] = mapped_column(index=True)
    client_id: Mapped[str] = mapped_column(index=True)
    user_sub: Mapped[str]
    scope: Mapped[str]
    issued_at: Mapped[datetime]
    expires_at: Mapped[datetime] = mapped_column(index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)


class DeviceCodeRow(Base):
    __tablename__ = "device_codes"

    device_code: Mapped[str] = mapped_column(primary_key=True)
    user_code: Mapped[str] = mapped_column(unique=True, index=True)
    client_id: Mapped[str] = mapped_column(index=True)
    scope: Mapped[str]                                # space-separated
    issued_at: Mapped[datetime]
    expires_at: Mapped[datetime] = mapped_column(index=True)
    interval_seconds: Mapped[int]
    last_polled_at: Mapped[datetime | None] = mapped_column(nullable=True)
    user_sub: Mapped[str | None] = mapped_column(nullable=True)                # None until approved
    denied: Mapped[bool] = mapped_column(default=False)
    redeemed_at: Mapped[datetime | None] = mapped_column(nullable=True)        # None until redeemed


class TrustedAssertionIssuerRow(Base):
    __tablename__ = "trusted_assertion_issuers"

    issuer: Mapped[str] = mapped_column(primary_key=True)
    public_key_pem: Mapped[bytes]
    algorithm: Mapped[str]                            # e.g. "RS256"
    allowed_audiences: Mapped[str]                    # space-separated
