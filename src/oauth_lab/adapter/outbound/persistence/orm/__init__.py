"""ORM package — re-exports `Base` and every Row mapping.

The export list MUST stay complete: autogenerate and `create_all` only see
tables whose mapping class has been imported and registered on
`Base.metadata`. A missing entry here is the classic Alembic footgun — the
table silently disappears from generated migrations.
"""

from oauth_lab.adapter.outbound.persistence.orm.models import (
    AuthorizationCodeRow,
    Base,
    ClientRow,
    DeviceCodeRow,
    RefreshTokenRow,
    TrustedAssertionIssuerRow,
    UserRow,
)

__all__ = [
    "AuthorizationCodeRow",
    "Base",
    "ClientRow",
    "DeviceCodeRow",
    "RefreshTokenRow",
    "TrustedAssertionIssuerRow",
    "UserRow",
]
