"""Demo-seed production guard.

`_demo_seed_refusal` decides whether the `seed` CLI may run. It is pure (no
I/O) so it can be tested directly, without spinning up the container. Demo
seeding inserts publicly-known credentials, so it must refuse to run against a
non-localhost issuer unless explicitly forced.
"""

from __future__ import annotations

import pytest

from oauth_lab.adapter.inbound.cli.seed_command import _demo_seed_refusal
from oauth_lab.config import Settings


def test_allowed_on_localhost_issuer() -> None:
    settings = Settings(issuer="http://localhost:8000", database_url="memory://")
    assert _demo_seed_refusal(settings) is None


def test_allowed_on_loopback_ip_issuer() -> None:
    settings = Settings(issuer="http://127.0.0.1:8000", database_url="memory://")
    assert _demo_seed_refusal(settings) is None


def test_refused_off_localhost_without_flag() -> None:
    settings = Settings(issuer="https://auth.example.com", database_url="memory://")
    refusal = _demo_seed_refusal(settings)
    assert refusal is not None
    # The message must name the override and call out the demo credentials.
    assert "OAUTH_LAB_ALLOW_DEMO_SEED" in refusal
    assert "demo-client/demo-secret" in refusal


def test_allowed_off_localhost_with_explicit_flag() -> None:
    settings = Settings(
        issuer="https://auth.example.com",
        database_url="memory://",
        allow_demo_seed=True,
    )
    assert _demo_seed_refusal(settings) is None


@pytest.mark.parametrize(
    "issuer",
    [
        "https://auth.example.com",
        "http://example.com",
        "https://oauth.internal.corp",
    ],
)
def test_refuses_non_localhost_variants(issuer: str) -> None:
    settings = Settings(issuer=issuer, database_url="memory://")
    assert _demo_seed_refusal(settings) is not None
