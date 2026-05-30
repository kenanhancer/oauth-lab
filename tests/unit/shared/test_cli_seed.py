"""`SeedDemoDataUseCase` — seeds demo clients + users; idempotent.

Tests the use case directly through the container's inbound port —
NOT through the CLI adapter (CLI is only a thin argparse wrapper).
"""

from __future__ import annotations

from argon2 import PasswordHasher

from oauth_lab.container import Container
from oauth_lab.domain.model.client_id import ClientId


class TestSeedDemoData:
    async def test_inserts_demo_client_and_user(self, container: Container) -> None:
        result = await container.seed_demo_data.execute()
        assert len(result.clients) >= 1
        assert len(result.users) >= 1

        demo = await container.clients.find_by_id(ClientId("demo-client"))
        assert demo is not None
        assert demo.is_confidential()
        # The hash should be a valid Argon2id encoding the known secret
        assert demo.secret_hash is not None
        PasswordHasher().verify(demo.secret_hash.decode("utf-8"), "demo-secret")

        alice = await container.users.find_by_username("alice")
        assert alice is not None
        PasswordHasher().verify(alice.password_hash.decode("utf-8"), "alice-password")

    async def test_is_idempotent(self, container: Container) -> None:
        first = await container.seed_demo_data.execute()
        second = await container.seed_demo_data.execute()
        assert {c.id for c in first.clients} == {c.id for c in second.clients}
        assert {u.sub for u in first.users} == {u.sub for u in second.users}
        # Still exactly one demo-client and one alice in storage
        demo = await container.clients.find_by_id(ClientId("demo-client"))
        assert demo is not None
        alice = await container.users.find_by_username("alice")
        assert alice is not None

    async def test_result_carries_plaintext_credentials_for_operator(
        self, container: Container
    ) -> None:
        result = await container.seed_demo_data.execute()
        demo_client = next(c for c in result.clients if c.id == "demo-client")
        assert demo_client.secret == "demo-secret"
        alice = next(u for u in result.users if u.username == "alice")
        assert alice.password == "alice-password"
