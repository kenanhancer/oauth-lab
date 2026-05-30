"""`seed` subcommand — driving adapter for `SeedDemoDataUseCase`.

This is a pure adapter: it translates argparse arguments into a call on
the inbound port and renders the result. No business logic — that lives
in `oauth_lab.application.service.seed_demo_data_service`.
"""

from __future__ import annotations

import argparse
import asyncio

from oauth_lab.application.port.inbound.seed_demo_data_use_case import SeedDemoDataResult
from oauth_lab.config import Settings
from oauth_lab.container import build_container


async def _run() -> int:
    settings = Settings()
    container = await build_container(settings)
    result = await container.seed_demo_data.execute()
    _render(settings.database_url, result)
    return 0


def _render(database_url: str, result: SeedDemoDataResult) -> None:
    """Adapter-side presentation — prints credentials for the operator."""
    print(
        f"Seeded {len(result.clients)} client(s) and "
        f"{len(result.users)} user(s) into {database_url}:"
    )
    print()
    for c in result.clients:
        secret_display = c.secret if c.secret else "(public — no secret)"
        grants_display = ", ".join(c.grants)
        scopes_display = " ".join(c.scopes)
        print(f"  client_id={c.id!r} secret={secret_display!r}")
        print(f"    auth_method={c.auth_method}")
        print(f"    grants=[{grants_display}]")
        print(f"    scopes={scopes_display!r}")
        if c.audience:
            print(f"    audience={c.audience!r}")
    print()
    for u in result.users:
        print(f"  username={u.username!r} password={u.password!r} sub={u.sub!r}")
    print()
    for ti in result.trusted_issuers:
        aud_display = " ".join(ti.audiences)
        print(f"  trusted_issuer={ti.issuer!r} alg={ti.algorithm}")
        print(f"    audiences=[{aud_display}]")
        print("    private_key_pem (lab only — sign demo assertions with this):")
        for line in ti.private_key_pem.decode("utf-8").splitlines():
            print(f"      {line}")
    print()
    print("Try M2M flow:")
    print("  curl -sS -u 'demo-client:demo-secret' \\")
    print("    -d 'grant_type=client_credentials&scope=read' \\")
    print("    http://localhost:8000/token")


def _dispatch(_args: argparse.Namespace) -> int:
    return asyncio.run(_run())


def register(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Attach the `seed` subcommand to the top-level argparse setup."""
    parser = subparsers.add_parser(
        "seed", help="Seed demo clients into the configured database"
    )
    parser.set_defaults(func=_dispatch)
