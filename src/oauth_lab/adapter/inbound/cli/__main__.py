"""Administrative CLI — `python -m oauth_lab.adapter.inbound.cli <command>`.

Currently exposes one subcommand:

    seed     Insert demo clients into the configured database.

Designed to grow — future commands (`register-client`, `rotate-jwks`,
`list-clients`) will sit alongside `seed` as more subparsers, each
contributing its own `register(subparsers)` function.
"""

from __future__ import annotations

import argparse

from oauth_lab.adapter.inbound.cli import seed_command


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="oauth_lab",
        description=__doc__.splitlines()[0] if __doc__ else "oauth-lab CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    seed_command.register(subparsers)

    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
