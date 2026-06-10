"""RSA key generation + load-or-create helper.

Used by `Container` to obtain a signing key for JWT access tokens (RFC 9068)
and OIDC `id_token`s. The same private key feeds the JWT issuer; the
corresponding public key is exposed at `/jwks`.

Key size: 2048 bits — the minimum recommended by NIST SP 800-131A for
RS256. For an OAuth lab this is plenty; production should consider 3072
or EC keys.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oauth_lab.application.port.outbound.key_pair_generator import KeyPairPem


class RsaKeyPairGenerator:
    """`KeyPairGenerator` port implementation — one fresh RSA keypair per call."""

    def generate(self) -> KeyPairPem:
        private_pem = generate_rsa_keypair_pem()
        return KeyPairPem(
            private_pem=private_pem,
            public_pem=public_key_pem_from_private(private_pem),
        )


def generate_rsa_keypair_pem(key_size: int = 2048) -> bytes:
    """Generate a fresh RSA private key, return PKCS8 PEM bytes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_pem_from_private(private_pem: bytes) -> bytes:
    """Extract the SubjectPublicKeyInfo PEM from a PKCS8 RSA private key."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_or_create_keypair(path: Path, key_size: int = 2048) -> bytes:
    """Read a PEM key from disk, or generate + persist if it doesn't exist.

    A freshly generated key is written owner-read/write only (0o600): it is
    an unencrypted PKCS8 private key, so it must never be group/world-readable.
    """
    if path.exists():
        return path.read_bytes()
    pem = generate_rsa_keypair_pem(key_size)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with 0o600 atomically rather than write-then-chmod, so the key is
    # never briefly readable by other users between creation and the chmod.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    return pem
