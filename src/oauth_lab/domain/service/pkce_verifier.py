"""PKCE verification service — RFC 7636 § 4.6.

The verification algorithm for `code_challenge_method=S256`:

    BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge

The base64url encoding has *no* trailing `=` padding (RFC 7636 § 4.2).
The comparison uses `secrets.compare_digest` to avoid timing oracles.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from oauth_lab.domain.model.pkce import PKCEChallenge, is_valid_code_verifier


class PKCEVerifier:
    def verify(self, code_verifier: str, challenge: PKCEChallenge) -> bool:
        if not is_valid_code_verifier(code_verifier):
            return False

        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return secrets.compare_digest(computed, challenge.value)
