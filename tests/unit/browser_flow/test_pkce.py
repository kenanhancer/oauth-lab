"""PKCE — RFC 7636 challenge value object + S256 verifier.

Test vectors come from RFC 7636 Appendix B:
    code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

Location: `tests/unit/browser_flow/` — folder name carries the scenario.
"""

from __future__ import annotations

import pytest

from oauth_lab.domain.model.pkce import PKCEChallenge, is_valid_code_verifier
from oauth_lab.domain.service.pkce_verifier import PKCEVerifier

RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class TestPKCEChallenge:
    def test_rfc_test_vector_accepted(self) -> None:
        c = PKCEChallenge(value=RFC_CHALLENGE)
        assert c.value == RFC_CHALLENGE
        assert c.method == "S256"

    def test_plain_method_rejected(self) -> None:
        # OAuth 2.1 § 4.8 + RFC 9700 § 4.8 forbid `plain`.
        with pytest.raises(ValueError, match="S256"):
            PKCEChallenge(value=RFC_CHALLENGE, method="plain")

    def test_unknown_method_rejected(self) -> None:
        with pytest.raises(ValueError, match="S256"):
            PKCEChallenge(value=RFC_CHALLENGE, method="S512")

    def test_too_short_rejected(self) -> None:
        with pytest.raises(ValueError, match="length"):
            PKCEChallenge(value="a" * 42)

    def test_too_long_rejected(self) -> None:
        with pytest.raises(ValueError, match="length"):
            PKCEChallenge(value="a" * 129)

    def test_invalid_charset_rejected(self) -> None:
        # `+` is not in the RFC 7636 unreserved set
        with pytest.raises(ValueError, match="unreserved"):
            PKCEChallenge(value="a" * 42 + "+")

    def test_min_length_43_accepted(self) -> None:
        PKCEChallenge(value="a" * 43)

    def test_max_length_128_accepted(self) -> None:
        PKCEChallenge(value="a" * 128)


class TestPKCEVerifier:
    def setup_method(self) -> None:
        self.verifier = PKCEVerifier()
        self.challenge = PKCEChallenge(value=RFC_CHALLENGE)

    def test_rfc_test_vector_verifies(self) -> None:
        assert self.verifier.verify(RFC_VERIFIER, self.challenge) is True

    def test_wrong_verifier_fails(self) -> None:
        wrong = "x" * 43
        assert self.verifier.verify(wrong, self.challenge) is False

    def test_malformed_verifier_returns_false_not_raises(self) -> None:
        # Out-of-charset: must be `False`, never an exception (timing safety).
        assert self.verifier.verify("a" * 42 + "+", self.challenge) is False

    def test_too_short_verifier_returns_false(self) -> None:
        assert self.verifier.verify("a" * 10, self.challenge) is False

    def test_too_long_verifier_returns_false(self) -> None:
        assert self.verifier.verify("a" * 129, self.challenge) is False

    def test_empty_verifier_returns_false(self) -> None:
        assert self.verifier.verify("", self.challenge) is False


class TestIsValidCodeVerifier:
    def test_rfc_verifier_is_valid(self) -> None:
        assert is_valid_code_verifier(RFC_VERIFIER) is True

    def test_short_is_invalid(self) -> None:
        assert is_valid_code_verifier("a" * 42) is False

    def test_long_is_invalid(self) -> None:
        assert is_valid_code_verifier("a" * 129) is False

    def test_bad_charset_is_invalid(self) -> None:
        assert is_valid_code_verifier("a" * 42 + "+") is False
