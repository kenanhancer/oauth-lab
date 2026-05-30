"""ScopeSet — parsing, intersection, ABNF validation."""

from __future__ import annotations

import pytest

from oauth_lab.domain.model.scope import Scope, ScopeSet


class TestScope:
    def test_valid_token_parses(self) -> None:
        assert Scope("read").value == "read"

    def test_empty_token_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid scope"):
            Scope("")

    def test_space_in_token_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid scope"):
            Scope("read write")

    def test_quote_in_token_rejected(self) -> None:
        # 0x22 (") is excluded per RFC 6749 §3.3
        with pytest.raises(ValueError, match="invalid scope"):
            Scope('say"hi')

    def test_backslash_in_token_rejected(self) -> None:
        # 0x5C (\) is excluded per RFC 6749 §3.3
        with pytest.raises(ValueError, match="invalid scope"):
            Scope("a\\b")


class TestScopeSet:
    def test_parse_empty(self) -> None:
        assert ScopeSet.parse(None).is_empty()
        assert ScopeSet.parse("").is_empty()
        assert ScopeSet.parse("   ").is_empty()

    def test_parse_space_delimited(self) -> None:
        s = ScopeSet.parse("read write admin")
        assert s.scopes == {Scope("read"), Scope("write"), Scope("admin")}

    def test_to_str_is_sorted(self) -> None:
        s = ScopeSet.parse("write read admin")
        assert s.to_str() == "admin read write"

    def test_intersect(self) -> None:
        a = ScopeSet.parse("read write admin")
        b = ScopeSet.parse("read delete")
        assert a.intersect(b).to_str() == "read"

    def test_is_subset_of(self) -> None:
        requested = ScopeSet.parse("read")
        allowed = ScopeSet.parse("read write")
        assert requested.is_subset_of(allowed)
        assert not allowed.is_subset_of(requested)
