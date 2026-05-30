"""Scope value object — RFC 6749 §3.3.

A single `Scope` is one space-delimited token from the request. `ScopeSet`
is the collection a client requested or was granted.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

# RFC 6749 §3.3 ABNF: 1*( %x21 / %x23-5B / %x5D-7E )
# Printable ASCII excluding space (0x20), '"' (0x22), and '\' (0x5C).
_SCOPE_TOKEN_RE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")


@dataclass(frozen=True, slots=True)
class Scope:
    value: str

    def __post_init__(self) -> None:
        if not _SCOPE_TOKEN_RE.match(self.value):
            raise ValueError(f"invalid scope token (RFC 6749 §3.3): {self.value!r}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ScopeSet:
    """An immutable set of scopes (backed by a frozenset; unordered)."""

    scopes: frozenset[Scope]

    @classmethod
    def parse(cls, raw: str | None) -> ScopeSet:
        if not raw:
            return cls(frozenset())
        return cls(frozenset(Scope(tok) for tok in raw.split(" ") if tok))

    def to_str(self) -> str:
        return " ".join(sorted(s.value for s in self.scopes))

    def intersect(self, other: ScopeSet) -> ScopeSet:
        return ScopeSet(self.scopes & other.scopes)

    def is_subset_of(self, other: ScopeSet) -> bool:
        return self.scopes <= other.scopes

    def is_empty(self) -> bool:
        return not self.scopes

    def __iter__(self) -> Iterator[Scope]:
        return iter(self.scopes)

    def __len__(self) -> int:
        return len(self.scopes)
