"""GrantRegistry — dispatches `grant_type` to a concrete `GrantStrategy`.

Adding a new grant is *one* registry entry plus a strategy class.
Existing strategies are not touched. (Open/Closed in practice.)
"""

from __future__ import annotations

from collections.abc import Iterable

from oauth_lab.application.service.grant.grant_strategy import GrantStrategy
from oauth_lab.domain.model.errors import UnsupportedGrantType
from oauth_lab.domain.model.grant_type import GrantType


class GrantRegistry:
    def __init__(self, grants: Iterable[GrantStrategy]) -> None:
        self._by_type: dict[GrantType, GrantStrategy] = {g.grant_type: g for g in grants}

    def resolve(self, grant_type: str | None) -> GrantStrategy:
        if grant_type is None:
            raise UnsupportedGrantType("grant_type is required")
        try:
            gt = GrantType(grant_type)
        except ValueError as exc:
            raise UnsupportedGrantType(f"unknown grant_type: {grant_type}") from exc
        if gt not in self._by_type:
            raise UnsupportedGrantType(f"grant_type not implemented yet: {gt.value}")
        return self._by_type[gt]
