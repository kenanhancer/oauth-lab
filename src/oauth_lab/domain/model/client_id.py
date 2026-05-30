"""ClientId value object — RFC 6749 §2.2."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ClientId:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("client_id must not be empty")
        if len(self.value) > 255:
            raise ValueError("client_id must be at most 255 characters")

    def __str__(self) -> str:
        return self.value
