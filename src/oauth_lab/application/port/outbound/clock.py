"""Clock port — abstracts the system clock so domain code is testable."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...
