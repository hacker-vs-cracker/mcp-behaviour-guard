from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..models import SideEffectKind


@dataclass(slots=True)
class SideEffectEvent:
    observer: str
    kind: SideEffectKind
    details: dict[str, Any]


class Observer(Protocol):
    name: str

    async def begin(self) -> None:
        """Reset or snapshot the observer before a tool call."""

    async def collect(self) -> list[SideEffectEvent]:
        """Return side effects observed since begin()."""
