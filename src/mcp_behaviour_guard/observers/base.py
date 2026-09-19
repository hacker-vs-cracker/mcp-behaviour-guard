from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..models import SideEffectKind


@dataclass(frozen=True, slots=True)
class ObservationScope:
    run_id: str
    check_id: str
    window_id: str
    operation_ids: tuple[str, ...]


@dataclass(slots=True)
class SideEffectEvent:
    observer: str
    kind: SideEffectKind
    details: dict[str, Any]


class ObserverCollectionError(ValueError):
    def __init__(self, message: str, events: list[SideEffectEvent] | None = None) -> None:
        super().__init__(message)
        self.events = list(events or [])


class Observer(Protocol):
    name: str
    observes: set[SideEffectKind]
    complete_observes: set[SideEffectKind]

    async def begin(self) -> None:
        """Reset or snapshot the observer before a tool call."""

    async def collect(self) -> list[SideEffectEvent]:
        """Return side effects observed since begin()."""
