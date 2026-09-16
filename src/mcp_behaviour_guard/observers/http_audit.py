from __future__ import annotations

from typing import Any

import httpx

from ..models import HttpAuditObserverSpec, SideEffectKind
from .base import SideEffectEvent


class HttpAuditObserver:
    def __init__(self, name: str, spec: HttpAuditObserverSpec) -> None:
        self.name = name
        self.spec = spec
        self.observes = set(spec.observes)

    async def begin(self) -> None:
        async with httpx.AsyncClient(timeout=self.spec.timeout_seconds) as client:
            response = await client.post(self.spec.reset_url)
            response.raise_for_status()

    async def collect(self) -> list[SideEffectEvent]:
        async with httpx.AsyncClient(timeout=self.spec.timeout_seconds) as client:
            response = await client.get(self.spec.events_url)
            response.raise_for_status()
            payload = response.json()

        raw_events: Any
        if isinstance(payload, dict):
            raw_events = payload.get("events")
        elif isinstance(payload, list):
            raw_events = payload
        else:
            raise ValueError(f"observer {self.name} returned an invalid event payload")
        if not isinstance(raw_events, list):
            raise ValueError(f"observer {self.name} did not return an events list")

        events: list[SideEffectEvent] = []
        for raw in raw_events:
            if not isinstance(raw, dict) or "kind" not in raw:
                raise ValueError(f"observer {self.name} returned an event without a kind")
            try:
                kind = SideEffectKind(raw["kind"])
            except ValueError as exc:
                raise ValueError(f"observer {self.name} returned an unknown event kind") from exc
            events.append(SideEffectEvent(observer=self.name, kind=kind, details=raw))
        return events
