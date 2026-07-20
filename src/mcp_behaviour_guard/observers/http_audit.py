from __future__ import annotations

from typing import Any

import httpx

from ..models import HttpAuditObserverSpec, SideEffectKind
from .base import SideEffectEvent


class HttpAuditObserver:
    def __init__(self, name: str, spec: HttpAuditObserverSpec) -> None:
        self.name = name
        self.spec = spec

    async def begin(self) -> None:
        async with httpx.AsyncClient(timeout=self.spec.timeout_seconds) as client:
            response = await client.post(self.spec.reset_url)
            response.raise_for_status()

    async def collect(self) -> list[SideEffectEvent]:
        async with httpx.AsyncClient(timeout=self.spec.timeout_seconds) as client:
            response = await client.get(self.spec.events_url)
            response.raise_for_status()
            payload = response.json()

        raw_events: list[dict[str, Any]]
        if isinstance(payload, dict):
            raw_events = payload.get("events", [])
        elif isinstance(payload, list):
            raw_events = payload
        else:
            raw_events = []

        events: list[SideEffectEvent] = []
        for raw in raw_events:
            kind_value = raw.get("kind", SideEffectKind.NETWORK_REQUEST.value)
            try:
                kind = SideEffectKind(kind_value)
            except ValueError:
                continue
            events.append(SideEffectEvent(observer=self.name, kind=kind, details=raw))
        return events
