from __future__ import annotations

import json
from typing import Any

from ..models import JsonlAuditObserverSpec, SideEffectKind
from .base import SideEffectEvent


class JsonlAuditObserver:
    def __init__(self, name: str, spec: JsonlAuditObserverSpec) -> None:
        self.name = name
        self.spec = spec
        self.observes = set(spec.observes)
        self._offset = 0

    async def begin(self) -> None:
        path = self.spec.path
        path.parent.mkdir(parents=True, exist_ok=True)
        if self.spec.truncate_on_begin:
            path.write_text("", encoding="utf-8")
            self._offset = 0
            return
        self._offset = path.stat().st_size if path.exists() else 0

    async def collect(self) -> list[SideEffectEvent]:
        path = self.spec.path
        if not path.exists():
            raise FileNotFoundError(f"audit file disappeared during observation: {path}")

        events: list[SideEffectEvent] = []
        with path.open("r", encoding="utf-8") as handle:
            handle.seek(self._offset)
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    payload: Any = json.loads(line)
                    if not isinstance(payload, dict):
                        raise ValueError("event must be a JSON object")
                    raw_kind = payload.pop("kind")
                    events.append(
                        SideEffectEvent(
                            observer=self.name,
                            kind=SideEffectKind(str(raw_kind)),
                            details=payload,
                        )
                    )
                except (KeyError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"invalid audit event at line {line_number}: {exc}") from exc
        return events
