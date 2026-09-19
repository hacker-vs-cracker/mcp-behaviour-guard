from __future__ import annotations

import json
from typing import Any

from ..models import JsonlAuditObserverSpec, SideEffectKind
from .base import ObserverCollectionError, SideEffectEvent


class JsonlAuditObserver:
    def __init__(self, name: str, spec: JsonlAuditObserverSpec) -> None:
        self.name = name
        self.spec = spec
        self.observes = set(spec.observes)
        self.complete_observes = set(self.observes)
        self._offset = 0
        self._source_identity: tuple[int, int] | None = None

    @property
    def ownership_keys(self) -> tuple[str, ...]:
        path = self.spec.path.expanduser().resolve(strict=False)
        return (f"jsonl-audit:{path}",)

    async def begin(self) -> None:
        path = self.spec.path
        path.parent.mkdir(parents=True, exist_ok=True)
        if self.spec.truncate_on_begin:
            path.write_text("", encoding="utf-8")

        if path.exists():
            stat = path.stat()
            self._offset = stat.st_size
            self._source_identity = (stat.st_dev, stat.st_ino)
        else:
            self._offset = 0
            self._source_identity = None

    async def collect(self) -> list[SideEffectEvent]:
        path = self.spec.path
        if not path.exists():
            raise FileNotFoundError(f"audit file disappeared during observation: {path}")

        stat = path.stat()
        current_identity = (stat.st_dev, stat.st_ino)
        if self._source_identity is not None and current_identity != self._source_identity:
            raise ObserverCollectionError(f"audit file was replaced during observation: {path}")
        if stat.st_size < self._offset:
            raise ObserverCollectionError(f"audit file shrank during observation: {path}")

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
                    raise ObserverCollectionError(
                        f"invalid audit event at line {line_number}: {exc}",
                        events,
                    ) from exc
        return events
