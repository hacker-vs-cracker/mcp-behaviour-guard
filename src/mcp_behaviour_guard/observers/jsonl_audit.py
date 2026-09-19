from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from ..models import JsonlAuditObserverSpec, SideEffectKind
from .base import ObserverCollectionError, SideEffectEvent

_POLL_INTERVAL_SECONDS = 0.01


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
        if self.spec.settle_timeout_seconds == 0:
            return self._collect_once()
        return await self._collect_settled()

    def _collect_once(self) -> list[SideEffectEvent]:
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

    async def _collect_settled(self) -> list[SideEffectEvent]:
        path = self.spec.path
        loop = asyncio.get_running_loop()
        started = loop.time()
        deadline = started + self.spec.settle_timeout_seconds
        quiet_since = started

        window_start = self._offset
        cursor = self._offset
        last_size = self._offset
        source_identity = self._source_identity
        source_seen = source_identity is not None
        consumed_prefix = bytearray()
        events: list[SideEffectEvent] = []

        while True:
            now = loop.time()
            try:
                stat = path.stat()
            except FileNotFoundError as exc:
                if source_seen:
                    raise ObserverCollectionError(
                        f"audit file disappeared during observation: {path}",
                        events,
                    ) from exc
                if now >= deadline:
                    raise FileNotFoundError(
                        f"audit file did not appear during settling: {path}"
                    ) from exc
                await asyncio.sleep(min(_POLL_INTERVAL_SECONDS, deadline - now))
                continue
            except OSError as exc:
                if source_seen:
                    raise ObserverCollectionError(
                        f"audit file became unreadable during observation: {path}: {exc}",
                        events,
                    ) from exc
                raise

            current_identity = (stat.st_dev, stat.st_ino)
            if source_identity is None:
                source_identity = current_identity
                source_seen = True
                quiet_since = loop.time()
            elif current_identity != source_identity:
                raise ObserverCollectionError(
                    f"audit file was replaced during observation: {path}",
                    events,
                )

            if stat.st_size < cursor:
                raise ObserverCollectionError(
                    f"audit file shrank during observation: {path}",
                    events,
                )

            size_changed = stat.st_size != last_size
            if size_changed:
                quiet_since = loop.time()
                last_size = stat.st_size

            try:
                cursor = self._read_complete_records(
                    cursor,
                    events,
                    source_identity,
                    window_start=window_start,
                    consumed_prefix=consumed_prefix,
                    verify_prefix=size_changed,
                )
            except FileNotFoundError as exc:
                raise ObserverCollectionError(
                    f"audit file disappeared during observation: {path}",
                    events,
                ) from exc
            except OSError as exc:
                raise ObserverCollectionError(
                    f"audit file became unreadable during observation: {path}: {exc}",
                    events,
                ) from exc

            now = loop.time()
            deadline_reached = now >= deadline
            quiet_reached = now - quiet_since >= self.spec.quiet_period_seconds
            if deadline_reached or quiet_reached:
                try:
                    final_stat = path.stat()
                except FileNotFoundError as exc:
                    raise ObserverCollectionError(
                        f"audit file disappeared during observation: {path}",
                        events,
                    ) from exc
                except OSError as exc:
                    raise ObserverCollectionError(
                        f"audit file became unreadable during observation: {path}: {exc}",
                        events,
                    ) from exc

                final_identity = (final_stat.st_dev, final_stat.st_ino)
                if final_identity != source_identity:
                    raise ObserverCollectionError(
                        f"audit file was replaced during observation: {path}",
                        events,
                    )
                if final_stat.st_size < cursor:
                    raise ObserverCollectionError(
                        f"audit file shrank during observation: {path}",
                        events,
                    )
                if final_stat.st_size > cursor:
                    raise ObserverCollectionError(
                        f"incomplete audit event remained at the settling boundary: {path}",
                        events,
                    )
                try:
                    self._verify_consumed_prefix(
                        window_start,
                        consumed_prefix,
                        source_identity,
                        events,
                    )
                except FileNotFoundError as exc:
                    raise ObserverCollectionError(
                        f"audit file disappeared during observation: {path}",
                        events,
                    ) from exc
                except OSError as exc:
                    raise ObserverCollectionError(
                        f"audit file became unreadable during observation: {path}: {exc}",
                        events,
                    ) from exc
                return events

            remaining_deadline = deadline - now
            remaining_quiet = self.spec.quiet_period_seconds - (now - quiet_since)
            await asyncio.sleep(
                max(
                    0.0,
                    min(_POLL_INTERVAL_SECONDS, remaining_deadline, remaining_quiet),
                )
            )

    def _read_complete_records(
        self,
        cursor: int,
        events: list[SideEffectEvent],
        source_identity: tuple[int, int] | None,
        *,
        window_start: int | None = None,
        consumed_prefix: bytearray | None = None,
        verify_prefix: bool = True,
    ) -> int:
        path = self.spec.path
        with path.open("rb") as handle:
            info = os.fstat(handle.fileno())
            current_identity = (info.st_dev, info.st_ino)
            if source_identity is not None and current_identity != source_identity:
                raise ObserverCollectionError(
                    f"audit file was replaced during observation: {path}",
                    events,
                )
            if consumed_prefix is not None and verify_prefix:
                if window_start is None:
                    raise RuntimeError("window_start is required with consumed_prefix")
                handle.seek(window_start)
                current_prefix = handle.read(len(consumed_prefix))
                if current_prefix != consumed_prefix:
                    raise ObserverCollectionError(
                        f"audit file changed before its append position: {path}",
                        events,
                    )

            handle.seek(cursor)
            payload = handle.read()

        complete_end = payload.rfind(b"\n") + 1
        if complete_end == 0:
            return cursor

        complete = payload[:complete_end]
        position = cursor
        for raw_line in complete.splitlines(keepends=True):
            line_position = position
            position += len(raw_line)
            if not raw_line.strip():
                continue

            try:
                line = raw_line.decode("utf-8")
                raw_payload: Any = json.loads(line)
                if not isinstance(raw_payload, dict):
                    raise ValueError("event must be a JSON object")
                raw_kind = raw_payload.pop("kind")
                events.append(
                    SideEffectEvent(
                        observer=self.name,
                        kind=SideEffectKind(str(raw_kind)),
                        details=raw_payload,
                    )
                )
            except (KeyError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                raise ObserverCollectionError(
                    f"invalid audit event at byte {line_position}: {exc}",
                    events,
                ) from exc

        if consumed_prefix is not None:
            consumed_prefix.extend(complete)

        return cursor + complete_end

    def _verify_consumed_prefix(
        self,
        window_start: int,
        consumed_prefix: bytearray,
        source_identity: tuple[int, int] | None,
        events: list[SideEffectEvent],
    ) -> None:
        if not consumed_prefix:
            return

        path = self.spec.path
        with path.open("rb") as handle:
            info = os.fstat(handle.fileno())
            current_identity = (info.st_dev, info.st_ino)
            if source_identity is not None and current_identity != source_identity:
                raise ObserverCollectionError(
                    f"audit file was replaced during observation: {path}",
                    events,
                )
            handle.seek(window_start)
            current_prefix = handle.read(len(consumed_prefix))

        if current_prefix != consumed_prefix:
            raise ObserverCollectionError(
                f"audit file changed before its append position: {path}",
                events,
            )
