from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..models import HttpAuditObserverSpec, SideEffectKind
from .base import ObserverCollectionError, SideEffectEvent

_POLL_INTERVAL_SECONDS = 0.05


def _same_json_value(left: Any, right: Any) -> bool:
    if isinstance(left, dict) or isinstance(right, dict):
        if not isinstance(left, dict) or not isinstance(right, dict):
            return False
        if left.keys() != right.keys():
            return False
        return all(_same_json_value(left[key], right[key]) for key in left)

    if isinstance(left, list) or isinstance(right, list):
        if not isinstance(left, list) or not isinstance(right, list):
            return False
        if len(left) != len(right):
            return False
        return all(_same_json_value(a, b) for a, b in zip(left, right, strict=True))

    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right

    left_number = isinstance(left, (int, float)) and not isinstance(left, bool)
    right_number = isinstance(right, (int, float)) and not isinstance(right, bool)
    if left_number or right_number:
        return left_number and right_number and left == right

    if left is None or right is None:
        return left is None and right is None

    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right

    return type(left) is type(right) and left == right


class HttpAuditObserver:
    def __init__(self, name: str, spec: HttpAuditObserverSpec) -> None:
        self.name = name
        self.spec = spec
        self.observes = set(spec.observes)
        self.complete_observes = set(self.observes)
        self._baseline_raw_events: list[Any] | None = None

    def _correlation_mode(self) -> str:
        value = getattr(self.spec, "correlation", "none")
        return value if isinstance(value, str) else "none"

    @staticmethod
    def _resource_key(url: str) -> str:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        port = parsed.port
        if port is None:
            port = {"http": 80, "https": 443}.get(scheme)
        material = (
            scheme,
            (parsed.hostname or "").lower(),
            port,
            parsed.path or "/",
            parsed.query,
        )
        return f"http-audit-resource:{material!r}"

    @property
    def ownership_keys(self) -> tuple[str, ...]:
        event_key = self._resource_key(self.spec.events_url)
        if self._correlation_mode() == "mcp_meta":
            return (event_key,)

        reset_url = self.spec.reset_url
        if reset_url is None:
            return (event_key,)
        return (
            event_key,
            self._resource_key(reset_url),
        )

    async def begin(self) -> None:
        self._baseline_raw_events = None
        async with httpx.AsyncClient(timeout=self.spec.timeout_seconds) as client:
            if self._correlation_mode() == "mcp_meta":
                self._baseline_raw_events = await self._fetch_raw_events(client)
                return

            reset_url = self.spec.reset_url
            if reset_url is None:
                raise ValueError(f"observer {self.name} requires a reset URL")
            response = await client.post(reset_url)
            response.raise_for_status()

    async def collect(self) -> list[SideEffectEvent]:
        baseline = self._baseline_raw_events
        if self._correlation_mode() == "mcp_meta" and baseline is None:
            raise ObserverCollectionError(
                f"observer {self.name} correlated collection requires a successful begin baseline"
            )

        async with httpx.AsyncClient(timeout=self.spec.timeout_seconds) as client:
            if self.spec.settle_timeout_seconds == 0:
                raw_events = await self._fetch_raw_events(client)
                if self._correlation_mode() == "mcp_meta":
                    assert baseline is not None
                    new_raw = self._append_suffix(raw_events, baseline, [])
                    return self._parse_events(new_raw, [])
                return self._parse_events(raw_events, [])

            return await self._collect_settled(
                client,
                initial_raw=baseline if self._correlation_mode() == "mcp_meta" else None,
            )

    async def _fetch_raw_events(self, client: httpx.AsyncClient) -> list[Any]:
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
        return raw_events

    def _append_suffix(
        self,
        raw_events: list[Any],
        previous_raw: list[Any],
        events: list[SideEffectEvent],
    ) -> list[Any]:
        if len(raw_events) < len(previous_raw):
            raise ObserverCollectionError(
                f"observer {self.name} event stream shrank during settling",
                events,
            )

        prior_prefix = raw_events[: len(previous_raw)]
        if not all(
            _same_json_value(current, previous)
            for current, previous in zip(prior_prefix, previous_raw, strict=True)
        ):
            raise ObserverCollectionError(
                f"observer {self.name} event stream changed before its append position",
                events,
            )

        return raw_events[len(previous_raw) :]

    def _parse_events(
        self,
        raw_events: list[Any],
        events: list[SideEffectEvent],
    ) -> list[SideEffectEvent]:
        for raw in raw_events:
            if not isinstance(raw, dict) or "kind" not in raw:
                raise ObserverCollectionError(
                    f"observer {self.name} returned an event without a kind",
                    events,
                )
            try:
                kind = SideEffectKind(raw["kind"])
            except ValueError as exc:
                raise ObserverCollectionError(
                    f"observer {self.name} returned an unknown event kind",
                    events,
                ) from exc
            events.append(SideEffectEvent(observer=self.name, kind=kind, details=raw))
        return events

    async def _collect_settled(
        self,
        client: httpx.AsyncClient,
        *,
        initial_raw: list[Any] | None = None,
    ) -> list[SideEffectEvent]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        deadline = started + self.spec.settle_timeout_seconds
        quiet_since = started

        previous_raw: list[Any] = list(initial_raw or [])
        events: list[SideEffectEvent] = []
        completed_snapshot = False

        while True:
            now = loop.time()
            remaining = deadline - now
            if remaining <= 0:
                return events

            try:
                raw_events = await asyncio.wait_for(
                    self._fetch_raw_events(client),
                    timeout=remaining,
                )
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                if completed_snapshot:
                    return events
                raise
            except Exception as exc:
                if completed_snapshot:
                    raise ObserverCollectionError(
                        f"observer {self.name} collection failed during settling: "
                        f"{type(exc).__name__}: {exc}",
                        events,
                    ) from exc
                raise

            first_snapshot = not completed_snapshot
            completed_snapshot = True
            new_raw = self._append_suffix(raw_events, previous_raw, events)
            if first_snapshot or new_raw:
                quiet_since = loop.time()
            if new_raw:
                self._parse_events(new_raw, events)

            previous_raw = raw_events
            now = loop.time()
            if now >= deadline:
                return events
            if now - quiet_since >= self.spec.quiet_period_seconds:
                return events

            await asyncio.sleep(
                max(
                    0.0,
                    min(
                        _POLL_INTERVAL_SECONDS,
                        deadline - now,
                        self.spec.quiet_period_seconds - (now - quiet_since),
                    ),
                )
            )
