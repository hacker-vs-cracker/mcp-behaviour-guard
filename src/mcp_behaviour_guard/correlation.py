from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .observers.base import ObservationScope, SideEffectEvent

CORRELATION_META_KEY = "io.github.hacker-vs-cracker.mcp-behaviour-guard/correlation"
CORRELATION_VERSION = 1
CORRELATION_MODE_MCP_META = "mcp_meta"


def build_correlation_meta(run_id: str, operation_id: str) -> dict[str, Any]:
    return {
        CORRELATION_META_KEY: {
            "version": CORRELATION_VERSION,
            "run_id": run_id,
            "guard_operation_id": operation_id,
        }
    }


def observer_correlation_mode(observer: object) -> str:
    direct = getattr(observer, "correlation", None)
    if isinstance(direct, str):
        return direct

    spec = getattr(observer, "spec", None)
    configured = getattr(spec, "correlation", "none")
    return configured if isinstance(configured, str) else "none"


def correlation_enabled(observers: Iterable[object]) -> bool:
    return any(
        observer_correlation_mode(observer) == CORRELATION_MODE_MCP_META for observer in observers
    )


def correlation_redaction_values(operation_id: str) -> set[str]:
    return {
        CORRELATION_META_KEY,
        "guard_operation_id",
        operation_id,
    }


def correlated_observer_names(observers: Iterable[object]) -> set[str]:
    return {
        str(getattr(observer, "name", ""))
        for observer in observers
        if observer_correlation_mode(observer) == CORRELATION_MODE_MCP_META
    }


def strip_internal_correlation(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            if key == CORRELATION_META_KEY:
                continue
            cleaned_item = strip_internal_correlation(item)
            if (
                key == "_meta"
                and isinstance(item, dict)
                and CORRELATION_META_KEY in item
                and cleaned_item == {}
            ):
                continue
            cleaned[key] = cleaned_item
        return cleaned
    if isinstance(value, list):
        return [strip_internal_correlation(item) for item in value]
    if isinstance(value, tuple):
        return [strip_internal_correlation(item) for item in value]
    return value


def attribute_correlated_events(
    events: list[SideEffectEvent],
    observers: Iterable[object],
    scope: ObservationScope,
) -> tuple[list[SideEffectEvent], dict[str, str]]:
    modes = {
        str(getattr(observer, "name", "")): observer_correlation_mode(observer)
        for observer in observers
    }
    attributed: list[SideEffectEvent] = []
    errors: dict[str, str] = {}

    for event in events:
        if modes.get(event.observer) != CORRELATION_MODE_MCP_META:
            attributed.append(event)
            continue

        correlation = _correlation_envelope(event.details)
        if correlation is None:
            errors[event.observer] = "correlation: required MCP metadata is missing or malformed"
            continue

        run_id, operation_id = correlation
        if run_id != scope.run_id or operation_id not in scope.operation_ids:
            continue

        attributed.append(_without_guard_correlation(event))

    return attributed, errors


def _correlation_envelope(details: dict[str, Any]) -> tuple[str, str] | None:
    meta = details.get("_meta")
    if not isinstance(meta, dict):
        return None

    envelope = meta.get(CORRELATION_META_KEY)
    if not isinstance(envelope, dict):
        return None

    version = envelope.get("version")
    run_id = envelope.get("run_id")
    operation_id = envelope.get("guard_operation_id")

    if type(version) is not int or version != CORRELATION_VERSION:
        return None
    if not isinstance(run_id, str) or not run_id:
        return None
    if not isinstance(operation_id, str) or not operation_id:
        return None

    return run_id, operation_id


def _without_guard_correlation(event: SideEffectEvent) -> SideEffectEvent:
    details = dict(event.details)
    meta = details.get("_meta")

    if isinstance(meta, dict):
        cleaned_meta = dict(meta)
        cleaned_meta.pop(CORRELATION_META_KEY, None)
        if cleaned_meta:
            details["_meta"] = cleaned_meta
        else:
            details.pop("_meta", None)

    return SideEffectEvent(
        observer=event.observer,
        kind=event.kind,
        details=details,
    )
