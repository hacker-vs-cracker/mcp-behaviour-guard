from __future__ import annotations

from ..models import (
    FilesystemObserverSpec,
    HttpAuditObserverSpec,
    JsonlAuditObserverSpec,
    ObserverSpec,
)
from .base import Observer, SideEffectEvent
from .filesystem import FilesystemObserver
from .http_audit import HttpAuditObserver
from .jsonl_audit import JsonlAuditObserver


def build_observer(name: str, spec: ObserverSpec) -> Observer:
    if isinstance(spec, HttpAuditObserverSpec):
        return HttpAuditObserver(name, spec)
    if isinstance(spec, FilesystemObserverSpec):
        return FilesystemObserver(name, spec)
    if isinstance(spec, JsonlAuditObserverSpec):
        return JsonlAuditObserver(name, spec)
    raise TypeError(f"unsupported observer type: {type(spec).__name__}")


__all__ = ["Observer", "SideEffectEvent", "build_observer"]
