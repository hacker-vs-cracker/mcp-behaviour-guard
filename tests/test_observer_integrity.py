from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import (
    Contract,
    HttpAuditObserverSpec,
    JsonlAuditObserverSpec,
    ObservationStatus,
    SideEffectKind,
)
from mcp_behaviour_guard.observers.http_audit import HttpAuditObserver
from mcp_behaviour_guard.observers.jsonl_audit import JsonlAuditObserver
from mcp_behaviour_guard.storage import RunStore


def _guard(tmp_path: Path) -> tuple[GuardEngine, RunStore]:
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {},
        }
    )
    store = RunStore(tmp_path / "guard.db")
    guard = GuardEngine(
        contract,
        tmp_path / "contract.yaml",
        store,
        tmp_path / "reports",
        False,
    )
    guard.run_dir.mkdir(parents=True)
    guard.trace_path.parent.mkdir(parents=True)
    return guard, store


@pytest.mark.asyncio
async def test_jsonl_keeps_valid_event_when_later_record_is_malformed(
    tmp_path: Path,
) -> None:
    guard, store = _guard(tmp_path)
    path = tmp_path / "events.jsonl"
    observer = JsonlAuditObserver(
        "audit",
        JsonlAuditObserverSpec(
            type="jsonl_audit",
            path=path,
            observes=[SideEffectKind.DATABASE_WRITE],
        ),
    )
    guard.observers = [observer]

    try:
        await observer.begin()
        path.write_text(
            '{"kind":"database_write","tool":"write"}\n{bad-json\n',
            encoding="utf-8",
        )

        events, observation, details = await guard._collect_observers(
            {},
            {SideEffectKind.DATABASE_WRITE},
        )

        assert len(events) == 1
        assert events[0].kind == SideEffectKind.DATABASE_WRITE
        assert observation == ObservationStatus.PARTIAL
        assert details
    finally:
        store.close()


@pytest.mark.asyncio
async def test_jsonl_truncation_cannot_report_complete_coverage(
    tmp_path: Path,
) -> None:
    guard, store = _guard(tmp_path)
    path = tmp_path / "events.jsonl"
    path.write_text((" " * 500) + "\n", encoding="utf-8")

    observer = JsonlAuditObserver(
        "audit",
        JsonlAuditObserverSpec(
            type="jsonl_audit",
            path=path,
            truncate_on_begin=False,
            observes=[SideEffectKind.DATABASE_WRITE],
        ),
    )
    guard.observers = [observer]

    try:
        await observer.begin()

        # Replace the stream with a shorter valid stream after the saved offset.
        path.write_text(
            '{"kind":"database_write","tool":"write"}\n',
            encoding="utf-8",
        )

        events, observation, details = await guard._collect_observers(
            {},
            {SideEffectKind.DATABASE_WRITE},
        )

        assert observation != ObservationStatus.COMPLETE
        assert details
        # The event may not be trusted after continuity is lost, but the stream
        # must never be presented as complete merely because the old offset is
        # now beyond EOF.
        assert len(events) in {0, 1}
    finally:
        store.close()


@pytest.mark.asyncio
async def test_http_audit_keeps_valid_event_when_later_record_is_malformed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeClient:
        def __init__(self, **kwargs):
            del kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            del args

        async def get(self, url: str):
            del url
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "events": [
                        {"kind": "database_write", "tool": "write"},
                        {"tool": "missing-kind"},
                    ]
                },
            )

    monkeypatch.setattr(
        "mcp_behaviour_guard.observers.http_audit.httpx.AsyncClient",
        FakeClient,
    )

    guard, store = _guard(tmp_path)
    observer = HttpAuditObserver(
        "audit",
        HttpAuditObserverSpec(
            type="http_audit",
            events_url="http://127.0.0.1/events",
            reset_url="http://127.0.0.1/reset",
            observes=[SideEffectKind.DATABASE_WRITE],
        ),
    )
    guard.observers = [observer]

    try:
        events, observation, details = await guard._collect_observers(
            {},
            {SideEffectKind.DATABASE_WRITE},
        )

        assert len(events) == 1
        assert events[0].kind == SideEffectKind.DATABASE_WRITE
        assert observation == ObservationStatus.PARTIAL
        assert details
    finally:
        store.close()


def test_jsonl_event_observer_remains_complete_for_declared_effect(
    tmp_path: Path,
) -> None:
    guard, store = _guard(tmp_path)
    observer = JsonlAuditObserver(
        "audit",
        JsonlAuditObserverSpec(
            type="jsonl_audit",
            path=tmp_path / "events.jsonl",
            observes=[SideEffectKind.FILESYSTEM_WRITE],
        ),
    )
    guard.observers = [observer]

    try:
        assert (
            guard._observer_coverage(
                {},
                {SideEffectKind.FILESYSTEM_WRITE},
            )
            == ObservationStatus.COMPLETE
        )
    finally:
        store.close()
