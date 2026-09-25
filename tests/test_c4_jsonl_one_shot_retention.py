from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import (
    Contract,
    JsonlAuditObserverSpec,
    ObservationStatus,
    SideEffectKind,
)
from mcp_behaviour_guard.observers.base import ObserverCollectionError
from mcp_behaviour_guard.observers.jsonl_audit import JsonlAuditObserver
from mcp_behaviour_guard.storage import RunStore


def _spec(path: Path) -> JsonlAuditObserverSpec:
    return JsonlAuditObserverSpec(
        type="jsonl_audit",
        path=path,
        truncate_on_begin=False,
        observes=[SideEffectKind.DATABASE_WRITE],
        settle_timeout_seconds=0,
        quiet_period_seconds=0,
    )


def _observer(path: Path) -> JsonlAuditObserver:
    return JsonlAuditObserver("audit", _spec(path))


def _valid_bytes(record: str = "valid") -> bytes:
    return (
        json.dumps(
            {
                "kind": "database_write",
                "record": record,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _guard(tmp_path: Path, observer: JsonlAuditObserver) -> tuple[GuardEngine, RunStore]:
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
    guard.observers = [observer]
    return guard, store


@pytest.mark.asyncio
async def test_one_shot_invalid_utf8_retains_prior_event_and_degrades_to_partial(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    observer = _observer(path)
    guard, store = _guard(tmp_path, observer)

    try:
        await observer.begin()
        path.write_bytes(_valid_bytes() + b'{"kind":"database_write","record":"bad-\xff"}\n')

        events, observation, errors = await guard._collect_observers(
            {},
            {SideEffectKind.DATABASE_WRITE},
        )

        assert [event.details["record"] for event in events] == ["valid"]
        assert observation == ObservationStatus.PARTIAL
        assert errors
    finally:
        store.close()


@pytest.mark.asyncio
async def test_one_shot_malformed_event_shape_retains_prior_event(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    observer = _observer(path)
    await observer.begin()
    path.write_bytes(_valid_bytes() + b'{"record":"missing-kind"}\n')

    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()

    assert [event.details["record"] for event in exc_info.value.events] == ["valid"]


@pytest.mark.asyncio
async def test_one_shot_incomplete_final_record_retains_prior_event(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    observer = _observer(path)
    await observer.begin()
    path.write_bytes(_valid_bytes() + b'{"kind":"database_write","record":"unfinished"')

    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()

    assert [event.details["record"] for event in exc_info.value.events] == ["valid"]


@pytest.mark.asyncio
async def test_one_shot_preserves_valid_final_json_without_trailing_newline(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    observer = _observer(path)
    await observer.begin()

    final = json.dumps(
        {"kind": "database_write", "record": "final-no-newline"},
        separators=(",", ":"),
    ).encode("utf-8")
    path.write_bytes(_valid_bytes("first") + final)

    events = await observer.collect()

    assert [event.details["record"] for event in events] == [
        "first",
        "final-no-newline",
    ]


@pytest.mark.asyncio
async def test_one_shot_accepts_blank_lines_and_crlf(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    observer = _observer(path)
    await observer.begin()

    record = b'{"kind":"database_write","record":"crlf"}\r\n'
    path.write_bytes(b"\r\n   \r\n" + record + b"\t\r\n")

    events = await observer.collect()

    assert [event.details["record"] for event in events] == ["crlf"]


@pytest.mark.asyncio
async def test_one_shot_handles_multibyte_utf8_across_text_reader_boundary(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    observer = _observer(path)
    await observer.begin()

    prefix = b'{"kind":"database_write","message":"'
    # Put the first byte of a three-byte UTF-8 code point at a typical 8192-byte
    # buffered-reader boundary. The exact buffer implementation is not part of
    # the contract; this freezes correct multibyte record semantics.
    padding = b"a" * (8191 - len(prefix))
    record = prefix + padding + "€".encode() + b'"}\n'
    path.write_bytes(record)

    events = await observer.collect()

    assert len(events) == 1
    assert events[0].details["message"].endswith("€")
