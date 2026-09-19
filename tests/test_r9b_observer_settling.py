from __future__ import annotations

import asyncio
import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from mcp_behaviour_guard.models import HttpAuditObserverSpec, JsonlAuditObserverSpec
from mcp_behaviour_guard.observers.base import ObserverCollectionError
from mcp_behaviour_guard.observers.http_audit import HttpAuditObserver
from mcp_behaviour_guard.observers.jsonl_audit import JsonlAuditObserver


def _jsonl_runtime_spec(
    path: Path,
    *,
    settle_timeout_seconds: float,
    quiet_period_seconds: float,
) -> SimpleNamespace:
    return SimpleNamespace(
        path=path,
        truncate_on_begin=False,
        observes=[],
        settle_timeout_seconds=settle_timeout_seconds,
        quiet_period_seconds=quiet_period_seconds,
    )


def _http_runtime_spec(
    *,
    settle_timeout_seconds: float,
    quiet_period_seconds: float,
) -> SimpleNamespace:
    return SimpleNamespace(
        events_url="https://example.test/audit/events",
        reset_url="https://example.test/audit/reset",
        timeout_seconds=1.0,
        observes=[],
        settle_timeout_seconds=settle_timeout_seconds,
        quiet_period_seconds=quiet_period_seconds,
    )


class _FakeResponse:
    def __init__(self, payload: Any) -> None:
        self._payload = copy.deepcopy(payload)

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return copy.deepcopy(self._payload)


class _SequencedAsyncClient:
    payloads: list[Any] = []
    get_count = 0
    init_count = 0

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        type(self).init_count += 1

    async def __aenter__(self) -> _SequencedAsyncClient:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def post(self, _url: str) -> _FakeResponse:
        return _FakeResponse({"ok": True})

    async def get(self, _url: str) -> _FakeResponse:
        index = min(type(self).get_count, len(type(self).payloads) - 1)
        type(self).get_count += 1
        item = type(self).payloads[index]
        if isinstance(item, tuple):
            delay, item = item
            await asyncio.sleep(float(delay))
        if isinstance(item, BaseException):
            raise item
        return _FakeResponse(item)


def _install_http_sequence(monkeypatch: pytest.MonkeyPatch, payloads: list[Any]) -> None:
    import mcp_behaviour_guard.observers.http_audit as module

    _SequencedAsyncClient.payloads = copy.deepcopy(payloads)
    _SequencedAsyncClient.get_count = 0
    _SequencedAsyncClient.init_count = 0
    monkeypatch.setattr(module.httpx, "AsyncClient", _SequencedAsyncClient)


def test_settling_spec_defaults_disabled_and_accepts_bounded_values(tmp_path: Path) -> None:
    default_jsonl = JsonlAuditObserverSpec(
        type="jsonl_audit",
        path=tmp_path / "audit.jsonl",
        observes=["database_write"],
    )
    assert default_jsonl.settle_timeout_seconds == 0
    assert default_jsonl.quiet_period_seconds == 0

    configured_jsonl = JsonlAuditObserverSpec(
        type="jsonl_audit",
        path=tmp_path / "configured.jsonl",
        observes=["database_write"],
        settle_timeout_seconds=0.2,
        quiet_period_seconds=0.05,
    )
    assert configured_jsonl.settle_timeout_seconds == 0.2
    assert configured_jsonl.quiet_period_seconds == 0.05

    configured_http = HttpAuditObserverSpec(
        type="http_audit",
        events_url="https://example.test/events",
        reset_url="https://example.test/reset",
        observes=["database_write"],
        settle_timeout_seconds=0.2,
        quiet_period_seconds=0.05,
    )
    assert configured_http.settle_timeout_seconds == 0.2
    assert configured_http.quiet_period_seconds == 0.05


@pytest.mark.parametrize(
    ("timeout", "quiet", "message"),
    [
        (0.2, 0.0, "settling requires both"),
        (0.0, 0.05, "settling requires both"),
        (0.05, 0.1, "quiet_period_seconds must not exceed settle_timeout_seconds"),
    ],
)
def test_settling_spec_rejects_ambiguous_or_unbounded_configuration(
    tmp_path: Path,
    timeout: float,
    quiet: float,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        JsonlAuditObserverSpec(
            type="jsonl_audit",
            path=tmp_path / "audit.jsonl",
            observes=["database_write"],
            settle_timeout_seconds=timeout,
            quiet_period_seconds=quiet,
        )


@pytest.mark.asyncio
async def test_jsonl_settling_captures_delayed_identical_events_by_byte_position(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.04,
        ),
    )
    await observer.begin()

    async def writer() -> None:
        await asyncio.sleep(0.015)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"kind":"database_write","record":"same"}\n')
            handle.flush()
        await asyncio.sleep(0.015)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"kind":"database_write","record":"same"}\n')
            handle.flush()

    writer_task = asyncio.create_task(writer())
    events = await observer.collect()
    await writer_task

    assert len(events) == 2
    assert [event.details["record"] for event in events] == ["same", "same"]


@pytest.mark.asyncio
async def test_jsonl_later_malformed_telemetry_preserves_validated_events(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.04,
        ),
    )
    await observer.begin()

    async def writer() -> None:
        await asyncio.sleep(0.015)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"kind":"database_write","record":"valid"}\n')
            handle.flush()
        await asyncio.sleep(0.015)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"kind":\n')
            handle.flush()

    writer_task = asyncio.create_task(writer())
    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()
    await writer_task

    assert len(exc_info.value.events) == 1
    assert exc_info.value.events[0].details["record"] == "valid"


@pytest.mark.asyncio
async def test_jsonl_replacement_after_valid_event_preserves_event_and_downgrades(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.05,
        ),
    )
    await observer.begin()

    async def writer() -> None:
        await asyncio.sleep(0.015)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"kind":"database_write","record":"kept"}\n')
            handle.flush()
        await asyncio.sleep(0.015)
        replacement = tmp_path / "replacement.jsonl"
        replacement.write_text(
            '{"kind":"database_write","record":"replacement"}\n',
            encoding="utf-8",
        )
        replacement.replace(path)

    writer_task = asyncio.create_task(writer())
    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()
    await writer_task

    assert len(exc_info.value.events) == 1
    assert exc_info.value.events[0].details["record"] == "kept"


@pytest.mark.asyncio
async def test_jsonl_shrink_after_valid_event_preserves_event_and_downgrades(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.05,
        ),
    )
    await observer.begin()

    async def writer() -> None:
        await asyncio.sleep(0.015)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"kind":"database_write","record":"kept"}\n')
            handle.flush()
        await asyncio.sleep(0.015)
        path.write_text("", encoding="utf-8")

    writer_task = asyncio.create_task(writer())
    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()
    await writer_task

    assert len(exc_info.value.events) == 1
    assert exc_info.value.events[0].details["record"] == "kept"


@pytest.mark.asyncio
async def test_http_settling_captures_delayed_append_without_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = {"kind": "database_write", "record": "late"}
    _install_http_sequence(monkeypatch, [[], [event], [event], [event]])

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.03,
        ),
    )
    events = await observer.collect()

    assert len(events) == 1
    assert events[0].details["record"] == "late"
    assert _SequencedAsyncClient.get_count >= 2


@pytest.mark.asyncio
async def test_http_same_payload_at_new_position_counts_as_distinct_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = {"kind": "database_write", "record": "same"}
    _install_http_sequence(
        monkeypatch,
        [[event], [event, event], [event, event], [event, event]],
    )

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.03,
        ),
    )
    events = await observer.collect()

    assert len(events) == 2
    assert [event.details["record"] for event in events] == ["same", "same"]


@pytest.mark.asyncio
async def test_http_prefix_rewrite_preserves_prior_event_and_downgrades(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {"kind": "database_write", "record": "first"}
    rewritten = {"kind": "database_write", "record": "rewritten"}
    _install_http_sequence(monkeypatch, [[first], [rewritten]])

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.03,
        ),
    )

    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()

    assert len(exc_info.value.events) == 1
    assert exc_info.value.events[0].details["record"] == "first"


@pytest.mark.asyncio
async def test_http_shrink_preserves_prior_events_and_downgrades(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {"kind": "database_write", "record": "first"}
    second = {"kind": "database_write", "record": "second"}
    _install_http_sequence(monkeypatch, [[first, second], [first]])

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.03,
        ),
    )

    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()

    assert [event.details["record"] for event in exc_info.value.events] == [
        "first",
        "second",
    ]


@pytest.mark.asyncio
async def test_http_later_malformed_suffix_preserves_prior_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {"kind": "database_write", "record": "first"}
    malformed = {"record": "missing-kind"}
    _install_http_sequence(monkeypatch, [[first], [first, malformed]])

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.03,
        ),
    )

    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()

    assert len(exc_info.value.events) == 1
    assert exc_info.value.events[0].details["record"] == "first"


@pytest.mark.asyncio
async def test_http_settling_is_bounded_by_deadline_under_continuous_growth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = [
        [{"kind": "database_write", "position": position} for position in range(count)]
        for count in range(1, 20)
    ]
    _install_http_sequence(monkeypatch, payloads)

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.05,
            quiet_period_seconds=0.04,
        ),
    )

    loop = asyncio.get_running_loop()
    started = loop.time()
    events = await observer.collect()
    elapsed = loop.time() - started

    assert elapsed < 0.20
    assert len(events) >= 2


@pytest.mark.asyncio
async def test_http_default_disabled_keeps_one_shot_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    late = {"kind": "database_write", "record": "late"}
    _install_http_sequence(monkeypatch, [[], [late]])

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.0,
            quiet_period_seconds=0.0,
        ),
    )
    events = await observer.collect()

    assert events == []
    assert _SequencedAsyncClient.get_count == 1


@pytest.mark.asyncio
async def test_jsonl_settling_waits_for_delayed_source_creation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.04,
        ),
    )
    await observer.begin()

    async def writer() -> None:
        await asyncio.sleep(0.015)
        path.write_text(
            '{"kind":"database_write","record":"created-late"}\n',
            encoding="utf-8",
        )

    writer_task = asyncio.create_task(writer())
    events = await observer.collect()
    await writer_task

    assert len(events) == 1
    assert events[0].details["record"] == "created-late"


@pytest.mark.asyncio
async def test_jsonl_disappearance_after_valid_event_preserves_event(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.05,
        ),
    )
    await observer.begin()

    async def writer() -> None:
        await asyncio.sleep(0.015)
        with path.open("a", encoding="utf-8") as handle:
            handle.write('{"kind":"database_write","record":"kept"}\n')
            handle.flush()
        await asyncio.sleep(0.015)
        path.unlink()

    writer_task = asyncio.create_task(writer())
    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()
    await writer_task

    assert len(exc_info.value.events) == 1
    assert exc_info.value.events[0].details["record"] == "kept"


@pytest.mark.asyncio
async def test_http_transport_failure_after_valid_snapshot_preserves_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {"kind": "database_write", "record": "first"}
    _install_http_sequence(monkeypatch, [[first], RuntimeError("transport down")])

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.05,
        ),
    )

    with pytest.raises(ObserverCollectionError) as exc_info:
        await observer.collect()

    assert len(exc_info.value.events) == 1
    assert exc_info.value.events[0].details["record"] == "first"


@pytest.mark.asyncio
async def test_http_initial_transport_failure_remains_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_http_sequence(monkeypatch, [RuntimeError("transport down")])

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.05,
        ),
    )

    with pytest.raises(RuntimeError, match="transport down"):
        await observer.collect()


@pytest.mark.asyncio
async def test_http_quiet_period_starts_after_first_successful_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    late = {"kind": "database_write", "record": "late"}
    _install_http_sequence(
        monkeypatch,
        [(0.03, []), [late], [late]],
    )

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.10,
            quiet_period_seconds=0.02,
        ),
    )
    events = await observer.collect()

    assert len(events) == 1
    assert events[0].details["record"] == "late"
    assert _SequencedAsyncClient.get_count >= 2


@pytest.mark.asyncio
async def test_http_overall_deadline_after_valid_snapshot_is_normal_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {"kind": "database_write", "record": "first"}
    _install_http_sequence(
        monkeypatch,
        [[first], (0.10, [first])],
    )

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.05,
            quiet_period_seconds=0.05,
        ),
    )
    events = await observer.collect()

    assert len(events) == 1
    assert events[0].details["record"] == "first"


@pytest.mark.asyncio
async def test_http_settling_reuses_one_async_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = {"kind": "database_write", "record": "late"}
    _install_http_sequence(
        monkeypatch,
        [[], [event], [event]],
    )

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.10,
            quiet_period_seconds=0.02,
        ),
    )
    events = await observer.collect()

    assert len(events) == 1
    assert _SequencedAsyncClient.init_count == 1


def test_jsonl_reader_rejects_replaced_inode_before_parsing_new_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.10,
            quiet_period_seconds=0.02,
        ),
    )

    asyncio.run(observer.begin())
    expected_identity = observer._source_identity
    assert expected_identity is not None

    replacement = tmp_path / "replacement.jsonl"
    replacement.write_text(
        '{"kind":"database_write","record":"replacement"}\n',
        encoding="utf-8",
    )
    replacement.replace(path)

    events = []
    with pytest.raises(ObserverCollectionError, match="replaced"):
        observer._read_complete_records(0, events, expected_identity)

    assert events == []


@pytest.mark.asyncio
async def test_jsonl_same_inode_rewrite_before_append_preserves_prior_event_and_downgrades(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.60,
            quiet_period_seconds=0.25,
        ),
    )
    await observer.begin()
    original_inode = path.stat().st_ino

    first = b'{"kind":"database_write","record":"aa"}\n'
    rewritten = b'{"kind":"database_write","record":"bb"}\n'
    later = b'{"kind":"database_write","record":"cc"}\n'
    assert len(first) == len(rewritten)

    first_consumed = asyncio.Event()
    original_reader = observer._read_complete_records

    def tracked_reader(*args: Any, **kwargs: Any) -> int:
        new_cursor = original_reader(*args, **kwargs)
        if new_cursor >= len(first):
            first_consumed.set()
        return new_cursor

    observer._read_complete_records = tracked_reader  # type: ignore[method-assign]

    async def writer() -> None:
        await asyncio.sleep(0.015)
        with path.open("ab") as handle:
            handle.write(first)
            handle.flush()

        await asyncio.wait_for(first_consumed.wait(), timeout=0.20)

        # r+b truncation preserves the inode on the supported POSIX path. Re-grow
        # past the prior cursor before the next poll so size/inode checks alone
        # cannot prove continuity.
        with path.open("r+b") as handle:
            handle.seek(0)
            handle.truncate(0)
            handle.write(rewritten)
            handle.write(later)
            handle.flush()

        assert path.stat().st_ino == original_inode

    writer_task = asyncio.create_task(writer())
    try:
        with pytest.raises(ObserverCollectionError, match="append position") as exc_info:
            await observer.collect()
    finally:
        await writer_task

    assert [event.details["record"] for event in exc_info.value.events] == ["aa"]


@pytest.mark.asyncio
async def test_http_prefix_continuity_distinguishes_boolean_from_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {"kind": "database_write", "flag": True}
    rewritten = {"kind": "database_write", "flag": 1}
    _install_http_sequence(monkeypatch, [[first], [rewritten]])

    observer = HttpAuditObserver(
        "audit",
        _http_runtime_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.05,
        ),
    )

    with pytest.raises(ObserverCollectionError, match="changed before") as exc_info:
        await observer.collect()

    assert len(exc_info.value.events) == 1
    assert exc_info.value.events[0].details["flag"] is True


@pytest.mark.asyncio
async def test_jsonl_same_size_rewrite_is_detected_at_settling_boundary(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    observer = JsonlAuditObserver(
        "audit",
        _jsonl_runtime_spec(
            path,
            settle_timeout_seconds=0.60,
            quiet_period_seconds=0.20,
        ),
    )
    await observer.begin()
    original_inode = path.stat().st_ino

    first = b'{"kind":"database_write","record":"aa"}\n'
    rewritten = b'{"kind":"database_write","record":"bb"}\n'
    assert len(first) == len(rewritten)

    first_consumed = asyncio.Event()
    original_reader = observer._read_complete_records

    def tracked_reader(*args: Any, **kwargs: Any) -> int:
        new_cursor = original_reader(*args, **kwargs)
        if new_cursor >= len(first):
            first_consumed.set()
        return new_cursor

    observer._read_complete_records = tracked_reader  # type: ignore[method-assign]

    async def writer() -> None:
        await asyncio.sleep(0.015)
        with path.open("ab") as handle:
            handle.write(first)
            handle.flush()

        await asyncio.wait_for(first_consumed.wait(), timeout=0.50)

        # Rewrite consumed bytes without changing inode or final size. No later
        # append exists, so the settling-boundary verification must catch this.
        with path.open("r+b") as handle:
            handle.seek(0)
            handle.write(rewritten)
            handle.flush()

        assert path.stat().st_ino == original_inode
        assert path.stat().st_size == len(first)

    writer_task = asyncio.create_task(writer())
    try:
        with pytest.raises(ObserverCollectionError, match="append position") as exc_info:
            await observer.collect()
    finally:
        await writer_task

    assert [event.details["record"] for event in exc_info.value.events] == ["aa"]
