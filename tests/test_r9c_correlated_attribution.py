from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mcp_behaviour_guard.baseline as baseline_module
import mcp_behaviour_guard.engine as engine_module
from mcp_behaviour_guard.baseline import capture_baseline
from mcp_behaviour_guard.client import McpClient
from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import (
    AuthorizationStatus,
    Contract,
    ExecutionStatus,
    FindingStatus,
    HttpAuditObserverSpec,
    IdentitySpec,
    InvocationRecord,
    JsonlAuditObserverSpec,
    ObservationStatus,
    RunSummary,
    ServerSpec,
    SideEffectKind,
)
from mcp_behaviour_guard.observers.base import ObserverCollectionError, SideEffectEvent
from mcp_behaviour_guard.storage import RunStore
from mcp_behaviour_guard.util import stable_hash, utc_now

CORRELATION_META_KEY = "io.github.hacker-vs-cracker.mcp-behaviour-guard/correlation"


def _correlation_meta(run_id: str, operation_id: str) -> dict[str, Any]:
    return {
        CORRELATION_META_KEY: {
            "version": 1,
            "run_id": run_id,
            "guard_operation_id": operation_id,
        }
    }


def _event(
    *,
    run_id: str | None = None,
    operation_id: str | None = None,
    record: str,
    raw_meta: Any = None,
    include_vendor_meta: bool = False,
) -> SideEffectEvent:
    details: dict[str, Any] = {
        "kind": SideEffectKind.DATABASE_WRITE.value,
        "tool": "write",
        "record": record,
    }
    if raw_meta is not None:
        details["_meta"] = raw_meta
    elif run_id is not None and operation_id is not None:
        details["_meta"] = _correlation_meta(run_id, operation_id)

    if include_vendor_meta:
        existing = details.get("_meta")
        if not isinstance(existing, dict):
            existing = {}
        details["_meta"] = {
            **existing,
            "vendor.example/trace": {"id": "keep-me"},
        }

    return SideEffectEvent(
        observer="audit",
        kind=SideEffectKind.DATABASE_WRITE,
        details=details,
    )


class _AuditObserver:
    name = "audit"
    observes = {SideEffectKind.DATABASE_WRITE}
    complete_observes = {SideEffectKind.DATABASE_WRITE}
    ownership_keys: tuple[str, ...] = ()

    def __init__(
        self,
        events: list[SideEffectEvent] | None = None,
        *,
        correlation: str = "mcp_meta",
    ) -> None:
        self.events = list(events or [])
        self.correlation = correlation

    async def begin(self) -> None:
        return None

    async def collect(self) -> list[SideEffectEvent]:
        return list(self.events)


def _record(test_id: str, identity_name: str, tool: str) -> InvocationRecord:
    return InvocationRecord(
        test_id=test_id,
        tool=tool,
        identity=identity_name,
        arguments={},
        allowed=True,
        duration_ms=1,
    )


def _guard(
    tmp_path: Path,
    *,
    observer: _AuditObserver | None = None,
    replay: bool = False,
) -> tuple[GuardEngine, RunStore]:
    tool: dict[str, Any] = {
        "permitted_identities": ["user"],
        "read_only": False,
        "forbidden_side_effects": ["database_write"],
    }
    if replay:
        tool["replay_probe"] = {
            "arguments": {},
            "attempts": 2,
            "event_kind": "database_write",
            "minimum_events": 1,
            "maximum_events": 2,
        }

    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {"write": tool},
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
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
    guard.run_dir.mkdir(parents=True, exist_ok=True)
    guard.trace_path.parent.mkdir(parents=True, exist_ok=True)
    store.start_run(
        guard.run_id,
        contract.server.target_label,
        str(tmp_path / "contract.yaml"),
        stable_hash(contract.model_dump(mode="json")),
        utc_now(),
    )
    if observer is not None:
        guard.observers = [observer]
    return guard, store


async def _run_mutation_check(
    guard: GuardEngine,
) -> tuple[InvocationRecord, list[SideEffectEvent], ObservationStatus, dict[str, str]]:
    return await guard._invoke_with_mutation_observation(
        "BEHAVIOUR-WRITE",
        "user",
        guard.contract.identities["user"],
        "write",
        {},
    )


def _assert_no_internal_correlation(value: Any, *identifiers: str) -> None:
    rendered = json.dumps(value, sort_keys=True, default=str)
    assert CORRELATION_META_KEY not in rendered
    for identifier in identifiers:
        assert identifier not in rendered


def test_jsonl_correlation_is_opt_in_additive_and_keeps_contract_version_1(
    tmp_path: Path,
) -> None:
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {"name": "local", "url": "http://127.0.0.1:8000/mcp"},
            "identities": {"user": {}},
            "tools": {"write": {"permitted_identities": ["user"]}},
            "observers": {
                "audit": {
                    "type": "jsonl_audit",
                    "path": str(tmp_path / "audit.jsonl"),
                    "truncate_on_begin": False,
                    "correlation": "mcp_meta",
                    "observes": ["database_write"],
                }
            },
        }
    )

    spec = contract.observers["audit"]
    assert isinstance(spec, JsonlAuditObserverSpec)
    assert spec.correlation == "mcp_meta"
    assert spec.truncate_on_begin is False
    assert contract.version == 1
    assert RunSummary.model_fields["schema_version"].default == 2


def test_correlated_jsonl_rejects_destructive_truncate(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="truncate_on_begin"):
        JsonlAuditObserverSpec(
            type="jsonl_audit",
            path=tmp_path / "audit.jsonl",
            truncate_on_begin=True,
            correlation="mcp_meta",
            observes=[SideEffectKind.DATABASE_WRITE],
        )


def test_legacy_jsonl_remains_uncorrelated_by_default(tmp_path: Path) -> None:
    spec = JsonlAuditObserverSpec(
        type="jsonl_audit",
        path=tmp_path / "audit.jsonl",
        observes=[SideEffectKind.DATABASE_WRITE],
    )
    assert getattr(spec, "correlation", "none") == "none"


def test_http_correlation_remains_out_of_scope_for_c1a() -> None:
    with pytest.raises(ValueError):
        HttpAuditObserverSpec(
            type="http_audit",
            events_url="http://127.0.0.1/events",
            reset_url="http://127.0.0.1/reset",
            correlation="mcp_meta",
            observes=[SideEffectKind.DATABASE_WRITE],
        )


def test_public_evidence_models_do_not_gain_guard_operation_fields() -> None:
    assert "guard_operation_id" not in InvocationRecord.model_fields
    assert "correlation" not in InvocationRecord.model_fields
    assert "guard_operation_id" not in RunSummary.model_fields
    assert RunSummary.model_fields["schema_version"].default == 2


class _MetaSession:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        **kwargs: Any,
    ) -> object:
        self.calls.append(
            {
                "name": name,
                "arguments": dict(arguments),
                "kwargs": dict(kwargs),
            }
        )
        return self.result


@pytest.mark.asyncio
async def test_mcp_client_passes_namespaced_correlation_in_request_meta_without_arguments() -> None:
    client = McpClient(
        ServerSpec(name="local", url="http://127.0.0.1:8000/mcp"),
        "user",
        IdentitySpec(),
    )
    result = SimpleNamespace(
        isError=False,
        structuredContent={"ok": True},
        content=[],
    )
    session = _MetaSession(result)
    meta = _correlation_meta("run-a", "guard-op-a")
    arguments = {"account": "A"}

    record = await client.invoke_on_session(
        session,  # type: ignore[arg-type]
        None,
        "TEST",
        "lookup",
        arguments,
        meta=meta,
    )

    assert session.calls == [
        {
            "name": "lookup",
            "arguments": {"account": "A"},
            "kwargs": {"meta": meta},
        }
    ]
    assert arguments == {"account": "A"}
    assert record.authorization == AuthorizationStatus.ALLOW
    assert record.execution == ExecutionStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_mcp_client_legacy_call_does_not_send_empty_meta() -> None:
    client = McpClient(
        ServerSpec(name="local", url="http://127.0.0.1:8000/mcp"),
        "user",
        IdentitySpec(),
    )
    session = _MetaSession(
        SimpleNamespace(
            isError=False,
            structuredContent={"ok": True},
            content=[],
        )
    )

    await client.invoke_on_session(  # type: ignore[arg-type]
        session,
        None,
        "TEST",
        "lookup",
        {"account": "A"},
    )

    assert session.calls[0]["kwargs"] == {}


@pytest.mark.asyncio
async def test_correlation_metadata_does_not_create_authorization_truth() -> None:
    client = McpClient(
        ServerSpec(name="local", url="http://127.0.0.1:8000/mcp"),
        "user",
        IdentitySpec(),
    )
    session = _MetaSession(
        SimpleNamespace(
            isError=True,
            structuredContent=None,
            content=[SimpleNamespace(text="ordinary business validation error")],
        )
    )

    record = await client.invoke_on_session(
        session,  # type: ignore[arg-type]
        None,
        "TEST",
        "lookup",
        {},
        meta=_correlation_meta("run-a", "guard-op-a"),
    )

    assert record.authorization == AuthorizationStatus.UNKNOWN
    assert record.execution == ExecutionStatus.REJECTED


@pytest.mark.asyncio
async def test_concurrent_engine_operations_send_distinct_task_local_meta_and_do_not_export_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = _AuditObserver()
    guard, store = _guard(tmp_path, observer=observer)
    seen: list[tuple[str, dict[str, Any], Any]] = []

    class FakeClient:
        def __init__(self, server: object, identity_name: str, identity: object) -> None:
            del server, identity
            self.identity_name = identity_name

        async def invoke(
            self,
            test_id: str,
            tool: str,
            arguments: dict[str, Any],
            denial_error_markers: list[str] | None = None,
            **kwargs: Any,
        ) -> InvocationRecord:
            del denial_error_markers
            seen.append((test_id, dict(arguments), kwargs.get("meta")))
            await asyncio.sleep(0)
            return InvocationRecord(
                test_id=test_id,
                tool=tool,
                identity=self.identity_name,
                arguments=dict(arguments),
                allowed=True,
                duration_ms=1,
            )

    monkeypatch.setattr(engine_module, "McpClient", FakeClient)

    try:
        await asyncio.gather(
            guard._invoke_for_operation(
                "guard-op-a",
                "TEST",
                "user",
                guard.contract.identities["user"],
                "write",
                {"slot": "a"},
            ),
            guard._invoke_for_operation(
                "guard-op-b",
                "TEST",
                "user",
                guard.contract.identities["user"],
                "write",
                {"slot": "b"},
            ),
        )

        by_slot = {arguments["slot"]: meta for _test, arguments, meta in seen}
        assert by_slot == {
            "a": _correlation_meta(guard.run_id, "guard-op-a"),
            "b": _correlation_meta(guard.run_id, "guard-op-b"),
        }

        trace_text = guard.trace_path.read_text(encoding="utf-8")
        assert CORRELATION_META_KEY not in trace_text
        assert "guard-op-a" not in trace_text
        assert "guard-op-b" not in trace_text

        invocation_payloads = [
            row["payload_json"]
            for row in store.connection.execute(
                "SELECT payload_json FROM invocations ORDER BY id"
            ).fetchall()
        ]
        _assert_no_internal_correlation(
            invocation_payloads,
            "guard-op-a",
            "guard-op-b",
        )
    finally:
        store.close()


@pytest.mark.asyncio
async def test_engine_does_not_send_correlation_when_observer_is_not_opted_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = _AuditObserver(correlation="none")
    guard, store = _guard(tmp_path, observer=observer)
    seen: list[Any] = []

    class FakeClient:
        def __init__(self, server: object, identity_name: str, identity: object) -> None:
            del server, identity
            self.identity_name = identity_name

        async def invoke(
            self,
            test_id: str,
            tool: str,
            arguments: dict[str, Any],
            denial_error_markers: list[str] | None = None,
            **kwargs: Any,
        ) -> InvocationRecord:
            del arguments, denial_error_markers
            seen.append(kwargs.get("meta"))
            return _record(test_id, self.identity_name, tool)

    monkeypatch.setattr(engine_module, "McpClient", FakeClient)

    try:
        await guard._invoke_for_operation(
            "guard-op-legacy",
            "TEST",
            "user",
            guard.contract.identities["user"],
            "write",
            {},
        )
        assert seen == [None]
    finally:
        store.close()


@pytest.mark.asyncio
async def test_cancelled_operation_does_not_bleed_correlation_into_next_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = _AuditObserver()
    guard, store = _guard(tmp_path, observer=observer)
    entered = asyncio.Event()
    release = asyncio.Event()
    seen: list[tuple[str, Any]] = []

    class FakeClient:
        def __init__(self, server: object, identity_name: str, identity: object) -> None:
            del server, identity
            self.identity_name = identity_name

        async def invoke(
            self,
            test_id: str,
            tool: str,
            arguments: dict[str, Any],
            denial_error_markers: list[str] | None = None,
            **kwargs: Any,
        ) -> InvocationRecord:
            del arguments, denial_error_markers
            seen.append((test_id, kwargs.get("meta")))
            if test_id == "CANCEL":
                entered.set()
                await release.wait()
            return _record(test_id, self.identity_name, tool)

    monkeypatch.setattr(engine_module, "McpClient", FakeClient)

    try:
        task = asyncio.create_task(
            guard._invoke_for_operation(
                "guard-op-cancel",
                "CANCEL",
                "user",
                guard.contract.identities["user"],
                "write",
                {},
            )
        )
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        await guard._invoke_for_operation(
            "guard-op-next",
            "NEXT",
            "user",
            guard.contract.identities["user"],
            "write",
            {},
        )

        assert seen[0][1] == _correlation_meta(guard.run_id, "guard-op-cancel")
        assert seen[1][1] == _correlation_meta(guard.run_id, "guard-op-next")
    finally:
        release.set()
        store.close()


@pytest.mark.asyncio
async def test_foreign_valid_correlation_is_excluded_without_downgrading_observation(
    tmp_path: Path,
) -> None:
    observer = _AuditObserver(
        [_event(run_id="foreign-run", operation_id="foreign-op", record="foreign")]
    )
    guard, store = _guard(tmp_path, observer=observer)

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        _invocation, events, observation, errors = await _run_mutation_check(guard)

        assert events == []
        assert observation == ObservationStatus.COMPLETE
        assert errors == {}
        assert not any(item.category == "runtime_behaviour" for item in guard.findings)
    finally:
        store.close()


@pytest.mark.asyncio
async def test_missing_correlation_cannot_become_a_confirmed_violation(
    tmp_path: Path,
) -> None:
    observer = _AuditObserver([_event(record="uncorrelated")])
    guard, store = _guard(tmp_path, observer=observer)

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        _invocation, events, observation, errors = await _run_mutation_check(guard)

        assert events == []
        assert observation == ObservationStatus.PARTIAL
        assert "audit" in errors

        finding = next(item for item in guard.findings if item.category == "runtime_behaviour")
        assert finding.status == FindingStatus.ERROR
        assert finding.observation == ObservationStatus.PARTIAL
        assert finding.observed["violations"] == []
    finally:
        store.close()


@pytest.mark.parametrize(
    "malformed_meta",
    [
        "not-a-mapping",
        {CORRELATION_META_KEY: "not-an-envelope"},
        {
            CORRELATION_META_KEY: {
                "version": 2,
                "run_id": "run",
                "guard_operation_id": "op",
            }
        },
        {
            CORRELATION_META_KEY: {
                "version": 1,
                "run_id": 123,
                "guard_operation_id": "op",
            }
        },
        {
            CORRELATION_META_KEY: {
                "version": 1,
                "run_id": "run",
                "guard_operation_id": "",
            }
        },
    ],
    ids=[
        "meta-not-mapping",
        "envelope-not-mapping",
        "unsupported-version",
        "run-id-not-string",
        "empty-operation-id",
    ],
)
@pytest.mark.asyncio
async def test_malformed_correlation_is_partial_and_never_echoed_in_errors(
    tmp_path: Path,
    malformed_meta: Any,
) -> None:
    observer = _AuditObserver(
        [
            _event(
                record="malformed",
                raw_meta=malformed_meta,
            )
        ]
    )
    guard, store = _guard(tmp_path, observer=observer)

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        _invocation, events, observation, errors = await _run_mutation_check(guard)

        assert events == []
        assert observation == ObservationStatus.PARTIAL
        assert "audit" in errors
        assert CORRELATION_META_KEY not in json.dumps(errors, sort_keys=True)

        finding = next(item for item in guard.findings if item.category == "runtime_behaviour")
        assert finding.status == FindingStatus.ERROR
        assert finding.observation == ObservationStatus.PARTIAL
    finally:
        store.close()


@pytest.mark.asyncio
async def test_current_event_is_attributed_but_correlation_is_stripped_everywhere(
    tmp_path: Path,
) -> None:
    observer = _AuditObserver()
    guard, store = _guard(tmp_path, observer=observer)
    seen_operation_ids: list[str] = []

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        operation_id = guard._current_operation_id.get()
        assert operation_id is not None
        seen_operation_ids.append(operation_id)
        observer.events.append(
            _event(
                run_id=guard.run_id,
                operation_id=operation_id,
                record="current",
                include_vendor_meta=True,
            )
        )
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        _invocation, events, observation, errors = await _run_mutation_check(guard)

        assert observation == ObservationStatus.COMPLETE
        assert errors == {}
        assert len(events) == 1
        assert events[0].details["_meta"] == {"vendor.example/trace": {"id": "keep-me"}}

        operation_id = seen_operation_ids[0]
        finding = next(item for item in guard.findings if item.category == "runtime_behaviour")
        assert finding.status == FindingStatus.FAILED
        assert finding.observation == ObservationStatus.COMPLETE
        _assert_no_internal_correlation(finding.model_dump(mode="json"), operation_id)

        finding_payloads = [
            row["payload_json"]
            for row in store.connection.execute(
                "SELECT payload_json FROM findings ORDER BY id"
            ).fetchall()
        ]
        _assert_no_internal_correlation(finding_payloads, operation_id)

        summary = RunSummary(
            run_id=guard.run_id,
            target=guard.contract.server.target_label,
            contract_path=str(guard.contract_path),
            started_at="start",
            finished_at="finish",
            findings=guard.findings,
            invocations=guard.invocations,
        )
        _assert_no_internal_correlation(summary.model_dump(mode="json"), operation_id)
    finally:
        store.close()


@pytest.mark.asyncio
async def test_mixed_current_and_missing_correlation_keeps_confirmed_failure_but_is_partial(
    tmp_path: Path,
) -> None:
    observer = _AuditObserver([_event(record="missing-correlation")])
    guard, store = _guard(tmp_path, observer=observer)

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        operation_id = guard._current_operation_id.get()
        assert operation_id is not None
        observer.events.append(
            _event(
                run_id=guard.run_id,
                operation_id=operation_id,
                record="confirmed-current",
            )
        )
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        _invocation, events, observation, errors = await _run_mutation_check(guard)

        assert len(events) == 1
        assert events[0].details["record"] == "confirmed-current"
        assert observation == ObservationStatus.PARTIAL
        assert "audit" in errors

        finding = next(item for item in guard.findings if item.category == "runtime_behaviour")
        assert finding.status == FindingStatus.FAILED
        assert finding.observation == ObservationStatus.PARTIAL
        assert len(finding.observed["violations"]) == 1
    finally:
        store.close()


@pytest.mark.asyncio
async def test_same_valid_correlation_at_multiple_positions_is_not_deduplicated(
    tmp_path: Path,
) -> None:
    observer = _AuditObserver()
    guard, store = _guard(tmp_path, observer=observer)

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        operation_id = guard._current_operation_id.get()
        assert operation_id is not None
        observer.events.extend(
            [
                _event(
                    run_id=guard.run_id,
                    operation_id=operation_id,
                    record="same",
                ),
                _event(
                    run_id=guard.run_id,
                    operation_id=operation_id,
                    record="same",
                ),
            ]
        )
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        _invocation, events, observation, _errors = await _run_mutation_check(guard)

        assert observation == ObservationStatus.COMPLETE
        assert [event.details["record"] for event in events] == ["same", "same"]
        _assert_no_internal_correlation([event.details for event in events])
    finally:
        store.close()


@pytest.mark.asyncio
async def test_replay_counts_only_events_from_operation_ids_in_current_scope(
    tmp_path: Path,
) -> None:
    observer = _AuditObserver()
    guard, store = _guard(tmp_path, observer=observer, replay=True)
    seen_operation_ids: list[str] = []
    foreign_added = False

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        nonlocal foreign_added
        del identity, arguments
        operation_id = guard._current_operation_id.get()
        assert operation_id is not None
        seen_operation_ids.append(operation_id)

        if not foreign_added:
            foreign_added = True
            observer.events.append(
                _event(
                    run_id=guard.run_id,
                    operation_id="foreign-operation",
                    record="foreign",
                )
            )

        observer.events.append(
            _event(
                run_id=guard.run_id,
                operation_id=operation_id,
                record=f"current-{operation_id}",
            )
        )
        await asyncio.sleep(0)
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        await guard._check_replay_protection()

        assert len(seen_operation_ids) == 2
        assert len(set(seen_operation_ids)) == 2

        finding = next(item for item in guard.findings if item.category == "replay")
        assert finding.status == FindingStatus.PASSED
        assert finding.observation == ObservationStatus.COMPLETE
        assert finding.observed["matching_side_effects"] == 2
        assert {event["details"]["record"] for event in finding.observed["events"]} == {
            f"current-{operation_id}" for operation_id in seen_operation_ids
        }
        _assert_no_internal_correlation(finding.model_dump(mode="json"))
        for event in finding.observed["events"]:
            assert "_meta" not in event["details"]
    finally:
        store.close()


@pytest.mark.asyncio
async def test_correlated_baseline_propagates_meta_but_never_fingerprints_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "baseline.jsonl"
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {
                "write": {
                    "permitted_identities": ["user"],
                    "side_effect_identity": "user",
                    "read_only": False,
                    "probe_arguments": {},
                    "forbidden_side_effects": ["database_write"],
                }
            },
            "observers": {
                "audit": {
                    "type": "jsonl_audit",
                    "path": str(path),
                    "truncate_on_begin": False,
                    "correlation": "mcp_meta",
                    "observes": ["database_write"],
                }
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        }
    )
    seen_meta: list[dict[str, Any]] = []

    class FakeBaselineClient:
        def __init__(self, server: object, identity_name: str, identity: object) -> None:
            del server, identity
            self.identity_name = identity_name

        async def list_tools(self) -> list[dict[str, Any]]:
            return [{"name": "write"}]

        async def invoke(
            self,
            test_id: str,
            tool: str,
            arguments: dict[str, Any],
            denial_error_markers: list[str] | None = None,
            *,
            meta: dict[str, Any] | None = None,
        ) -> InvocationRecord:
            del arguments, denial_error_markers
            assert meta is not None
            seen_meta.append(meta)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "kind": "database_write",
                            "tool": tool,
                            "record": "baseline",
                            "_meta": meta,
                        }
                    )
                    + "\n"
                )
            return _record(test_id, self.identity_name, tool).model_copy(
                update={
                    "response": {
                        "ok": True,
                        "_meta": {
                            **meta,
                            "vendor.example/trace": {"id": "keep-me"},
                        },
                    }
                }
            )

    monkeypatch.setattr(baseline_module, "McpClient", FakeBaselineClient)

    baseline = await capture_baseline(contract, lab_mode=True)

    assert len(seen_meta) == 1
    envelope = seen_meta[0][CORRELATION_META_KEY]
    assert envelope["version"] == 1
    assert isinstance(envelope["run_id"], str) and envelope["run_id"]
    assert isinstance(envelope["guard_operation_id"], str) and envelope["guard_operation_id"]

    side_effects = baseline["probes"]["write"]["side_effects"]
    assert len(side_effects) == 1
    _assert_no_internal_correlation(
        side_effects,
        envelope["run_id"],
        envelope["guard_operation_id"],
    )

    response_shape = baseline["probes"]["write"]["response_shape"]
    assert response_shape["_meta"] == {"vendor.example/trace": {"id": "str"}}
    assert CORRELATION_META_KEY not in json.dumps(
        response_shape,
        sort_keys=True,
    )
    assert CORRELATION_META_KEY not in json.dumps(
        baseline,
        sort_keys=True,
    )


@pytest.mark.asyncio
async def test_correlation_only_meta_is_removed_after_successful_attribution(
    tmp_path: Path,
) -> None:
    observer = _AuditObserver()
    guard, store = _guard(tmp_path, observer=observer)

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        operation_id = guard._current_operation_id.get()
        assert operation_id is not None
        observer.events.append(
            _event(
                run_id=guard.run_id,
                operation_id=operation_id,
                record="current-only-meta",
            )
        )
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        _invocation, events, observation, errors = await _run_mutation_check(guard)
        assert observation == ObservationStatus.COMPLETE
        assert errors == {}
        assert len(events) == 1
        assert "_meta" not in events[0].details
    finally:
        store.close()


@pytest.mark.asyncio
async def test_r9b_collection_error_preserves_attributed_event_and_stays_partial(
    tmp_path: Path,
) -> None:
    class PartialAuditObserver(_AuditObserver):
        async def collect(self) -> list[SideEffectEvent]:
            raise ObserverCollectionError(
                "audit file changed before its append position",
                list(self.events),
            )

    observer = PartialAuditObserver()
    guard, store = _guard(tmp_path, observer=observer)

    async def accepted(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        operation_id = guard._current_operation_id.get()
        assert operation_id is not None
        observer.events.append(
            _event(
                run_id=guard.run_id,
                operation_id=operation_id,
                record="preserved-current",
            )
        )
        return _record(test_id, identity_name, tool)

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        _invocation, events, observation, errors = await _run_mutation_check(guard)
        assert observation == ObservationStatus.PARTIAL
        assert "audit" in errors
        assert "append position" in errors["audit"]
        assert len(events) == 1
        assert events[0].details["record"] == "preserved-current"
        assert "_meta" not in events[0].details

        finding = next(item for item in guard.findings if item.category == "runtime_behaviour")
        assert finding.status == FindingStatus.FAILED
        assert finding.observation == ObservationStatus.PARTIAL
        _assert_no_internal_correlation(finding.model_dump(mode="json"))
    finally:
        store.close()


@pytest.mark.asyncio
async def test_correlated_baseline_missing_correlation_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "baseline-missing-correlation.jsonl"
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {
                "write": {
                    "permitted_identities": ["user"],
                    "side_effect_identity": "user",
                    "read_only": False,
                    "probe_arguments": {},
                    "forbidden_side_effects": ["database_write"],
                }
            },
            "observers": {
                "audit": {
                    "type": "jsonl_audit",
                    "path": str(path),
                    "truncate_on_begin": False,
                    "correlation": "mcp_meta",
                    "observes": ["database_write"],
                }
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        }
    )

    class FakeBaselineClient:
        def __init__(self, server: object, identity_name: str, identity: object) -> None:
            del server, identity
            self.identity_name = identity_name

        async def list_tools(self) -> list[dict[str, Any]]:
            return [{"name": "write"}]

        async def invoke(
            self,
            test_id: str,
            tool: str,
            arguments: dict[str, Any],
            denial_error_markers: list[str] | None = None,
            *,
            meta: dict[str, Any] | None = None,
        ) -> InvocationRecord:
            del arguments, denial_error_markers
            assert meta is not None
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "kind": "database_write",
                            "tool": tool,
                            "record": "missing-correlation",
                        }
                    )
                    + "\n"
                )
            return _record(test_id, self.identity_name, tool)

    monkeypatch.setattr(baseline_module, "McpClient", FakeBaselineClient)

    with pytest.raises(ObserverCollectionError, match="correlation"):
        await capture_baseline(contract, lab_mode=True)


@pytest.mark.asyncio
async def test_exported_invocation_error_redacts_internal_correlation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = _AuditObserver()
    guard, store = _guard(tmp_path, observer=observer)
    operation_id = "guard-op-error"

    class FakeClient:
        def __init__(self, server: object, identity_name: str, identity: object) -> None:
            del server, identity
            self.identity_name = identity_name

        async def invoke(
            self,
            test_id: str,
            tool: str,
            arguments: dict[str, Any],
            denial_error_markers: list[str] | None = None,
            **kwargs: Any,
        ) -> InvocationRecord:
            del arguments, denial_error_markers, kwargs
            return _record(test_id, self.identity_name, tool).model_copy(
                update={
                    "allowed": None,
                    "error": (
                        f"transport request contained {CORRELATION_META_KEY} "
                        f"guard_operation_id={operation_id}"
                    ),
                }
            )

    monkeypatch.setattr(engine_module, "McpClient", FakeClient)

    try:
        await guard._invoke_for_operation(
            operation_id,
            "ERROR-ECHO",
            "user",
            guard.contract.identities["user"],
            "write",
            {},
        )

        exported_error = guard.invocations[-1].error or ""
        assert CORRELATION_META_KEY not in exported_error
        assert "guard_operation_id" not in exported_error
        assert operation_id not in exported_error

        trace_text = guard.trace_path.read_text(encoding="utf-8")
        _assert_no_internal_correlation(trace_text, operation_id)
        assert "guard_operation_id" not in trace_text

        payload = store.connection.execute(
            "SELECT payload_json FROM invocations ORDER BY id DESC LIMIT 1"
        ).fetchone()["payload_json"]
        _assert_no_internal_correlation(payload, operation_id)
        assert "guard_operation_id" not in payload
    finally:
        store.close()


@pytest.mark.asyncio
async def test_unrelated_correlated_observer_error_does_not_reduce_complete_required_coverage(
    tmp_path: Path,
) -> None:
    correlated = _AuditObserver([_event(record="missing-correlation")])

    class IndependentFilesystemObserver:
        name = "filesystem"
        observes = {SideEffectKind.FILESYSTEM_WRITE}
        complete_observes = {SideEffectKind.FILESYSTEM_WRITE}
        correlation = "none"
        ownership_keys: tuple[str, ...] = ()

        async def begin(self) -> None:
            return None

        async def collect(self) -> list[SideEffectEvent]:
            return [
                SideEffectEvent(
                    observer=self.name,
                    kind=SideEffectKind.FILESYSTEM_WRITE,
                    details={"path": "workspace/output.txt"},
                )
            ]

    guard, store = _guard(tmp_path, observer=correlated)
    guard.observers = [correlated, IndependentFilesystemObserver()]  # type: ignore[list-item]
    scope = guard._new_observation_scope("MIXED-COVERAGE")

    try:
        events, observation, errors = await guard._collect_observers(
            {},
            {SideEffectKind.FILESYSTEM_WRITE},
            scope,
        )

        assert observation == ObservationStatus.COMPLETE
        assert "audit" in errors
        assert len(events) == 1
        assert events[0].observer == "filesystem"
        assert events[0].kind == SideEffectKind.FILESYSTEM_WRITE
    finally:
        store.close()


@pytest.mark.asyncio
async def test_correlated_collection_without_scope_fails_closed(
    tmp_path: Path,
) -> None:
    observer = _AuditObserver(
        [_event(run_id="some-run", operation_id="some-operation", record="raw")]
    )
    guard, store = _guard(tmp_path, observer=observer)

    try:
        events, observation, errors = await guard._collect_observers(
            {},
            {SideEffectKind.DATABASE_WRITE},
        )

        assert events == []
        assert observation == ObservationStatus.PARTIAL
        assert errors == {"audit": "correlation: observation scope is required"}
        _assert_no_internal_correlation(errors)
    finally:
        store.close()


@pytest.mark.asyncio
async def test_downstream_finding_does_not_reexport_reflected_correlation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = _AuditObserver()
    guard, store = _guard(tmp_path, observer=observer)
    seen_operation_ids: list[str] = []

    class FakeClient:
        def __init__(self, server: object, identity_name: str, identity: object) -> None:
            del server, identity
            self.identity_name = identity_name

        async def invoke(
            self,
            test_id: str,
            tool: str,
            arguments: dict[str, Any],
            denial_error_markers: list[str] | None = None,
            **kwargs: Any,
        ) -> InvocationRecord:
            del arguments, denial_error_markers
            meta = kwargs.get("meta")
            assert isinstance(meta, dict)
            envelope = meta[CORRELATION_META_KEY]
            operation_id = envelope["guard_operation_id"]
            seen_operation_ids.append(operation_id)
            return _record(test_id, self.identity_name, tool).model_copy(
                update={
                    "allowed": None,
                    "error": (
                        f"request metadata {CORRELATION_META_KEY} guard_operation_id={operation_id}"
                    ),
                }
            )

    monkeypatch.setattr(engine_module, "McpClient", FakeClient)

    try:
        await guard._check_tool_side_effects()

        assert len(seen_operation_ids) == 1
        operation_id = seen_operation_ids[0]
        finding = next(item for item in guard.findings if item.category == "runtime_behaviour")
        assert finding.status == FindingStatus.ERROR
        _assert_no_internal_correlation(
            finding.model_dump(mode="json"),
            operation_id,
        )
        assert "guard_operation_id" not in json.dumps(
            finding.model_dump(mode="json"),
            sort_keys=True,
        )

        finding_payload = store.connection.execute(
            "SELECT payload_json FROM findings ORDER BY id DESC LIMIT 1"
        ).fetchone()["payload_json"]
        _assert_no_internal_correlation(finding_payload, operation_id)
        assert "guard_operation_id" not in finding_payload
    finally:
        store.close()


@pytest.mark.asyncio
async def test_r9b_partial_coverage_survives_unrelated_correlation_error(
    tmp_path: Path,
) -> None:
    correlated = _AuditObserver([_event(record="missing-correlation")])

    class PartialFilesystemObserver:
        name = "filesystem"
        observes = {SideEffectKind.FILESYSTEM_WRITE}
        complete_observes = {SideEffectKind.FILESYSTEM_WRITE}
        correlation = "none"
        ownership_keys: tuple[str, ...] = ()

        async def begin(self) -> None:
            return None

        async def collect(self) -> list[SideEffectEvent]:
            raise ObserverCollectionError(
                "filesystem changed during collection",
                [
                    SideEffectEvent(
                        observer=self.name,
                        kind=SideEffectKind.FILESYSTEM_WRITE,
                        details={"path": "workspace/preserved.txt"},
                    )
                ],
            )

    guard, store = _guard(tmp_path, observer=correlated)
    guard.observers = [correlated, PartialFilesystemObserver()]  # type: ignore[list-item]
    scope = guard._new_observation_scope("MIXED-R9B-CORRELATION")

    try:
        events, observation, errors = await guard._collect_observers(
            {},
            {SideEffectKind.FILESYSTEM_WRITE},
            scope,
        )

        assert observation == ObservationStatus.PARTIAL
        assert set(errors) == {"audit", "filesystem"}
        assert "correlation" in errors["audit"]
        assert "filesystem changed during collection" in errors["filesystem"]

        assert len(events) == 1
        assert events[0].observer == "filesystem"
        assert events[0].kind == SideEffectKind.FILESYSTEM_WRITE
        assert events[0].details["path"] == "workspace/preserved.txt"
    finally:
        store.close()
