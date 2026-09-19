from __future__ import annotations

import asyncio
import json
import os
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

import mcp_behaviour_guard.baseline as baseline_module
from mcp_behaviour_guard.baseline import capture_baseline
from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import Contract, InvocationRecord
from mcp_behaviour_guard.storage import RunStore
from mcp_behaviour_guard.util import stable_hash, utc_now


def _start_guard(
    tmp_path: Path,
    *,
    store_name: str,
    observers: dict[str, dict[str, Any]],
    replay_attempts: int | None = None,
) -> tuple[GuardEngine, RunStore]:
    tool: dict[str, Any] = {
        "permitted_identities": ["user"],
        "read_only": False,
        "forbidden_side_effects": ["database_write"],
    }
    if replay_attempts is not None:
        tool["replay_probe"] = {
            "arguments": {},
            "attempts": replay_attempts,
            "event_kind": "database_write",
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
            "observers": observers,
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        }
    )
    store = RunStore(tmp_path / store_name)
    guard = GuardEngine(
        contract,
        tmp_path / f"{store_name}.yaml",
        store,
        tmp_path / f"{store_name}-reports",
        False,
    )
    guard.run_dir.mkdir(parents=True, exist_ok=True)
    guard.trace_path.parent.mkdir(parents=True, exist_ok=True)
    store.start_run(
        guard.run_id,
        contract.server.target_label,
        str(tmp_path / f"{store_name}.yaml"),
        stable_hash(contract.model_dump(mode="json")),
        utc_now(),
    )
    return guard, store


def _jsonl_spec(path: Path, *, truncate_on_begin: bool = True) -> dict[str, Any]:
    return {
        "type": "jsonl_audit",
        "path": str(path),
        "truncate_on_begin": truncate_on_begin,
        "observes": ["database_write"],
    }


def _http_spec(base: str) -> dict[str, Any]:
    return {
        "type": "http_audit",
        "events_url": f"{base}/events",
        "reset_url": f"{base}/reset",
        "observes": ["database_write"],
    }


def _record(test_id: str, identity_name: str, tool: str) -> InvocationRecord:
    return InvocationRecord(
        test_id=test_id,
        tool=tool,
        identity=identity_name,
        arguments={},
        allowed=True,
        duration_ms=1,
    )


def test_observation_scope_separates_run_check_window_and_operation_identity() -> None:
    from mcp_behaviour_guard.observers.base import ObservationScope

    scope = ObservationScope(
        run_id="run-a",
        check_id="AUTH-WRITE-USER",
        window_id="window-a",
        operation_ids=("guard-op-1", "guard-op-2"),
    )

    assert scope.run_id == "run-a"
    assert scope.check_id == "AUTH-WRITE-USER"
    assert scope.window_id == "window-a"
    assert scope.operation_ids == ("guard-op-1", "guard-op-2")
    assert scope.check_id not in scope.operation_ids


@pytest.mark.asyncio
async def test_shared_jsonl_resources_are_exclusive_and_lock_order_is_deadlock_safe(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first.jsonl"
    second_path = tmp_path / "second.jsonl"

    guard_a, store_a = _start_guard(
        tmp_path,
        store_name="a.db",
        observers={
            "first": _jsonl_spec(first_path),
            "second": _jsonl_spec(second_path),
        },
    )
    guard_b, store_b = _start_guard(
        tmp_path,
        store_name="b.db",
        observers={
            "second": _jsonl_spec(second_path),
            "first": _jsonl_spec(first_path),
        },
    )

    state = {"active": 0, "max_active": 0}

    def fake_invoke(label: str):
        async def invoke(
            test_id: str,
            identity_name: str,
            identity: object,
            tool: str,
            arguments: dict[str, Any],
        ) -> InvocationRecord:
            del identity, arguments
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            try:
                await asyncio.sleep(0.08)
                for path in (first_path, second_path):
                    with path.open("a", encoding="utf-8") as handle:
                        handle.write(
                            json.dumps(
                                {
                                    "kind": "database_write",
                                    "tool": tool,
                                    "source": label,
                                }
                            )
                            + "\n"
                        )
                return _record(test_id, identity_name, tool)
            finally:
                state["active"] -= 1

        return invoke

    guard_a._invoke = fake_invoke("a")  # type: ignore[method-assign]
    guard_b._invoke = fake_invoke("b")  # type: ignore[method-assign]

    try:
        result_a, result_b = await asyncio.wait_for(
            asyncio.gather(
                guard_a._invoke_with_mutation_observation(
                    "AUTH-WRITE-USER",
                    "user",
                    guard_a.contract.identities["user"],
                    "write",
                    {},
                ),
                guard_b._invoke_with_mutation_observation(
                    "AUTH-WRITE-USER",
                    "user",
                    guard_b.contract.identities["user"],
                    "write",
                    {},
                ),
            ),
            timeout=2,
        )

        assert state["max_active"] == 1
        assert len(result_a[1]) == 2
        assert len(result_b[1]) == 2
        assert {event.details["source"] for event in result_a[1]} == {"a"}
        assert {event.details["source"] for event in result_b[1]} == {"b"}
    finally:
        store_a.close()
        store_b.close()


@pytest.mark.asyncio
async def test_shared_http_reset_stream_is_exclusive_and_does_not_cross_attribute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared_events: list[dict[str, Any]] = []

    class FakeResponse:
        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self._payload

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            del kwargs

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            del args

        async def post(self, url: str) -> FakeResponse:
            assert url.endswith("/reset")
            shared_events.clear()
            return FakeResponse({"reset": True})

        async def get(self, url: str) -> FakeResponse:
            assert url.endswith("/events")
            return FakeResponse({"events": list(shared_events)})

    monkeypatch.setattr(
        "mcp_behaviour_guard.observers.http_audit.httpx.AsyncClient",
        FakeClient,
    )

    base = "http://127.0.0.1:9999/audit"
    guard_a, store_a = _start_guard(
        tmp_path,
        store_name="http-a.db",
        observers={"audit": _http_spec(base)},
    )
    guard_b, store_b = _start_guard(
        tmp_path,
        store_name="http-b.db",
        observers={"audit": _http_spec(base)},
    )

    state = {"active": 0, "max_active": 0}

    def fake_invoke(label: str):
        async def invoke(
            test_id: str,
            identity_name: str,
            identity: object,
            tool: str,
            arguments: dict[str, Any],
        ) -> InvocationRecord:
            del identity, arguments
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            try:
                await asyncio.sleep(0.08)
                shared_events.append(
                    {
                        "kind": "database_write",
                        "tool": tool,
                        "source": label,
                    }
                )
                return _record(test_id, identity_name, tool)
            finally:
                state["active"] -= 1

        return invoke

    guard_a._invoke = fake_invoke("a")  # type: ignore[method-assign]
    guard_b._invoke = fake_invoke("b")  # type: ignore[method-assign]

    try:
        result_a, result_b = await asyncio.wait_for(
            asyncio.gather(
                guard_a._invoke_with_mutation_observation(
                    "AUTH-WRITE-USER",
                    "user",
                    guard_a.contract.identities["user"],
                    "write",
                    {},
                ),
                guard_b._invoke_with_mutation_observation(
                    "AUTH-WRITE-USER",
                    "user",
                    guard_b.contract.identities["user"],
                    "write",
                    {},
                ),
            ),
            timeout=2,
        )

        assert state["max_active"] == 1
        assert len(result_a[1]) == 1
        assert len(result_b[1]) == 1
        assert result_a[1][0].details["source"] == "a"
        assert result_b[1][0].details["source"] == "b"
    finally:
        store_a.close()
        store_b.close()


@pytest.mark.asyncio
async def test_cancelling_active_window_releases_shared_observer_ownership(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cancel.jsonl"
    observers = {"audit": _jsonl_spec(path)}
    guard_a, store_a = _start_guard(
        tmp_path,
        store_name="cancel-a.db",
        observers=observers,
    )
    guard_b, store_b = _start_guard(
        tmp_path,
        store_name="cancel-b.db",
        observers=observers,
    )

    first_entered = asyncio.Event()
    second_entered = asyncio.Event()
    hold_first = asyncio.Event()

    async def first_invoke(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        first_entered.set()
        await hold_first.wait()
        return _record(test_id, identity_name, tool)

    async def second_invoke(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        second_entered.set()
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "kind": "database_write",
                        "tool": tool,
                        "source": "second",
                    }
                )
                + "\n"
            )
        return _record(test_id, identity_name, tool)

    guard_a._invoke = first_invoke  # type: ignore[method-assign]
    guard_b._invoke = second_invoke  # type: ignore[method-assign]

    first_task: asyncio.Task[Any] | None = None
    second_task: asyncio.Task[Any] | None = None
    try:
        first_task = asyncio.create_task(
            guard_a._invoke_with_mutation_observation(
                "AUTH-WRITE-USER",
                "user",
                guard_a.contract.identities["user"],
                "write",
                {},
            )
        )
        await asyncio.wait_for(first_entered.wait(), timeout=1)

        second_task = asyncio.create_task(
            guard_b._invoke_with_mutation_observation(
                "AUTH-WRITE-USER",
                "user",
                guard_b.contract.identities["user"],
                "write",
                {},
            )
        )
        await asyncio.sleep(0.05)

        # The second operation must still be waiting for exclusive ownership.
        assert not second_entered.is_set()

        first_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_task

        await asyncio.wait_for(second_entered.wait(), timeout=1)
        second_result = await asyncio.wait_for(second_task, timeout=1)
        assert len(second_result[1]) == 1
        assert second_result[1][0].details["source"] == "second"
    finally:
        for task in (first_task, second_task):
            if task is not None and not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
        store_a.close()
        store_b.close()


@pytest.mark.asyncio
async def test_baseline_capture_uses_same_shared_observer_ownership(
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
            "observers": {"audit": _jsonl_spec(path)},
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        }
    )

    state = {"active": 0, "max_active": 0, "sequence": 0}

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
            **kwargs: Any,
        ) -> InvocationRecord:
            del arguments, denial_error_markers, kwargs
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            state["sequence"] += 1
            sequence = state["sequence"]
            try:
                await asyncio.sleep(0.08)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "kind": "database_write",
                                "tool": tool,
                                "source": f"baseline-{sequence}",
                            }
                        )
                        + "\n"
                    )
                return InvocationRecord(
                    test_id=test_id,
                    tool=tool,
                    identity=self.identity_name,
                    arguments={},
                    allowed=True,
                    response={"ok": True},
                    duration_ms=1,
                )
            finally:
                state["active"] -= 1

    monkeypatch.setattr(baseline_module, "McpClient", FakeBaselineClient)

    first, second = await asyncio.wait_for(
        asyncio.gather(
            capture_baseline(contract, lab_mode=True),
            capture_baseline(contract, lab_mode=True),
        ),
        timeout=2,
    )

    assert state["max_active"] == 1
    assert len(first["probes"]["write"]["side_effects"]) == 1
    assert len(second["probes"]["write"]["side_effects"]) == 1


@pytest.mark.asyncio
async def test_replay_attempts_keep_one_check_id_but_get_distinct_guard_operation_ids(
    tmp_path: Path,
) -> None:
    path = tmp_path / "replay.jsonl"
    guard, store = _start_guard(
        tmp_path,
        store_name="replay.db",
        observers={"audit": _jsonl_spec(path)},
        replay_attempts=3,
    )
    seen: list[tuple[str, str | None]] = []

    async def fake_invoke(
        test_id: str,
        identity_name: str,
        identity: object,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        del identity, arguments
        seen.append((test_id, guard._current_operation_id.get()))
        invocation = _record(test_id, identity_name, tool)
        guard._record_invocation(invocation)
        return invocation

    guard._invoke = fake_invoke  # type: ignore[method-assign]

    try:
        await guard._check_replay_protection()

        assert len(seen) == 3
        assert {test_id for test_id, _operation_id in seen} == {"REPLAY-WRITE"}
        operation_ids = [operation_id for _test_id, operation_id in seen]
        assert all(isinstance(item, str) and item for item in operation_ids)
        assert len(set(operation_ids)) == 3
    finally:
        store.close()


@pytest.mark.asyncio
async def test_runtime_side_effect_check_uses_shared_observer_ownership(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime-side-effects.jsonl"
    observers = {"audit": _jsonl_spec(path)}
    guard_a, store_a = _start_guard(
        tmp_path,
        store_name="runtime-a.db",
        observers=observers,
    )
    guard_b, store_b = _start_guard(
        tmp_path,
        store_name="runtime-b.db",
        observers=observers,
    )

    state = {"active": 0, "max_active": 0}

    def fake_invoke(label: str):
        async def invoke(
            test_id: str,
            identity_name: str,
            identity: object,
            tool: str,
            arguments: dict[str, Any],
        ) -> InvocationRecord:
            del identity, arguments
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            try:
                await asyncio.sleep(0.08)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "kind": "database_write",
                                "tool": tool,
                                "source": label,
                            }
                        )
                        + "\n"
                    )
                return _record(test_id, identity_name, tool)
            finally:
                state["active"] -= 1

        return invoke

    guard_a._invoke = fake_invoke("a")  # type: ignore[method-assign]
    guard_b._invoke = fake_invoke("b")  # type: ignore[method-assign]

    try:
        await asyncio.wait_for(
            asyncio.gather(
                guard_a._check_tool_side_effects(),
                guard_b._check_tool_side_effects(),
            ),
            timeout=2,
        )

        assert state["max_active"] == 1
        finding_a = next(item for item in guard_a.findings if item.test_id == "BEHAVIOUR-WRITE")
        finding_b = next(item for item in guard_b.findings if item.test_id == "BEHAVIOUR-WRITE")
        assert {event["details"]["source"] for event in finding_a.observed["events"]} == {"a"}
        assert {event["details"]["source"] for event in finding_b.observed["events"]} == {"b"}
    finally:
        store_a.close()
        store_b.close()


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.name != "posix", reason="R9A cross-process lease currently targets macOS/Ubuntu"
)
async def test_observer_ownership_coordinates_separate_processes(
    tmp_path: Path,
) -> None:
    from mcp_behaviour_guard.observers.ownership import observer_ownership

    key = f"r9a-cross-process:{tmp_path.resolve()}"

    class Resource:
        ownership_keys = (key,)

    child_code = r"""
import asyncio
import sys
from mcp_behaviour_guard.observers.ownership import observer_ownership

key = sys.argv[1]

class Resource:
    ownership_keys = (key,)

async def main() -> None:
    print("trying", flush=True)
    async with observer_ownership([Resource()]):
        print("acquired", flush=True)

asyncio.run(main())
"""

    async with observer_ownership([Resource()]):
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            child_code,
            key,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert child.stdout is not None
        assert await asyncio.wait_for(child.stdout.readline(), timeout=2) == b"trying\n"

        # The separate process must remain blocked while this process owns the lease.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(child.stdout.readline(), timeout=0.2)

        child.terminate()
        await asyncio.wait_for(child.wait(), timeout=2)

    # Once the owning process releases the lease, a new process must acquire it.
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        child_code,
        key,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(child.communicate(), timeout=3)
    assert child.returncode == 0, stderr.decode("utf-8", errors="replace")
    assert stdout.splitlines() == [b"trying", b"acquired"]


def _unstarted_guard_for_run(
    tmp_path: Path,
    *,
    store_name: str,
    observers: dict[str, dict[str, Any]],
    url: str = "http://127.0.0.1:8000/mcp",
) -> tuple[GuardEngine, RunStore]:
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": url,
            },
            "identities": {"user": {}},
            "tools": {},
            "observers": observers,
        }
    )
    store = RunStore(tmp_path / store_name)
    guard = GuardEngine(
        contract,
        tmp_path / f"{store_name}.yaml",
        store,
        tmp_path / f"{store_name}-reports",
        False,
    )
    return guard, store


def _install_minimal_run_body(
    guard: GuardEngine,
    *,
    entered: asyncio.Event,
    release: asyncio.Event | None = None,
    state: dict[str, int] | None = None,
) -> None:
    async def discover() -> list[dict[str, Any]]:
        if state is not None:
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
        entered.set()
        try:
            if release is not None:
                await release.wait()
            else:
                await asyncio.sleep(0.08)
            return []
        finally:
            if state is not None:
                state["active"] -= 1

    async def ignore(*args: object, **kwargs: object) -> None:
        del args, kwargs

    guard._discover_tools = discover  # type: ignore[method-assign]
    guard._check_inventory = ignore  # type: ignore[method-assign]
    guard._check_temporal_integrity = ignore  # type: ignore[method-assign]
    guard._check_access_matrix = ignore  # type: ignore[method-assign]
    guard._check_tool_side_effects = ignore  # type: ignore[method-assign]
    guard._check_tenant_isolation = ignore  # type: ignore[method-assign]
    guard._check_policy_probes = ignore  # type: ignore[method-assign]
    guard._check_session_isolation = ignore  # type: ignore[method-assign]
    guard._check_replay_protection = ignore  # type: ignore[method-assign]


@pytest.mark.asyncio
async def test_same_target_runs_serialize_even_when_one_run_has_no_observers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "shared.jsonl"
    guard_a, store_a = _unstarted_guard_for_run(
        tmp_path,
        store_name="whole-run-a.db",
        observers={"audit": _jsonl_spec(path)},
    )
    guard_b, store_b = _unstarted_guard_for_run(
        tmp_path,
        store_name="whole-run-b.db",
        observers={},
    )

    first_entered = asyncio.Event()
    second_entered = asyncio.Event()
    release_first = asyncio.Event()
    _install_minimal_run_body(
        guard_a,
        entered=first_entered,
        release=release_first,
    )
    _install_minimal_run_body(
        guard_b,
        entered=second_entered,
    )

    first_task: asyncio.Task[Any] | None = None
    second_task: asyncio.Task[Any] | None = None
    try:
        first_task = asyncio.create_task(guard_a.run())
        await asyncio.wait_for(first_entered.wait(), timeout=1)

        second_task = asyncio.create_task(guard_b.run())
        await asyncio.sleep(0.08)

        assert not second_entered.is_set()

        release_first.set()
        await asyncio.wait_for(first_task, timeout=1)
        await asyncio.wait_for(second_entered.wait(), timeout=1)
        await asyncio.wait_for(second_task, timeout=1)
    finally:
        release_first.set()
        for task in (first_task, second_task):
            if task is not None and not task.done():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
        store_a.close()
        store_b.close()


@pytest.mark.asyncio
async def test_different_targets_are_not_globally_serialized(
    tmp_path: Path,
) -> None:
    guard_a, store_a = _unstarted_guard_for_run(
        tmp_path,
        store_name="different-a.db",
        observers={},
    )
    guard_b, store_b = _unstarted_guard_for_run(
        tmp_path,
        store_name="different-b.db",
        observers={},
        url="http://127.0.0.1:9001/mcp",
    )

    entered_a = asyncio.Event()
    entered_b = asyncio.Event()
    state = {"active": 0, "max_active": 0}
    _install_minimal_run_body(guard_a, entered=entered_a, state=state)
    _install_minimal_run_body(guard_b, entered=entered_b, state=state)

    try:
        await asyncio.wait_for(
            asyncio.gather(guard_a.run(), guard_b.run()),
            timeout=2,
        )
        assert entered_a.is_set()
        assert entered_b.is_set()
        assert state["max_active"] == 2
    finally:
        store_a.close()
        store_b.close()


def test_server_ownership_key_is_opaque_and_deterministic() -> None:
    from mcp_behaviour_guard.models import ServerSpec
    from mcp_behaviour_guard.observers.ownership import server_ownership_key

    first = ServerSpec(
        name="target",
        url="https://user:top-secret@example.test/mcp?token=hidden",
    )
    second = ServerSpec(
        name="different-display-name",
        url="https://other:another-secret@example.test/other-path?x=y",
    )

    key_a = server_ownership_key(first)
    key_b = server_ownership_key(first)

    assert key_a == key_b
    assert key_a.startswith("mcp-target:")
    assert "top-secret" not in key_a
    assert "hidden" not in key_a
    assert "user" not in key_a

    assert key_a == server_ownership_key(second)


def _observer_contract(observers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": 1,
        "server": {
            "name": "offline",
            "url": "http://127.0.0.1:8000/mcp",
        },
        "identities": {"user": {}},
        "tools": {},
        "observers": observers,
    }


def test_contract_rejects_duplicate_jsonl_observer_source(tmp_path: Path) -> None:
    from pydantic import ValidationError

    audit = tmp_path / "audit.jsonl"
    with pytest.raises(ValidationError, match="share one JSONL audit source"):
        Contract.model_validate(
            _observer_contract(
                {
                    "first": _jsonl_spec(audit),
                    "second": _jsonl_spec(tmp_path / "nested" / ".." / "audit.jsonl"),
                }
            )
        )


def test_contract_rejects_shared_http_event_stream() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="share one HTTP event stream"):
        Contract.model_validate(
            _observer_contract(
                {
                    "first": {
                        "type": "http_audit",
                        "events_url": "https://user:secret@example.test/events?tenant=a",
                        "reset_url": "https://example.test/reset-a",
                        "observes": ["database_write"],
                    },
                    "second": {
                        "type": "http_audit",
                        "events_url": "https://other:secret@example.test/events?tenant=a",
                        "reset_url": "https://example.test/reset-b",
                        "observes": ["database_write"],
                    },
                }
            )
        )


def test_contract_rejects_shared_http_reset_stream() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="share one HTTP reset stream"):
        Contract.model_validate(
            _observer_contract(
                {
                    "first": {
                        "type": "http_audit",
                        "events_url": "https://example.test/events-a",
                        "reset_url": "https://user:secret@example.test/reset",
                        "observes": ["database_write"],
                    },
                    "second": {
                        "type": "http_audit",
                        "events_url": "https://example.test/events-b",
                        "reset_url": "https://other:secret@example.test/reset",
                        "observes": ["database_write"],
                    },
                }
            )
        )


def test_contract_rejects_overlapping_filesystem_observer_roots(tmp_path: Path) -> None:
    from pydantic import ValidationError

    root = tmp_path / "workspace"
    with pytest.raises(ValidationError, match="have overlapping filesystem roots"):
        Contract.model_validate(
            _observer_contract(
                {
                    "first": {
                        "type": "filesystem",
                        "roots": [str(root)],
                    },
                    "second": {
                        "type": "filesystem",
                        "roots": [str(root / "nested")],
                    },
                }
            )
        )


def test_contract_rejects_overlapping_roots_inside_one_filesystem_observer(
    tmp_path: Path,
) -> None:
    from pydantic import ValidationError

    root = tmp_path / "workspace"
    with pytest.raises(ValidationError, match="has overlapping filesystem roots"):
        Contract.model_validate(
            _observer_contract(
                {
                    "filesystem": {
                        "type": "filesystem",
                        "roots": [
                            str(root),
                            str(root / "nested"),
                        ],
                    }
                }
            )
        )


def test_server_ownership_key_normalizes_default_http_ports() -> None:
    from mcp_behaviour_guard.models import ServerSpec
    from mcp_behaviour_guard.observers.ownership import server_ownership_key

    https_implicit = ServerSpec(name="a", url="https://example.test/mcp")
    https_explicit = ServerSpec(name="b", url="https://example.test:443/other")
    https_nondefault = ServerSpec(name="c", url="https://example.test:8443/mcp")
    http_implicit = ServerSpec(name="d", url="http://example.test/mcp")
    http_explicit = ServerSpec(name="e", url="http://example.test:80/other")

    assert server_ownership_key(https_implicit) == server_ownership_key(https_explicit)
    assert server_ownership_key(http_implicit) == server_ownership_key(http_explicit)
    assert server_ownership_key(https_implicit) != server_ownership_key(https_nondefault)
    assert server_ownership_key(https_implicit) != server_ownership_key(http_implicit)


def test_contract_rejects_default_port_alias_for_same_http_event_stream() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="share one HTTP event stream"):
        Contract.model_validate(
            _observer_contract(
                {
                    "first": {
                        "type": "http_audit",
                        "events_url": "https://example.test/events",
                        "reset_url": "https://example.test/reset-a",
                        "observes": ["database_write"],
                    },
                    "second": {
                        "type": "http_audit",
                        "events_url": "https://example.test:443/events",
                        "reset_url": "https://example.test/reset-b",
                        "observes": ["database_write"],
                    },
                }
            )
        )


@pytest.mark.skipif(os.name != "posix", reason="R9A same-host process leasing targets macOS/Ubuntu")
def test_lock_directory_repairs_existing_permissions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import stat

    import mcp_behaviour_guard.observers.ownership as ownership_module

    monkeypatch.setattr(ownership_module, "_lease_base_dir", lambda: tmp_path)
    uid = str(os.getuid())
    root = tmp_path / f"mcp-behaviour-guard-{uid}"
    leases = root / "observer-leases"
    leases.mkdir(parents=True)
    root.chmod(0o777)
    leases.chmod(0o777)

    lock_path = ownership_module._lock_path(
        "http-audit-events:https://user:secret@example.test/events?token=hidden"
    )

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(leases.stat().st_mode) == 0o700
    assert "secret" not in lock_path.name
    assert "hidden" not in lock_path.name


@pytest.mark.skipif(os.name != "posix", reason="R9A same-host process leasing targets macOS/Ubuntu")
def test_lock_directory_rejects_wrong_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp_behaviour_guard.observers.ownership as ownership_module

    real_uid = os.getuid()
    fake_uid = real_uid + 1
    monkeypatch.setattr(ownership_module, "_lease_base_dir", lambda: tmp_path)
    monkeypatch.setattr(ownership_module.os, "getuid", lambda: fake_uid)

    root = tmp_path / f"mcp-behaviour-guard-{fake_uid}"
    root.mkdir(mode=0o700)

    with pytest.raises(PermissionError, match="not owned by the current user"):
        ownership_module._lock_path("r9a-owner-check")


@pytest.mark.skipif(os.name != "posix", reason="R9A same-host process leasing targets macOS/Ubuntu")
def test_lock_directory_rejects_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp_behaviour_guard.observers.ownership as ownership_module

    monkeypatch.setattr(ownership_module, "_lease_base_dir", lambda: tmp_path)
    target = tmp_path / "real-directory"
    target.mkdir(mode=0o700)
    root = tmp_path / f"mcp-behaviour-guard-{os.getuid()}"
    root.symlink_to(target, target_is_directory=True)

    with pytest.raises(PermissionError, match="must not be a symlink"):
        ownership_module._lock_path("r9a-symlink-check")


def test_http_observer_ownership_keys_normalize_resource_aliases() -> None:
    from mcp_behaviour_guard.models import HttpAuditObserverSpec
    from mcp_behaviour_guard.observers.http_audit import HttpAuditObserver

    first = HttpAuditObserver(
        "first",
        HttpAuditObserverSpec(
            type="http_audit",
            events_url="https://user:secret@example.test/events?tenant=a",
            reset_url="https://user:secret@example.test/reset",
            observes=["database_write"],
        ),
    )
    second = HttpAuditObserver(
        "second",
        HttpAuditObserverSpec(
            type="http_audit",
            events_url="https://other:another@example.test:443/events?tenant=a",
            reset_url="https://other:another@example.test:443/reset",
            observes=["database_write"],
        ),
    )

    assert first.ownership_keys == second.ownership_keys
    joined = " ".join(first.ownership_keys)
    assert "secret" not in joined
    assert "another" not in joined
    assert "user@" not in joined


def test_stdio_target_ownership_normalizes_equivalent_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp_behaviour_guard.models import ServerSpec
    from mcp_behaviour_guard.observers.ownership import server_ownership_key

    monkeypatch.chdir(tmp_path)
    relative = ServerSpec(
        name="relative",
        transport="stdio",
        command="python",
        args=["-m", "demo.server"],
        cwd=Path("."),
    )
    absolute = ServerSpec(
        name="absolute",
        transport="stdio",
        command="python",
        args=["-m", "demo.server"],
        cwd=tmp_path,
    )

    assert server_ownership_key(relative) == server_ownership_key(absolute)


def test_guard_operation_id_does_not_change_invocation_model_schema() -> None:
    assert "guard_operation_id" not in InvocationRecord.model_fields
    properties = InvocationRecord.model_json_schema().get("properties", {})
    assert "guard_operation_id" not in properties


@pytest.mark.skipif(os.name != "posix", reason="R9A same-host process leasing targets macOS/Ubuntu")
def test_posix_lease_namespace_does_not_depend_on_tmpdir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp_behaviour_guard.observers.ownership as ownership_module

    monkeypatch.setattr(ownership_module.tempfile, "gettempdir", lambda: "/tmp/alternate-r9a")
    assert ownership_module._lease_base_dir() == Path("/tmp")


def test_http_observer_ownership_key_is_role_neutral_for_same_resource() -> None:
    from mcp_behaviour_guard.models import HttpAuditObserverSpec
    from mcp_behaviour_guard.observers.http_audit import HttpAuditObserver

    first = HttpAuditObserver(
        "first",
        HttpAuditObserverSpec(
            type="http_audit",
            events_url="https://example.test/audit",
            reset_url="https://example.test/reset-a",
            observes=["database_write"],
        ),
    )
    second = HttpAuditObserver(
        "second",
        HttpAuditObserverSpec(
            type="http_audit",
            events_url="https://example.test/events-b",
            reset_url="https://example.test:443/audit",
            observes=["database_write"],
        ),
    )

    first_audit_key = next(key for key in first.ownership_keys if "/audit" in key)
    second_audit_key = next(key for key in second.ownership_keys if "/audit" in key)
    assert first_audit_key == second_audit_key


def test_contract_rejects_cross_role_http_resource_reuse() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="share one HTTP audit resource"):
        Contract.model_validate(
            _observer_contract(
                {
                    "first": {
                        "type": "http_audit",
                        "events_url": "https://example.test/audit",
                        "reset_url": "https://example.test/reset-a",
                        "observes": ["database_write"],
                    },
                    "second": {
                        "type": "http_audit",
                        "events_url": "https://example.test/events-b",
                        "reset_url": "https://example.test:443/audit",
                        "observes": ["database_write"],
                    },
                }
            )
        )


def test_contract_allows_one_http_observer_to_use_same_url_for_get_and_reset() -> None:
    contract = Contract.model_validate(
        _observer_contract(
            {
                "audit": {
                    "type": "http_audit",
                    "events_url": "https://example.test/audit",
                    "reset_url": "https://example.test:443/audit",
                    "observes": ["database_write"],
                }
            }
        )
    )
    assert set(contract.observers) == {"audit"}
