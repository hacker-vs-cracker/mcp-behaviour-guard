from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import (
    Contract,
    FilesystemObserverSpec,
    InvocationRecord,
    SideEffectKind,
)
from mcp_behaviour_guard.observers.filesystem import FilesystemObserver
from mcp_behaviour_guard.storage import RunStore
from mcp_behaviour_guard.util import utc_now


def _guard(tmp_path: Path, contract_data: dict) -> tuple[GuardEngine, RunStore]:
    contract = Contract.model_validate(contract_data)
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
    store.start_run(
        guard.run_id,
        contract.server.target_label,
        "contract.yaml",
        "hash",
        utc_now(),
    )
    return guard, store


def test_filesystem_observer_rejects_empty_roots() -> None:
    with pytest.raises(ValidationError):
        FilesystemObserverSpec(type="filesystem", roots=[])


@pytest.mark.asyncio
async def test_filesystem_observer_rejects_non_directory_root(
    tmp_path: Path,
) -> None:
    file_root = tmp_path / "not-a-directory.txt"
    file_root.write_text("fixture", encoding="utf-8")
    observer = FilesystemObserver(
        "filesystem",
        FilesystemObserverSpec(
            type="filesystem",
            roots=[file_root],
        ),
    )

    with pytest.raises(NotADirectoryError):
        await observer.begin()


@pytest.mark.asyncio
async def test_filesystem_observer_keeps_same_basename_roots_distinct(
    tmp_path: Path,
) -> None:
    first = tmp_path / "one" / "data"
    second = tmp_path / "two" / "data"
    first.mkdir(parents=True)
    second.mkdir(parents=True)

    (first / "record.txt").write_text("same", encoding="utf-8")
    (second / "record.txt").write_text("same", encoding="utf-8")

    observer = FilesystemObserver(
        "filesystem",
        FilesystemObserverSpec(
            type="filesystem",
            roots=[first, second],
        ),
    )

    await observer.begin()
    (first / "record.txt").write_text("changed", encoding="utf-8")
    events = await observer.collect()

    assert len(events) == 1
    assert events[0].kind == SideEffectKind.FILESYSTEM_WRITE
    assert events[0].details["operation"] == "modified"


@pytest.mark.asyncio
async def test_access_matrix_does_not_mutate_when_required_observer_cannot_start(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
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
                    "forbidden_side_effects": ["database_write"],
                }
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        },
    )

    class BrokenObserver:
        name = "database"
        observes = {SideEffectKind.DATABASE_WRITE}

        async def begin(self) -> None:
            raise RuntimeError("observer unavailable")

        async def collect(self):
            return []

    guard.observers = [BrokenObserver()]
    calls: list[str] = []

    async def unexpected_mutation(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del test_id, identity_name, identity, arguments
        calls.append(tool)
        return InvocationRecord(
            test_id="AUTH-WRITE-USER",
            tool=tool,
            identity="user",
            arguments={},
            allowed=True,
            duration_ms=0,
        )

    guard._invoke = unexpected_mutation  # type: ignore[method-assign]

    try:
        await guard._check_access_matrix()
        assert calls == []
    finally:
        store.close()


def test_empty_network_allowlist_means_no_network_claim() -> None:
    from mcp_behaviour_guard.engine import (
        _required_effect_kinds,
        _side_effect_violations,
    )
    from mcp_behaviour_guard.models import ToolContract
    from mcp_behaviour_guard.observers.base import SideEffectEvent

    tool = ToolContract(
        permitted_identities=["user"],
        allowed_filesystem_writes=["data/*"],
    )
    event = SideEffectEvent(
        observer="audit",
        kind=SideEffectKind.NETWORK_REQUEST,
        details={"destination": "https://example.invalid"},
    )

    assert SideEffectKind.NETWORK_REQUEST not in _required_effect_kinds(tool)
    assert _side_effect_violations(tool, [event]) == []


def test_explicit_network_deny_requires_network_coverage_and_flags_event() -> None:
    from mcp_behaviour_guard.engine import (
        _required_effect_kinds,
        _side_effect_violations,
    )
    from mcp_behaviour_guard.models import ToolContract
    from mcp_behaviour_guard.observers.base import SideEffectEvent

    tool = ToolContract(
        permitted_identities=["user"],
        forbidden_side_effects=[SideEffectKind.NETWORK_REQUEST],
    )
    event = SideEffectEvent(
        observer="audit",
        kind=SideEffectKind.NETWORK_REQUEST,
        details={"destination": "https://example.invalid"},
    )

    assert SideEffectKind.NETWORK_REQUEST in _required_effect_kinds(tool)
    violations = _side_effect_violations(tool, [event])
    assert len(violations) == 1
    assert violations[0]["reason"] == "side-effect kind is explicitly forbidden"


@pytest.mark.asyncio
async def test_access_matrix_does_not_mutate_when_required_observer_is_missing(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
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
                    "forbidden_side_effects": ["database_write"],
                }
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        },
    )
    guard.observers = []
    calls: list[str] = []

    async def unexpected_mutation(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del test_id, identity_name, identity, arguments
        calls.append(tool)
        return InvocationRecord(
            test_id="AUTH-WRITE-USER",
            tool=tool,
            identity="user",
            arguments={},
            allowed=True,
            duration_ms=0,
        )

    guard._invoke = unexpected_mutation  # type: ignore[method-assign]

    try:
        await guard._check_access_matrix()
        assert calls == []
    finally:
        store.close()


@pytest.mark.asyncio
async def test_tenant_probe_does_not_mutate_when_required_observer_cannot_start(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {"tenant": "tenant-a"}},
            "tools": {
                "write": {
                    "permitted_identities": ["user"],
                    "forbidden_side_effects": ["database_write"],
                    "tenant_probes": {
                        "user": {
                            "arguments": {"tenant": "tenant-b"},
                            "expected_tenant": "tenant-a",
                            "require_denial": True,
                        }
                    },
                }
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        },
    )

    class BrokenObserver:
        name = "database"
        observes = {SideEffectKind.DATABASE_WRITE}

        async def begin(self) -> None:
            raise RuntimeError("observer unavailable")

        async def collect(self):
            return []

    guard.observers = [BrokenObserver()]
    calls: list[str] = []

    async def unexpected_mutation(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del test_id, identity_name, identity, arguments
        calls.append(tool)
        return InvocationRecord(
            test_id="TENANT-WRITE-USER",
            tool=tool,
            identity="user",
            arguments={},
            allowed=True,
            response={"tenant": "tenant-b"},
            duration_ms=0,
        )

    guard._invoke = unexpected_mutation  # type: ignore[method-assign]

    try:
        await guard._check_tenant_isolation()
        assert calls == []
    finally:
        store.close()


@pytest.mark.asyncio
async def test_policy_probe_does_not_mutate_when_required_observer_cannot_start(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
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
                    "forbidden_side_effects": ["database_write"],
                    "policy_probes": [
                        {
                            "id": "POLICY-WRITE-DENIED",
                            "identity": "user",
                            "arguments": {"value": "test"},
                            "checks": [{"type": "denied"}],
                        }
                    ],
                }
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        },
    )

    class BrokenObserver:
        name = "database"
        observes = {SideEffectKind.DATABASE_WRITE}

        async def begin(self) -> None:
            raise RuntimeError("observer unavailable")

        async def collect(self):
            return []

    guard.observers = [BrokenObserver()]
    calls: list[str] = []

    async def unexpected_mutation(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del test_id, identity_name, identity, arguments
        calls.append(tool)
        return InvocationRecord(
            test_id="POLICY-WRITE-DENIED",
            tool=tool,
            identity="user",
            arguments={},
            allowed=True,
            response={"ok": True},
            duration_ms=0,
        )

    guard._invoke = unexpected_mutation  # type: ignore[method-assign]

    try:
        await guard._check_policy_probes()
        assert calls == []
    finally:
        store.close()


@pytest.mark.asyncio
async def test_session_isolation_write_does_not_mutate_when_required_observer_cannot_start(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {
                "writer": {},
                "reader": {},
            },
            "tools": {
                "write": {
                    "permitted_identities": ["writer"],
                    "forbidden_side_effects": ["database_write"],
                },
                "read": {
                    "permitted_identities": ["reader"],
                    "read_only": True,
                },
            },
            "session_tests": [
                {
                    "id": "SESSION-001",
                    "writer_identity": "writer",
                    "reader_identity": "reader",
                    "write": {
                        "tool": "write",
                        "arguments": {"note": "placeholder"},
                    },
                    "read": {
                        "tool": "read",
                        "arguments": {},
                    },
                    "marker_argument": "note",
                }
            ],
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        },
    )

    class BrokenObserver:
        name = "database"
        observes = {SideEffectKind.DATABASE_WRITE}

        async def begin(self) -> None:
            raise RuntimeError("observer unavailable")

        async def collect(self):
            return []

    guard.observers = [BrokenObserver()]
    calls: list[str] = []

    async def unexpected_mutation(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del test_id, identity_name, identity, arguments
        calls.append(tool)
        return InvocationRecord(
            test_id="SESSION",
            tool=tool,
            identity="writer",
            arguments={},
            allowed=True,
            response={},
            duration_ms=0,
        )

    guard._invoke = unexpected_mutation  # type: ignore[method-assign]

    try:
        await guard._check_session_isolation()
        assert calls == []
    finally:
        store.close()


@pytest.mark.asyncio
async def test_mutating_access_matrix_runs_with_complete_required_observation(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
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
                    "forbidden_side_effects": ["database_write"],
                }
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        },
    )

    class HealthyObserver:
        name = "database"
        observes = {SideEffectKind.DATABASE_WRITE}

        def __init__(self) -> None:
            self.begins = 0
            self.collects = 0

        async def begin(self) -> None:
            self.begins += 1

        async def collect(self):
            self.collects += 1
            return []

    observer = HealthyObserver()
    guard.observers = [observer]
    calls: list[str] = []

    async def allowed_mutation(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del identity, arguments
        calls.append(tool)
        return InvocationRecord(
            test_id=test_id,
            tool=tool,
            identity=identity_name,
            arguments={},
            allowed=True,
            duration_ms=0,
        )

    guard._invoke = allowed_mutation  # type: ignore[method-assign]

    try:
        await guard._check_access_matrix()
        finding = next(item for item in guard.findings if item.test_id == "AUTH-WRITE-USER")
        assert calls == ["write"]
        assert observer.begins == 1
        assert observer.collects == 1
        assert finding.observation.value == "complete"
    finally:
        store.close()
