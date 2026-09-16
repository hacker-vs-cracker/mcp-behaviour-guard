from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_behaviour_guard.client import McpClient
from mcp_behaviour_guard.engine import GuardEngine, _authorization_assessment
from mcp_behaviour_guard.evidence import redact
from mcp_behaviour_guard.models import (
    AssessmentStatus,
    AuthorizationStatus,
    Contract,
    ExecutionStatus,
    FilesystemObserverSpec,
    Finding,
    FindingStatus,
    HttpAuditObserverSpec,
    IdentitySpec,
    InvocationRecord,
    ObservationStatus,
    RunSummary,
    ServerSpec,
    Severity,
    SideEffectKind,
)
from mcp_behaviour_guard.observers.base import SideEffectEvent
from mcp_behaviour_guard.observers.http_audit import HttpAuditObserver
from mcp_behaviour_guard.storage import RunStore
from mcp_behaviour_guard.util import utc_now


class _ToolSession:
    def __init__(self, result: object) -> None:
        self.result = result

    async def call_tool(self, name: str, arguments: dict):
        del name, arguments
        return self.result


@pytest.mark.asyncio
async def test_tool_error_is_not_automatically_a_denial() -> None:
    client = McpClient(
        ServerSpec(name="local", url="http://127.0.0.1:8000/mcp"),
        "user",
        IdentitySpec(),
    )
    result = SimpleNamespace(
        isError=True, structuredContent=None, content=[SimpleNamespace(text="invalid customer")]
    )
    record = await client.invoke_on_session(_ToolSession(result), None, "TEST", "lookup", {})

    assert record.allowed is None
    assert record.authorization == AuthorizationStatus.UNKNOWN
    assert record.execution == ExecutionStatus.REJECTED
    assert _authorization_assessment(record, False, True) == FindingStatus.ERROR


@pytest.mark.asyncio
async def test_contract_declared_denial_needs_a_working_positive_control() -> None:
    client = McpClient(
        ServerSpec(name="local", url="http://127.0.0.1:8000/mcp"),
        "user",
        IdentitySpec(),
    )
    result = SimpleNamespace(
        isError=True,
        structuredContent=None,
        content=[SimpleNamespace(text="authentication required")],
    )
    record = await client.invoke_on_session(
        _ToolSession(result), None, "TEST", "lookup", {}, ["authentication required"]
    )

    assert record.authorization == AuthorizationStatus.DENY
    assert _authorization_assessment(record, False, False) == FindingStatus.ERROR
    assert _authorization_assessment(record, False, True) == FindingStatus.PASSED


@pytest.mark.asyncio
async def test_connection_error_does_not_look_like_a_denial() -> None:
    client = McpClient(
        ServerSpec(name="local", url="http://127.0.0.1:8000/mcp"),
        "user",
        IdentitySpec(),
    )

    @asynccontextmanager
    async def failed_session():
        raise ConnectionError("target unavailable")
        yield  # pragma: no cover

    client.session = failed_session  # type: ignore[method-assign]
    record = await client.invoke("TEST", "lookup", {})

    assert record.allowed is None
    assert record.authorization == AuthorizationStatus.UNKNOWN
    assert record.execution == ExecutionStatus.FAILED


def test_run_assessment_separates_failure_from_missing_evidence() -> None:
    base = dict(
        test_id="CHECK",
        category="test",
        title="check",
        severity=Severity.INFO,
        expected=True,
        observed=True,
    )
    summary = RunSummary(
        run_id="run",
        target="local",
        contract_path="contract.yaml",
        started_at="start",
        finished_at="finish",
        invocations=[],
        findings=[Finding(**base, status=FindingStatus.ERROR)],
    )
    assert summary.assessment == AssessmentStatus.INCONCLUSIVE
    assert '"assessment":"inconclusive"' in summary.model_dump_json()
    summary.findings.append(Finding(**base, status=FindingStatus.FAILED))
    assert summary.assessment == AssessmentStatus.FAIL


class _Observer:
    def __init__(
        self,
        name: str,
        fail: bool,
        events: list[SideEffectEvent],
        observes: set[SideEffectKind] | None = None,
    ) -> None:
        self.name = name
        self.fail = fail
        self.events = events
        self.observes = observes or set()

    async def begin(self) -> None:
        if self.fail:
            raise ConnectionError("audit unavailable")

    async def collect(self) -> list[SideEffectEvent]:
        return self.events


def _guard(tmp_path: Path, data: dict) -> tuple[GuardEngine, RunStore]:
    contract = Contract.model_validate(data)
    store = RunStore(tmp_path / "guard.db")
    guard = GuardEngine(contract, tmp_path / "contract.yaml", store, tmp_path / "reports", False)
    guard.run_dir.mkdir(parents=True)
    guard.trace_path.parent.mkdir(parents=True)
    store.start_run(guard.run_id, contract.server.target_label, "contract.yaml", "hash", utc_now())
    return guard, store


@pytest.mark.asyncio
async def test_observer_outage_is_partial_not_a_clean_pass(tmp_path: Path) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {"name": "local", "url": "http://127.0.0.1:8000/mcp"},
            "identities": {"user": {}},
            "tools": {"lookup": {"permitted_identities": ["user"], "read_only": True}},
        },
    )
    event = SideEffectEvent("healthy", SideEffectKind.DATABASE_WRITE, {"tool": "lookup"})
    guard.observers = [_Observer("broken", True, []), _Observer("healthy", False, [event])]
    try:
        errors = await guard._begin_observers()
        events, observation, details = await guard._collect_observers(errors)
        assert observation == ObservationStatus.PARTIAL
        assert events == [event]
        assert "broken" in details
    finally:
        store.close()


@pytest.mark.asyncio
async def test_prohibited_effect_fails_even_when_another_observer_is_down(tmp_path: Path) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {"name": "local", "url": "http://127.0.0.1:8000/mcp"},
            "identities": {"user": {}},
            "tools": {"lookup": {"permitted_identities": ["user"], "read_only": True}},
        },
    )
    event = SideEffectEvent("audit", SideEffectKind.DATABASE_WRITE, {"tool": "lookup"})
    guard.observers = [_Observer("broken", True, []), _Observer("audit", False, [event])]

    async def accepted(test_id, identity_name, identity, tool, arguments):
        del identity, arguments
        return InvocationRecord(
            test_id=test_id,
            tool=tool,
            identity=identity_name,
            arguments={},
            allowed=True,
            duration_ms=1,
        )

    guard._invoke = accepted  # type: ignore[method-assign]
    try:
        await guard._check_tool_side_effects()
        finding = next(item for item in guard.findings if item.category == "runtime_behaviour")
        assert finding.status == FindingStatus.FAILED
        assert finding.observation == ObservationStatus.PARTIAL
    finally:
        store.close()


@pytest.mark.asyncio
async def test_declared_side_effect_claim_without_observer_is_inconclusive(tmp_path: Path) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {"name": "local", "url": "http://127.0.0.1:8000/mcp"},
            "identities": {"user": {}},
            "tools": {"lookup": {"permitted_identities": ["user"], "read_only": True}},
        },
    )
    try:
        await guard._check_tool_side_effects()
        assert guard.findings[0].status == FindingStatus.ERROR
        assert guard.findings[0].observation == ObservationStatus.UNAVAILABLE
    finally:
        store.close()


@pytest.mark.asyncio
async def test_replay_with_zero_effects_is_inconclusive(tmp_path: Path) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {"name": "local", "url": "http://127.0.0.1:8000/mcp"},
            "identities": {"user": {}},
            "tools": {
                "write": {
                    "permitted_identities": ["user"],
                    "replay_probe": {"arguments": {}, "attempts": 2},
                }
            },
            "safety": {"destructive_tests": True, "require_lab_mode": False},
        },
    )
    guard.observers = [
        _Observer(
            "audit",
            False,
            [],
            {SideEffectKind.DATABASE_WRITE},
        )
    ]

    async def accepted(test_id, identity_name, identity, tool, arguments):
        del identity, arguments
        return InvocationRecord(
            test_id=test_id,
            tool=tool,
            identity=identity_name,
            arguments={},
            allowed=True,
            duration_ms=1,
        )

    guard._invoke = accepted  # type: ignore[method-assign]
    try:
        await guard._check_replay_protection()
        finding = next(item for item in guard.findings if item.category == "replay")
        assert finding.status == FindingStatus.ERROR
        assert finding.observed["matching_side_effects"] == 0
    finally:
        store.close()


@pytest.mark.asyncio
async def test_replay_never_runs_when_audit_cannot_start(tmp_path: Path) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {"name": "local", "url": "http://127.0.0.1:8000/mcp"},
            "identities": {"user": {}},
            "tools": {
                "write": {
                    "permitted_identities": ["user"],
                    "replay_probe": {"arguments": {}, "attempts": 2},
                }
            },
            "safety": {"destructive_tests": True, "require_lab_mode": False},
        },
    )
    guard.observers = [_Observer("audit", True, [])]

    async def unexpected_call(*args):
        del args
        raise AssertionError("replay was invoked without audit coverage")

    guard._invoke = unexpected_call  # type: ignore[method-assign]
    try:
        await guard._check_replay_protection()
        finding = next(item for item in guard.findings if item.category == "replay")
        assert finding.status == FindingStatus.ERROR
        assert finding.observed["probe_executed"] is False
    finally:
        store.close()


def test_trace_omits_arguments_response_and_configured_token(tmp_path: Path) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {"name": "local", "url": "http://127.0.0.1:8000/mcp"},
            "identities": {"user": {"headers": {"Authorization": "Bearer test-secret-token"}}},
            "tools": {"lookup": {"permitted_identities": ["user"]}},
        },
    )
    try:
        guard._record_invocation(
            InvocationRecord(
                test_id="TEST",
                tool="lookup",
                identity="user",
                arguments={"account": "private-account"},
                allowed=True,
                response={"token": "test-secret-token", "customer": "private-customer"},
                error=None,
                duration_ms=1,
            )
        )
        text = guard.trace_path.read_text(encoding="utf-8")
        assert "private-account" not in text
        assert "private-customer" not in text
        assert "test-secret-token" not in text
    finally:
        store.close()


@pytest.mark.asyncio
async def test_invalid_audit_kind_is_not_silently_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Client:
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
                json=lambda: {"events": [{"kind": "unrecognized_effect"}]},
            )

    monkeypatch.setattr("mcp_behaviour_guard.observers.http_audit.httpx.AsyncClient", _Client)
    observer = HttpAuditObserver(
        "audit",
        HttpAuditObserverSpec(
            type="http_audit",
            events_url="http://127.0.0.1/events",
            reset_url="http://127.0.0.1/reset",
        ),
    )
    with pytest.raises(ValueError, match="unknown event kind"):
        await observer.collect()


def test_execution_status_includes_unknown() -> None:
    assert "unknown" in {item.value for item in ExecutionStatus}


def test_mixed_pass_and_skip_is_not_overall_pass() -> None:
    base = dict(
        category="test",
        title="check",
        severity=Severity.INFO,
        expected=True,
        observed=True,
    )

    summary = RunSummary(
        run_id="run",
        target="local",
        contract_path="contract.yaml",
        started_at="start",
        finished_at="finish",
        invocations=[],
        findings=[
            Finding(test_id="PASS", **base, status=FindingStatus.PASSED),
            Finding(test_id="SKIP", **base, status=FindingStatus.SKIPPED),
        ],
    )

    assert summary.assessment == AssessmentStatus.NOT_TESTED


def test_evidence_validity_is_not_prematurely_exported() -> None:
    assert "evidence_validity" not in RunSummary.model_fields


def test_authorization_redaction_only_preserves_known_statuses() -> None:
    assert redact({"authorization": "allow"})["authorization"] == "allow"
    assert redact({"authorization": "deny"})["authorization"] == "deny"
    assert redact({"authorization": "unknown"})["authorization"] == "unknown"

    redacted = redact({"authorization": "opaque-auth-material-123456"})
    assert redacted["authorization"] == "[redacted]"


def test_http_audit_observer_declares_effect_coverage() -> None:
    spec = HttpAuditObserverSpec(
        type="http_audit",
        events_url="http://127.0.0.1/events",
        reset_url="http://127.0.0.1/reset",
        observes=[SideEffectKind.DATABASE_WRITE],
    )

    assert spec.model_dump(mode="json")["observes"] == [SideEffectKind.DATABASE_WRITE.value]


@pytest.mark.asyncio
async def test_healthy_observer_without_required_effect_coverage_is_partial(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {
                "name": "local",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {
                "lookup": {
                    "permitted_identities": ["user"],
                    "read_only": True,
                    "forbidden_side_effects": ["database_write"],
                }
            },
        },
    )

    guard.observers = [
        _Observer(
            "filesystem",
            False,
            [],
            {SideEffectKind.FILESYSTEM_WRITE},
        )
    ]

    async def accepted(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del identity, arguments
        return InvocationRecord(
            test_id=test_id,
            tool=tool,
            identity=identity_name,
            arguments={},
            allowed=True,
            duration_ms=1,
        )

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        await guard._check_tool_side_effects()

        finding = next(item for item in guard.findings if item.category == "runtime_behaviour")

        assert finding.status == FindingStatus.ERROR
        assert finding.observation == ObservationStatus.PARTIAL
    finally:
        store.close()


@pytest.mark.asyncio
async def test_replay_does_not_run_without_required_effect_coverage(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {
                "name": "local",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {
                "write": {
                    "permitted_identities": ["user"],
                    "replay_probe": {
                        "arguments": {},
                        "attempts": 2,
                        "event_kind": "database_write",
                    },
                }
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": False,
            },
        },
    )

    guard.observers = [
        _Observer(
            "filesystem",
            False,
            [],
            {SideEffectKind.FILESYSTEM_WRITE},
        )
    ]

    async def unexpected_call(*args):
        del args
        raise AssertionError("replay ran without database-write coverage")

    guard._invoke = unexpected_call  # type: ignore[method-assign]

    try:
        await guard._check_replay_protection()

        finding = next(item for item in guard.findings if item.category == "replay")

        assert finding.status == FindingStatus.ERROR
        assert finding.observation == ObservationStatus.PARTIAL
        assert finding.observed["probe_executed"] is False
    finally:
        store.close()


def test_filesystem_observer_cannot_overclaim_effect_coverage(tmp_path: Path) -> None:
    with pytest.raises(
        ValueError,
        match="filesystem observers can only observe filesystem_write",
    ):
        FilesystemObserverSpec(
            type="filesystem",
            roots=[tmp_path],
            observes=[SideEffectKind.DATABASE_WRITE],
        )
