from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import (
    AuthorizationStatus,
    Contract,
    ExecutionStatus,
    FindingStatus,
    InvocationRecord,
    ObservationStatus,
    RunSummary,
)
from mcp_behaviour_guard.reporting import write_reports
from mcp_behaviour_guard.storage import RunStore
from mcp_behaviour_guard.util import utc_now

MARKER = "SYNTHETIC_C3B_PROTECTED_CANARY_20260925"


def _probe(
    *,
    require_denial: bool,
    confidentiality: dict[str, Any] | None = None,
    arguments: dict[str, Any] | None = None,
    resource_tenant_path: str = "resource.tenant",
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "arguments": arguments if arguments is not None else {"requested_tenant": "tenant-b"},
        "resource_tenant_path": resource_tenant_path,
        "expected_tenant": "tenant-a",
        "require_denial": require_denial,
    }
    if confidentiality is not None:
        value["confidentiality"] = confidentiality
    return value


def _contract_data(probe: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 1,
        "server": {
            "name": "offline",
            "url": "http://127.0.0.1:8000/mcp",
        },
        "identities": {
            "user": {
                "tenant": "tenant-a",
            }
        },
        "tools": {
            "lookup": {
                "permitted_identities": ["user"],
                "read_only": True,
                "tenant_probes": {
                    "user": probe,
                },
            }
        },
    }


def _guard(tmp_path: Path, probe: dict[str, Any]) -> tuple[GuardEngine, RunStore]:
    contract = Contract.model_validate(_contract_data(probe))
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


def _invocation(
    *,
    allowed: bool | None,
    authorization: AuthorizationStatus,
    execution: ExecutionStatus,
    response: Any,
    error: str | None = None,
) -> InvocationRecord:
    return InvocationRecord(
        test_id="TENANT-LOOKUP-USER",
        tool="lookup",
        identity="user",
        arguments={},
        allowed=allowed,
        authorization=authorization,
        execution=execution,
        response=response,
        error=error,
        duration_ms=0,
    )


async def _exercise(
    tmp_path: Path,
    *,
    probe: dict[str, Any],
    invocation: InvocationRecord,
    positive_control: bool = True,
    observation: ObservationStatus = ObservationStatus.NOT_REQUIRED,
    observer_errors: dict[str, str] | None = None,
):
    guard, store = _guard(tmp_path, probe)
    guard._identity_positive_controls[("lookup", "user")] = positive_control

    async def observed(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del test_id, identity_name, identity, tool, arguments
        return invocation, [], observation, observer_errors or {}

    guard._invoke_with_mutation_observation = observed  # type: ignore[method-assign]

    try:
        await guard._check_tenant_isolation()
        return next(item for item in guard.findings if item.test_id == "TENANT-LOOKUP-USER")
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Preservation checks. These are expected to be GREEN before C3b implementation.
# They freeze the corrected interpretation and prevent the old Case-B mistake.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_preserves_strict_denial_failure_for_successful_forbidden_call(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(require_denial=True),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={"resource": {"tenant": "tenant-a"}},
        ),
    )
    assert finding.status == FindingStatus.FAILED


@pytest.mark.asyncio
async def test_preserves_foreign_real_owner_as_ownership_failure(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(require_denial=False),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={"resource": {"tenant": "tenant-b"}},
        ),
    )
    assert finding.status == FindingStatus.FAILED


@pytest.mark.asyncio
async def test_preserves_requested_tenant_echo_when_real_owner_matches(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(require_denial=False),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={
                "requested_tenant": "tenant-b",
                "resource": {"tenant": "tenant-a"},
            },
        ),
    )
    assert finding.status == FindingStatus.PASSED


# ---------------------------------------------------------------------------
# C3b RED contract and semantic freeze.
#
# Chosen bounded additive shape:
#   tenant_probes.<identity>.confidentiality.values
#
# "values" is deliberate: current evidence redaction already omits that key.
# Matching is exact, case-sensitive literal containment in response string leaves.
# No regex, fuzzy matching, or encoding expansion is part of this slice.
# ---------------------------------------------------------------------------


def test_contract_v1_accepts_optional_confidentiality_values() -> None:
    contract = Contract.model_validate(
        _contract_data(
            _probe(
                require_denial=True,
                confidentiality={"values": [MARKER]},
            )
        )
    )
    assert contract.version == 1
    predicate = contract.tools["lookup"].tenant_probes["user"].confidentiality
    assert predicate is not None
    assert predicate.values == [MARKER]


@pytest.mark.asyncio
async def test_denied_protected_match_fails_confidentiality(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=True,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=False,
            authorization=AuthorizationStatus.DENY,
            execution=ExecutionStatus.REJECTED,
            response={
                "error": "access denied",
                "payload": {"message": f"prefix:{MARKER}:suffix"},
            },
            error="tool returned isError=true",
        ),
    )
    assert finding.status == FindingStatus.FAILED
    assert finding.observed["authorization_assertion"] == "passed"
    assert finding.observed["confidentiality_assertion"] == "failed"


@pytest.mark.asyncio
async def test_denied_harmless_requested_tenant_echo_is_not_confidentiality_failure(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=True,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=False,
            authorization=AuthorizationStatus.DENY,
            execution=ExecutionStatus.REJECTED,
            response={
                "error": "access denied",
                "requested_tenant": "tenant-b",
            },
            error="tool returned isError=true",
        ),
    )
    assert finding.status == FindingStatus.PASSED
    assert finding.observed["authorization_assertion"] == "passed"
    assert finding.observed["confidentiality_assertion"] == "passed"


@pytest.mark.asyncio
async def test_protected_match_survives_unknown_execution(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=True,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=None,
            authorization=AuthorizationStatus.UNKNOWN,
            execution=ExecutionStatus.FAILED,
            response={"payload": {"protected": MARKER}},
            error="transport failed after response capture",
        ),
    )
    assert finding.status == FindingStatus.FAILED
    assert finding.observed["authorization_assertion"] == "error"
    assert finding.observed["confidentiality_assertion"] == "failed"
    assert finding.observed["execution"] == ExecutionStatus.FAILED.value


@pytest.mark.asyncio
async def test_protected_match_survives_missing_positive_control(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=True,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=False,
            authorization=AuthorizationStatus.DENY,
            execution=ExecutionStatus.REJECTED,
            response={"payload": {"protected": MARKER}},
            error="tool returned isError=true",
        ),
        positive_control=False,
    )
    assert finding.status == FindingStatus.FAILED
    assert finding.observed["authorization_assertion"] == "error"
    assert finding.observed["confidentiality_assertion"] == "failed"


@pytest.mark.asyncio
async def test_protected_match_survives_partial_observation(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=True,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=False,
            authorization=AuthorizationStatus.DENY,
            execution=ExecutionStatus.REJECTED,
            response={"payload": {"protected": MARKER}},
            error="tool returned isError=true",
        ),
        observation=ObservationStatus.PARTIAL,
        observer_errors={"database": "collector ended early"},
    )
    assert finding.status == FindingStatus.FAILED
    assert finding.observation == ObservationStatus.PARTIAL
    assert finding.observed["confidentiality_assertion"] == "failed"


@pytest.mark.asyncio
async def test_protected_match_survives_unavailable_observation(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=True,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=False,
            authorization=AuthorizationStatus.DENY,
            execution=ExecutionStatus.REJECTED,
            response={"payload": {"protected": MARKER}},
            error="tool returned isError=true",
        ),
        observation=ObservationStatus.UNAVAILABLE,
        observer_errors={"database": "collector unavailable"},
    )
    assert finding.status == FindingStatus.FAILED
    assert finding.observation == ObservationStatus.UNAVAILABLE
    assert finding.observed["confidentiality_assertion"] == "failed"


@pytest.mark.asyncio
async def test_successful_forbidden_call_records_authorization_failure(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(require_denial=True),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={"resource": {"tenant": "tenant-a"}},
        ),
    )
    assert finding.status == FindingStatus.FAILED
    assert finding.observed["authorization_assertion"] == "failed"
    assert finding.observed["confidentiality_assertion"] == "not_asserted"


@pytest.mark.asyncio
async def test_foreign_owner_failure_is_not_relabelled_as_confidentiality(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(require_denial=False),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={"resource": {"tenant": "tenant-b"}},
        ),
    )
    assert finding.status == FindingStatus.FAILED
    assert finding.observed["authorization_assertion"] == "not_asserted"
    assert finding.observed["ownership_assertion"] == "failed"
    assert finding.observed["confidentiality_assertion"] == "not_asserted"


@pytest.mark.asyncio
async def test_requested_tenant_echo_is_not_independent_confidentiality_evidence(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(require_denial=False),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={
                "requested_tenant": "tenant-b",
                "resource": {"tenant": "tenant-a"},
            },
        ),
    )
    assert finding.status == FindingStatus.PASSED
    assert finding.observed["ownership_assertion"] == "passed"
    assert finding.observed["confidentiality_assertion"] == "not_asserted"


@pytest.mark.asyncio
async def test_legacy_probe_marks_confidentiality_unasserted(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(require_denial=True),
        invocation=_invocation(
            allowed=False,
            authorization=AuthorizationStatus.DENY,
            execution=ExecutionStatus.REJECTED,
            response={"error": "access denied"},
            error="tool returned isError=true",
        ),
    )
    assert finding.status == FindingStatus.PASSED
    assert finding.observed["authorization_assertion"] == "passed"
    assert finding.observed["confidentiality_assertion"] == "not_asserted"


def test_confidentiality_values_reject_empty_or_whitespace_only_values() -> None:
    with pytest.raises(ValidationError):
        Contract.model_validate(
            _contract_data(
                _probe(
                    require_denial=True,
                    confidentiality={"values": []},
                )
            )
        )

    with pytest.raises(ValidationError) as excinfo:
        Contract.model_validate(
            _contract_data(
                _probe(
                    require_denial=True,
                    confidentiality={"values": ["   "]},
                )
            )
        )
    assert "non-empty" in str(excinfo.value).lower()


def test_confidentiality_values_reject_duplicates() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Contract.model_validate(
            _contract_data(
                _probe(
                    require_denial=True,
                    confidentiality={"values": [MARKER, MARKER]},
                )
            )
        )
    assert "duplicate" in str(excinfo.value).lower()


def test_confidentiality_value_already_in_nested_request_arguments_is_rejected() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Contract.model_validate(
            _contract_data(
                _probe(
                    require_denial=True,
                    arguments={
                        "requested_tenant": "tenant-b",
                        "filters": {"client_supplied": MARKER},
                    },
                    confidentiality={"values": [MARKER]},
                )
            )
        )
    assert "request arguments" in str(excinfo.value).lower()


@pytest.mark.asyncio
async def test_missing_selected_owner_is_inconclusive_not_pass_or_mismatch_failure(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(require_denial=False),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={"requested_tenant": "tenant-b"},
        ),
    )
    assert finding.status == FindingStatus.ERROR
    assert finding.observed["ownership_assertion"] == "error"
    assert finding.observed["confidentiality_assertion"] == "not_asserted"


@pytest.mark.asyncio
async def test_protected_match_and_owner_mismatch_preserve_both_failures(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=False,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={
                "resource": {"tenant": "tenant-b"},
                "payload": {"protected": MARKER},
            },
        ),
    )
    assert finding.status == FindingStatus.FAILED
    assert finding.observed["ownership_assertion"] == "failed"
    assert finding.observed["confidentiality_assertion"] == "failed"


@pytest.mark.asyncio
async def test_confidentiality_literal_matching_is_case_sensitive(
    tmp_path: Path,
) -> None:
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=False,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={
                "resource": {"tenant": "tenant-a"},
                "payload": {"protected": MARKER.lower()},
            },
        ),
    )
    assert finding.status == FindingStatus.PASSED
    assert finding.observed["ownership_assertion"] == "passed"
    assert finding.observed["confidentiality_assertion"] == "passed"


@pytest.mark.asyncio
async def test_confidentiality_does_not_expand_base64_encodings(
    tmp_path: Path,
) -> None:
    encoded = base64.b64encode(MARKER.encode("utf-8")).decode("ascii")
    finding = await _exercise(
        tmp_path,
        probe=_probe(
            require_denial=False,
            confidentiality={"values": [MARKER]},
        ),
        invocation=_invocation(
            allowed=True,
            authorization=AuthorizationStatus.ALLOW,
            execution=ExecutionStatus.SUCCEEDED,
            response={
                "resource": {"tenant": "tenant-a"},
                "payload": {"protected": encoded},
            },
        ),
    )
    assert finding.status == FindingStatus.PASSED
    assert finding.observed["confidentiality_assertion"] == "passed"


@pytest.mark.asyncio
async def test_protected_literal_is_omitted_from_all_report_formats(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
        _probe(
            require_denial=True,
            confidentiality={"values": [MARKER]},
        ),
    )
    guard._identity_positive_controls[("lookup", "user")] = True

    async def observed(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del test_id, identity_name, identity, tool, arguments
        return (
            _invocation(
                allowed=False,
                authorization=AuthorizationStatus.DENY,
                execution=ExecutionStatus.REJECTED,
                response={"payload": {"protected": MARKER}},
                error=f"backend diagnostic included {MARKER}",
            ),
            [],
            ObservationStatus.NOT_REQUIRED,
            {},
        )

    guard._invoke_with_mutation_observation = observed  # type: ignore[method-assign]

    try:
        await guard._check_tenant_isolation()
        finding = next(item for item in guard.findings if item.test_id == "TENANT-LOOKUP-USER")
        assert MARKER not in str(finding.model_dump(mode="json"))

        summary = RunSummary(
            run_id=guard.run_id,
            target=guard.contract.server.target_label,
            contract_path="contract.yaml",
            started_at="start",
            finished_at="finish",
            findings=guard.findings,
            invocations=guard.invocations,
        )
        assert summary.schema_version == 2

        report_dir = tmp_path / "exports"
        paths = write_reports(
            summary,
            report_dir,
            ["json", "html", "junit", "sarif"],
        )
        assert {item.name for item in paths} == {
            "report.json",
            "index.html",
            "junit.xml",
            "results.sarif",
        }
        for item in paths:
            assert MARKER not in item.read_text(encoding="utf-8")
    finally:
        store.close()


def test_protected_literal_is_redacted_from_trace_error_and_response(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
        _probe(
            require_denial=True,
            confidentiality={"values": [MARKER]},
        ),
    )
    try:
        guard._record_invocation(
            _invocation(
                allowed=False,
                authorization=AuthorizationStatus.DENY,
                execution=ExecutionStatus.REJECTED,
                response={"payload": {"protected": MARKER}},
                error=f"backend diagnostic included {MARKER}",
            )
        )
        trace = guard.trace_path.read_text(encoding="utf-8")
        assert MARKER not in trace
    finally:
        store.close()


def test_assertion_evidence_exports_only_finite_safe_outcomes() -> None:
    from mcp_behaviour_guard.evidence import redact

    safe = redact(
        {
            "authorization_assertion": "passed",
            "ownership_assertion": "failed",
            "confidentiality_assertion": "not_asserted",
        }
    )
    assert safe["authorization_assertion"] == "passed"
    assert safe["ownership_assertion"] == "failed"
    assert safe["confidentiality_assertion"] == "not_asserted"

    unsafe = redact(
        {
            "authorization_assertion": "opaque-auth-material-123456",
            "ownership_assertion": {"unexpected": "object"},
            "confidentiality_assertion": "unexpected-state",
        }
    )
    assert unsafe["authorization_assertion"] == "[redacted]"
    assert unsafe["ownership_assertion"] == "[redacted]"
    assert unsafe["confidentiality_assertion"] == "[redacted]"
