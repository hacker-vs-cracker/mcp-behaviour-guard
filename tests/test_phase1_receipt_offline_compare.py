from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mcp_behaviour_guard.baseline as baseline_module
import mcp_behaviour_guard.cli as cli_module
import mcp_behaviour_guard.runner as runner_module
from mcp_behaviour_guard import __version__
from mcp_behaviour_guard.cli import app
from mcp_behaviour_guard.models import Contract, Finding, FindingStatus, RunSummary, Severity


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _finding(
    test_id: str,
    status: str,
    *,
    observation: str = "not_required",
    severity: str | None = None,
) -> dict[str, Any]:
    if severity is None:
        severity = {
            "failed": "high",
            "error": "medium",
            "passed": "info",
            "skipped": "info",
        }[status]
    return {
        "test_id": test_id,
        "category": "synthetic",
        "title": test_id,
        "status": status,
        "severity": severity,
        "expected": {"assertion": True},
        "observed": {"assertion": status},
        "evidence": {},
        "remediation": None,
        "observation": observation,
    }


def _assessment(findings: list[dict[str, Any]]) -> str:
    statuses = [item["status"] for item in findings]
    if "failed" in statuses:
        return "fail"
    if "error" in statuses:
        return "inconclusive"
    if "skipped" in statuses:
        return "not_tested"
    if "passed" not in statuses:
        return "not_tested"
    return "pass"


def _write_saved_run(
    root: Path,
    findings: list[dict[str, Any]],
    *,
    logical_target: str = "target-a",
    contract_sha: str = "contract-a",
    target_input_sha: str = "target-input-a",
    policy_sha: str = "policy-a",
    identity_sha: str = "identity-a",
    observer_sha: str = "observer-a",
    definition_sha: str = "definition-a",
    lab_mode: bool = False,
    deployment_identity: str | None = None,
    credential_principal: str | None = None,
    runner_version: str = "0.5.0",
    sdk_version: str = "1.28.1",
    state_strategy: str = "stdio_process",
    normalization_version: int = 2,
    tools: list[dict[str, Any]] | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if tools is None:
        tools = [{"name": "lookup", "inputSchema": {"type": "object"}}]
    tool_inventory_path = root / "tool-inventory.json"
    tool_inventory_path.write_text(json.dumps(tools, indent=2), encoding="utf-8")

    report = {
        "schema_version": 2,
        "run_id": root.name,
        "target": logical_target,
        "contract_path": "contract.yaml",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "findings": findings,
        "invocations": [],
        "transport": "stdio",
        "sdk_version": sdk_version,
        "state_strategy": state_strategy,
        "assessment": _assessment(findings),
    }
    report_path = root / "report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    receipt = {
        "schema_version": 1,
        "normalization_version": normalization_version,
        "normalization": {"unverified_sensitive_fields": []},
        "report_schema_version": 2,
        "run": {
            "run_id": root.name,
            "attempt_id": None,
            "started_at": report["started_at"],
            "finished_at": report["finished_at"],
            "completion": "completed",
        },
        "context": {
            "logical_target": logical_target,
            "deployment_identity": deployment_identity,
            "credential_principal": credential_principal,
            "contract_source_sha256": contract_sha,
            "target_input_sha256": target_input_sha,
            "effective_policy_sha256": policy_sha,
            "identity_profile_sha256": identity_sha,
            "observer_scope_sha256": observer_sha,
            "fixture_profile": {"lab_mode": lab_mode},
        },
        "runner": {
            "version": runner_version,
            "mcp_sdk_version": sdk_version,
            "transport": "stdio",
            "state_strategy": state_strategy,
            "protocol_versions": None,
        },
        "checks": {
            "finding_ids": sorted(item["test_id"] for item in findings),
            "definition_sha256": definition_sha,
        },
        "artifacts": {
            "report_json_sha256": _sha256(report_path),
            "tool_inventory_sha256": _sha256(tool_inventory_path),
        },
    }
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return root


def _compare_saved_runs(reference: Path, candidate: Path) -> dict[str, Any]:
    compare = getattr(baseline_module, "compare_saved_runs", None)
    if compare is None:
        pytest.fail("Phase 1 compare_saved_runs API is not implemented")
    return compare(reference, candidate)


def _comparison_error_type() -> type[Exception]:
    error_type = getattr(baseline_module, "SavedRunComparisonError", None)
    if error_type is None:
        pytest.fail("Phase 1 SavedRunComparisonError API is not implemented")
    return error_type


def _contract(
    secret: str,
    *,
    role: str = "reviewer",
    approval_required: bool = False,
    url: str = "http://127.0.0.1:8000/mcp",
    identity_name: str = "reviewer",
    tool_name: str = "lookup",
    observer_url: str | None = None,
    tenant_probe_denial: bool | None = None,
) -> Contract:
    tool: dict[str, Any] = {
        "permitted_identities": [identity_name],
        "read_only": True,
        "approval_required": approval_required,
    }
    if tenant_probe_denial is not None:
        tool["tenant_probes"] = {
            identity_name: {
                "arguments": {"resource_id": "foreign-resource"},
                "require_denial": tenant_probe_denial,
            }
        }

    payload: dict[str, Any] = {
        "version": 1,
        "server": {
            "name": "synthetic",
            "url": url,
        },
        "identities": {
            identity_name: {
                "headers": {
                    "Authorization": f"Bearer {secret}",
                },
                "role": role,
            }
        },
        "tools": {
            tool_name: tool,
        },
    }
    if observer_url is not None:
        payload["observers"] = {
            "credential_audit": {
                "type": "http_audit",
                "events_url": f"{observer_url}/events",
                "reset_url": f"{observer_url}/reset",
                "observes": ["database_write"],
            }
        }

    return Contract.model_validate(payload)


def _summary(target: str, contract_path: Path) -> RunSummary:
    return RunSummary(
        run_id="run-1",
        target=target,
        contract_path=str(contract_path),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        findings=[
            Finding(
                test_id="AUTH-SYNTHETIC",
                category="authorization",
                title="synthetic authorization",
                status=FindingStatus.PASSED,
                severity=Severity.INFO,
                expected={"allowed": True},
                observed={"allowed": True},
            )
        ],
        invocations=[],
        transport="streamable-http",
        sdk_version="1.28.1",
        state_strategy="legacy_session",
    )


async def _run_synthetic_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    secret: str,
    output_name: str,
    role: str = "reviewer",
    approval_required: bool = False,
    url: str = "http://127.0.0.1:8000/mcp",
    identity_name: str = "reviewer",
    tool_name: str = "lookup",
    observer_url: str | None = None,
    tenant_probe_denial: bool | None = None,
) -> tuple[Path, Path]:
    contract = _contract(
        secret,
        role=role,
        approval_required=approval_required,
        url=url,
        identity_name=identity_name,
        tool_name=tool_name,
        observer_url=observer_url,
        tenant_probe_denial=tenant_probe_denial,
    )
    contract_path = tmp_path / "contract.yaml"
    if not contract_path.exists():
        contract_path.write_text(
            """version: 1
server:
  name: synthetic
  url: http://127.0.0.1:8000/mcp
identities:
  reviewer:
    headers:
      Authorization: ${SYNTHETIC_TOKEN}
tools: {}
""",
            encoding="utf-8",
        )

    monkeypatch.setattr(runner_module, "load_contract", lambda _: contract)
    monkeypatch.setattr(runner_module, "validate_target", lambda *_args, **_kwargs: None)

    class FakeEngine:
        def __init__(
            self,
            loaded_contract: Contract,
            loaded_contract_path: Path,
            _store: Any,
            output: Path,
            _lab_mode: bool,
        ) -> None:
            self.run_dir = Path(output) / "run-1"
            self._summary = _summary(
                loaded_contract.server.target_label,
                loaded_contract_path,
            )

        async def run(self) -> RunSummary:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            (self.run_dir / "tool-inventory.json").write_text(
                json.dumps(
                    [{"name": "lookup", "inputSchema": {"type": "object"}}],
                    indent=2,
                ),
                encoding="utf-8",
            )
            return self._summary

    monkeypatch.setattr(runner_module, "GuardEngine", FakeEngine)

    result = await runner_module.run_contract(
        contract_path,
        output=tmp_path / output_name,
        database=tmp_path / f"{output_name}.db",
        lab_mode=False,
    )
    return result.run_dir, contract_path


@pytest.mark.asyncio
async def test_run_contract_emits_external_receipt_without_changing_report_v2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir, contract_path = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="phase1-super-secret",
        output_name="reports-a",
    )

    report_path = run_dir / "report.json"
    receipt_path = run_dir / "receipt.json"

    assert receipt_path.exists()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    receipt_text = receipt_path.read_text(encoding="utf-8")
    receipt = json.loads(receipt_text)

    assert report["schema_version"] == 2
    assert receipt["schema_version"] == 1
    assert receipt["normalization_version"] == 2
    assert receipt["report_schema_version"] == 2
    assert receipt["run"]["run_id"] == "run-1"
    assert receipt["run"]["completion"] == "completed"
    assert receipt["run"]["attempt_id"] is None
    assert receipt["context"]["logical_target"] == "http://127.0.0.1:8000"
    assert receipt["context"]["deployment_identity"] is None
    assert receipt["context"]["credential_principal"] is None
    assert receipt["context"]["contract_source_sha256"] == _sha256(contract_path)
    assert receipt["context"]["effective_policy_sha256"]
    assert receipt["context"]["identity_profile_sha256"]
    assert receipt["context"]["observer_scope_sha256"]
    assert receipt["context"]["fixture_profile"] == {"lab_mode": False}
    assert receipt["runner"]["version"] == __version__
    assert receipt["runner"]["mcp_sdk_version"] == "1.28.1"
    assert receipt["runner"]["transport"] == "streamable-http"
    assert receipt["runner"]["state_strategy"] == "legacy_session"
    assert receipt["runner"]["protocol_versions"] is None
    assert receipt["checks"]["finding_ids"] == ["AUTH-SYNTHETIC"]
    assert receipt["checks"]["definition_sha256"]
    assert receipt["artifacts"]["report_json_sha256"] == _sha256(report_path)
    assert receipt["artifacts"]["tool_inventory_sha256"] == _sha256(run_dir / "tool-inventory.json")
    assert "phase1-super-secret" not in receipt_text
    assert str(tmp_path) not in receipt_text


@pytest.mark.asyncio
async def test_receipt_policy_and_identity_digests_ignore_secret_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="secret-a",
        output_name="reports-a",
    )
    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))

    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="secret-b",
        output_name="reports-b",
    )
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["effective_policy_sha256"]
        == receipt_b["context"]["effective_policy_sha256"]
    )
    assert (
        receipt_a["context"]["identity_profile_sha256"]
        == receipt_b["context"]["identity_profile_sha256"]
    )


@pytest.mark.asyncio
async def test_receipt_policy_digest_changes_for_non_secret_policy_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="reports-a",
        approval_required=False,
    )
    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))

    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="reports-b",
        approval_required=True,
    )
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["effective_policy_sha256"]
        != receipt_b["context"]["effective_policy_sha256"]
    )
    assert receipt_a["checks"]["definition_sha256"] != receipt_b["checks"]["definition_sha256"]


@pytest.mark.asyncio
async def test_receipt_identity_digest_changes_for_non_secret_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="reports-a",
        role="reviewer",
    )
    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))

    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="reports-b",
        role="administrator",
    )
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["identity_profile_sha256"]
        != receipt_b["context"]["identity_profile_sha256"]
    )


def test_offline_compare_is_deterministic_and_preserves_unknown_context(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])

    first = _compare_saved_runs(reference, candidate)
    second = _compare_saved_runs(reference, candidate)

    assert first == second
    assert first["schema_version"] == 1
    assert first["normalization_version"] == 2
    assert first["inputs"]["reference"]["receipt_sha256"] == _sha256(reference / "receipt.json")
    assert first["inputs"]["candidate"]["receipt_sha256"] == _sha256(candidate / "receipt.json")
    assert first["comparability"]["state"] == "comparable"
    assert first["comparability"]["reasons"] == []
    assert first["comparability"]["input_changes"] == []
    assert "context.deployment_identity" in first["comparability"]["unknown_fields"]
    assert "context.credential_principal" in first["comparability"]["unknown_fields"]
    assert first["conformance"] == {"reference": "pass", "candidate": "pass"}
    assert first["regression"]["new_failures"] == []
    assert first["coverage"]["missing_checks"] == []
    assert first["freshness"] == {"reference": "unknown", "candidate": "unknown"}


def test_unchanged_failure_is_not_a_new_regression_but_candidate_still_fails(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("TENANT-X", "failed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("TENANT-X", "failed")])

    result = _compare_saved_runs(reference, candidate)

    assert result["conformance"]["candidate"] == "fail"
    assert result["regression"]["new_failures"] == []
    assert result["regression"]["persistent_failures"] == ["TENANT-X"]
    assert result["regression"]["has_new_regression"] is False


def test_pass_to_fail_is_a_new_regression(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "failed")])

    result = _compare_saved_runs(reference, candidate)

    assert result["regression"]["new_failures"] == ["AUTH-X"]
    assert result["regression"]["has_new_regression"] is True
    assert result["conformance"]["candidate"] == "fail"


def test_fail_to_pass_is_fixed_only_when_the_check_is_present(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "failed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])

    result = _compare_saved_runs(reference, candidate)

    assert result["regression"]["fixed_failures"] == ["AUTH-X"]
    assert result["coverage"]["missing_checks"] == []


def test_missing_failed_check_is_lost_coverage_not_a_fix(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "failed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("OTHER", "passed")])

    result = _compare_saved_runs(reference, candidate)

    assert result["regression"]["fixed_failures"] == []
    assert result["coverage"]["missing_checks"] == ["AUTH-X"]
    assert result["coverage"]["new_checks"] == ["OTHER"]


def test_skipped_candidate_check_is_coverage_loss_not_a_fix(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "skipped")])

    result = _compare_saved_runs(reference, candidate)

    assert result["regression"]["fixed_failures"] == []
    assert result["coverage"]["skipped_checks"] == ["AUTH-X"]
    assert result["conformance"]["candidate"] == "not_tested"


def test_contract_source_change_is_input_change_not_automatic_incomparability(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        contract_sha="contract-a",
        policy_sha="policy-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        contract_sha="contract-b",
        policy_sha="policy-a",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "comparable"
    assert result["comparability"]["input_changes"] == ["context.contract_source_sha256"]


def test_policy_change_is_explicit_changed_context(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        policy_sha="policy-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        policy_sha="policy-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "changed_context"
    assert "context.effective_policy_sha256" in result["comparability"]["reasons"]


def test_different_logical_target_is_unsupported(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        logical_target="target-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        logical_target="target-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "unsupported"
    assert "context.logical_target" in result["comparability"]["reasons"]


def test_finding_order_is_semantic_noise(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-A", "passed"), _finding("AUTH-B", "failed")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-B", "failed"), _finding("AUTH-A", "passed")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["regression"]["new_failures"] == []
    assert result["regression"]["fixed_failures"] == []
    assert result["regression"]["persistent_failures"] == ["AUTH-B"]
    assert result["coverage"]["missing_checks"] == []
    assert result["coverage"]["new_checks"] == []


def test_offline_compare_never_recaptures_or_contacts_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])

    async def forbidden_capture(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("offline comparison attempted live baseline capture")

    monkeypatch.setattr(baseline_module, "capture_baseline", forbidden_capture)

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "comparable"


def test_report_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    (candidate / "report.json").write_text("{}\n", encoding="utf-8")

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match="digest"):
        _compare_saved_runs(reference, candidate)


def test_unsupported_normalization_version_is_rejected(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        normalization_version=999,
    )

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match="normalization"):
        _compare_saved_runs(reference, candidate)


def test_error_transition_is_explicit_regression_not_a_fix(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed", observation="complete")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "error", observation="partial")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["conformance"]["candidate"] == "inconclusive"
    assert result["regression"]["new_errors"] == ["AUTH-X"]
    assert result["regression"]["fixed_failures"] == []
    assert result["coverage"]["observation_changes"] == [
        {"test_id": "AUTH-X", "before": "complete", "after": "partial"}
    ]


def test_observation_degradation_does_not_erase_confirmed_failure(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("TENANT-X", "failed", observation="complete")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("TENANT-X", "failed", observation="partial")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["conformance"]["candidate"] == "fail"
    assert result["regression"]["persistent_failures"] == ["TENANT-X"]
    assert result["coverage"]["observation_changes"] == [
        {"test_id": "TENANT-X", "before": "complete", "after": "partial"}
    ]


def test_severity_change_is_reported_without_reordering_noise(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "failed", severity="high")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed", severity="critical")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["regression"]["severity_changes"] == [
        {"test_id": "AUTH-X", "before": "high", "after": "critical"}
    ]
    assert result["regression"]["persistent_failures"] == ["AUTH-X"]


def test_known_credential_principal_change_is_unsupported(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        credential_principal="principal-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        credential_principal="principal-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "unsupported"
    assert "context.credential_principal" in result["comparability"]["reasons"]


def test_saved_tool_inventory_reports_added_removed_and_schema_changes(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        tools=[
            {"name": "lookup", "inputSchema": {"type": "object"}},
            {"name": "legacy", "inputSchema": {"type": "object"}},
        ],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        tools=[
            {
                "name": "lookup",
                "inputSchema": {
                    "type": "object",
                    "properties": {"tenant": {"type": "string"}},
                },
            },
            {"name": "admin", "inputSchema": {"type": "object"}},
        ],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["capabilities"]["added_tools"] == ["admin"]
    assert result["capabilities"]["removed_tools"] == ["legacy"]
    assert sorted(result["capabilities"]["changed_tool_schemas"]) == ["lookup"]


def test_tool_inventory_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    (candidate / "tool-inventory.json").write_text("[]\n", encoding="utf-8")

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match="digest"):
        _compare_saved_runs(reference, candidate)


def test_receipt_check_membership_must_match_report(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    receipt_path = candidate / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["checks"]["finding_ids"] = ["DIFFERENT-CHECK"]
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match="finding|check|membership"):
        _compare_saved_runs(reference, candidate)


def test_duplicate_finding_ids_are_rejected(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed"), _finding("AUTH-X", "failed")],
    )

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match="duplicate"):
        _compare_saved_runs(reference, candidate)


def test_baseline_compare_saved_cli_is_offline_and_writes_machine_readable_diff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "failed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "failed")])
    output = tmp_path / "saved-run-diff.json"

    async def forbidden_async(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("compare-saved attempted live execution")

    def forbidden_sync(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("compare-saved attempted contract/credential loading")

    monkeypatch.setattr(cli_module, "capture_baseline", forbidden_async)
    monkeypatch.setattr(cli_module, "run_contract", forbidden_async)
    monkeypatch.setattr(cli_module, "load_contract", forbidden_sync)

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["conformance"]["candidate"] == "fail"
    assert payload["regression"]["has_new_regression"] is False
    assert payload["regression"]["persistent_failures"] == ["AUTH-X"]


def _drop_tool_inventory(root: Path) -> None:
    receipt_path = root / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["artifacts"]["tool_inventory_sha256"] = None
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    (root / "tool-inventory.json").unlink()


def test_new_failing_check_is_first_assessment_not_established_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed"), _finding("AUTH-NEW", "failed")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["conformance"]["candidate"] == "fail"
    assert result["coverage"]["new_checks"] == ["AUTH-NEW"]
    assert result["regression"]["new_failures"] == []
    assert result["regression"]["has_new_regression"] is False


def test_new_error_check_is_first_assessment_not_established_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed"), _finding("AUTH-NEW", "error")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["conformance"]["candidate"] == "inconclusive"
    assert result["coverage"]["new_checks"] == ["AUTH-NEW"]
    assert result["regression"]["new_errors"] == []
    assert result["regression"]["has_new_regression"] is False


def test_policy_changed_pass_to_fail_is_transition_not_established_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        policy_sha="policy-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed")],
        policy_sha="policy-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "changed_context"
    assert result["regression"]["status_changes"] == [
        {"test_id": "AUTH-X", "before": "passed", "after": "failed"}
    ]
    assert result["regression"]["new_failures"] == []
    assert result["regression"]["has_new_regression"] is False


def test_unsupported_target_transition_is_not_established_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        logical_target="target-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed")],
        logical_target="target-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "unsupported"
    assert result["regression"]["status_changes"] == [
        {"test_id": "AUTH-X", "before": "passed", "after": "failed"}
    ]
    assert result["regression"]["new_failures"] == []
    assert result["regression"]["has_new_regression"] is False


def test_missing_candidate_tool_inventory_is_coverage_loss_not_tool_removal(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
    )
    _drop_tool_inventory(candidate)

    result = _compare_saved_runs(reference, candidate)

    assert result["capabilities"]["comparison_state"] == "unavailable"
    assert result["capabilities"]["reference_inventory_available"] is True
    assert result["capabilities"]["candidate_inventory_available"] is False
    assert result["capabilities"]["added_tools"] == []
    assert result["capabilities"]["removed_tools"] == []
    assert result["capabilities"]["changed_tool_schemas"] == {}
    assert result["coverage"]["capability_inventory_regression"] is True
    assert result["coverage"]["regression"] is True


def test_missing_reference_tool_inventory_does_not_infer_added_tools(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
    )
    _drop_tool_inventory(reference)

    result = _compare_saved_runs(reference, candidate)

    assert result["capabilities"]["comparison_state"] == "unavailable"
    assert result["capabilities"]["reference_inventory_available"] is False
    assert result["capabilities"]["candidate_inventory_available"] is True
    assert result["capabilities"]["added_tools"] == []
    assert result["capabilities"]["removed_tools"] == []
    assert result["capabilities"]["changed_tool_schemas"] == {}
    assert result["coverage"]["capability_inventory_regression"] is False


def test_changed_context_fail_to_pass_is_not_established_fix(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "failed")],
        policy_sha="policy-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        policy_sha="policy-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "changed_context"
    assert result["regression"]["status_changes"] == [
        {"test_id": "AUTH-X", "before": "failed", "after": "passed"}
    ]
    assert result["regression"]["fixed_failures"] == []


def test_changed_context_failure_is_not_classified_as_persistent_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "failed")],
        policy_sha="policy-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed")],
        policy_sha="policy-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "changed_context"
    assert result["conformance"]["candidate"] == "fail"
    assert result["regression"]["persistent_failures"] == []


def test_unsupported_error_to_pass_is_not_established_resolution(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "error")],
        logical_target="target-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        logical_target="target-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "unsupported"
    assert result["regression"]["status_changes"] == [
        {"test_id": "AUTH-X", "before": "error", "after": "passed"}
    ]
    assert result["regression"]["resolved_errors"] == []


def test_changed_context_severity_escalation_is_not_established_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "failed", severity="high")],
        policy_sha="policy-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed", severity="critical")],
        policy_sha="policy-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "changed_context"
    assert result["regression"]["severity_escalations"] == [
        {"test_id": "AUTH-X", "before": "high", "after": "critical"}
    ]
    assert result["regression"]["has_new_regression"] is False


def test_skipped_to_failed_is_current_failure_not_established_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "skipped")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "comparable"
    assert result["conformance"]["candidate"] == "fail"
    assert result["regression"]["status_changes"] == [
        {"test_id": "AUTH-X", "before": "skipped", "after": "failed"}
    ]
    assert result["regression"]["new_failures"] == []
    assert result["regression"]["has_new_regression"] is False


def test_error_to_failed_is_current_failure_not_established_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "error")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "comparable"
    assert result["conformance"]["candidate"] == "fail"
    assert result["regression"]["status_changes"] == [
        {"test_id": "AUTH-X", "before": "error", "after": "failed"}
    ]
    assert result["regression"]["new_failures"] == []
    assert result["regression"]["has_new_regression"] is False


def test_pass_to_error_is_coverage_regression_not_established_security_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "error")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["conformance"]["candidate"] == "inconclusive"
    assert result["regression"]["new_errors"] == ["AUTH-X"]
    assert result["regression"]["has_new_regression"] is False
    assert result["coverage"]["regression"] is True


def test_severity_escalation_on_persistent_failure_is_not_new_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "failed", severity="high")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed", severity="critical")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["regression"]["persistent_failures"] == ["AUTH-X"]
    assert result["regression"]["severity_escalations"] == [
        {"test_id": "AUTH-X", "before": "high", "after": "critical"}
    ]
    assert result["regression"]["has_new_regression"] is False


def test_compare_saved_cli_blocks_changed_context_even_when_candidate_passes(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        policy_sha="policy-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        policy_sha="policy-b",
    )
    output = tmp_path / "changed-context.json"

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["comparability"]["state"] == "changed_context"
    assert payload["conformance"]["candidate"] == "pass"


def test_compare_saved_cli_blocks_capability_change_for_review(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        tools=[{"name": "lookup", "inputSchema": {"type": "object"}}],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        tools=[
            {"name": "lookup", "inputSchema": {"type": "object"}},
            {"name": "admin", "inputSchema": {"type": "object"}},
        ],
    )
    output = tmp_path / "capability-change.json"

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["capabilities"]["added_tools"] == ["admin"]
    assert payload["capabilities"]["review_required"] is True


def test_compare_saved_cli_clean_comparable_pass_returns_zero(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
    )
    output = tmp_path / "clean.json"

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["comparability"]["state"] == "comparable"
    assert payload["conformance"]["candidate"] == "pass"
    assert payload["regression"]["has_new_regression"] is False
    assert payload["coverage"]["regression"] is False
    assert payload["capabilities"]["review_required"] is False


def test_compare_saved_cli_unsupported_context_returns_two(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        logical_target="target-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        logical_target="target-b",
    )
    output = tmp_path / "unsupported.json"

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["comparability"]["state"] == "unsupported"


@pytest.mark.asyncio
async def test_receipt_separates_target_input_from_effective_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="target-a",
        url="http://127.0.0.1:8000/v1",
    )
    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))

    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="target-b",
        url="http://127.0.0.1:8000/v2",
    )
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert receipt_a["context"]["logical_target"] == receipt_b["context"]["logical_target"]
    assert (
        receipt_a["context"]["target_input_sha256"] != receipt_b["context"]["target_input_sha256"]
    )
    assert (
        receipt_a["context"]["effective_policy_sha256"]
        == receipt_b["context"]["effective_policy_sha256"]
    )


@pytest.mark.asyncio
async def test_target_input_digest_ignores_secret_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="secret-a",
        output_name="secret-a",
    )
    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="secret-b",
        output_name="secret-b",
    )

    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["target_input_sha256"] == receipt_b["context"]["target_input_sha256"]
    )


def test_target_input_change_is_explicit_input_not_context_change(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        target_input_sha="target-v1",
        policy_sha="same-policy",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        target_input_sha="target-v2",
        policy_sha="same-policy",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "comparable"
    assert result["comparability"]["reasons"] == []
    assert result["comparability"]["input_changes"] == ["context.target_input_sha256"]


def test_missing_required_policy_identity_is_rejected(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    receipt_path = candidate / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    del receipt["context"]["effective_policy_sha256"]
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    error_type = _comparison_error_type()
    with pytest.raises(
        error_type, match="receipt.*effective_policy_sha256|effective_policy_sha256"
    ):
        _compare_saved_runs(reference, candidate)


def test_missing_explicit_unknown_context_field_is_rejected(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    receipt_path = candidate / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    del receipt["context"]["deployment_identity"]
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match="receipt.*deployment_identity|deployment_identity"):
        _compare_saved_runs(reference, candidate)


def test_missing_required_runner_identity_is_rejected(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    receipt_path = candidate / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    del receipt["runner"]["version"]
    receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match="receipt.*version|runner.version"):
        _compare_saved_runs(reference, candidate)


@pytest.mark.asyncio
async def test_sensitive_named_identity_preserves_non_secret_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="identity-a",
        identity_name="invalid_token",
        role="reviewer",
    )
    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="identity-b",
        identity_name="invalid_token",
        role="administrator",
    )

    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["identity_profile_sha256"]
        != receipt_b["context"]["identity_profile_sha256"]
    )
    assert (
        receipt_a["context"]["effective_policy_sha256"]
        != receipt_b["context"]["effective_policy_sha256"]
    )
    assert receipt_a["checks"]["definition_sha256"] != receipt_b["checks"]["definition_sha256"]


@pytest.mark.asyncio
async def test_sensitive_named_identity_still_ignores_secret_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="secret-a",
        output_name="secret-a",
        identity_name="invalid_token",
        role="reviewer",
    )
    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="secret-b",
        output_name="secret-b",
        identity_name="invalid_token",
        role="reviewer",
    )

    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["identity_profile_sha256"]
        == receipt_b["context"]["identity_profile_sha256"]
    )
    assert (
        receipt_a["context"]["effective_policy_sha256"]
        == receipt_b["context"]["effective_policy_sha256"]
    )
    assert receipt_a["checks"]["definition_sha256"] == receipt_b["checks"]["definition_sha256"]


@pytest.mark.asyncio
async def test_sensitive_named_tool_preserves_policy_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="tool-a",
        tool_name="credential_export",
        approval_required=False,
    )
    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="tool-b",
        tool_name="credential_export",
        approval_required=True,
    )

    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["effective_policy_sha256"]
        != receipt_b["context"]["effective_policy_sha256"]
    )
    assert receipt_a["checks"]["definition_sha256"] != receipt_b["checks"]["definition_sha256"]


@pytest.mark.asyncio
async def test_sensitive_named_observer_preserves_observer_scope_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="observer-a",
        observer_url="http://127.0.0.1:8101",
    )
    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="observer-b",
        observer_url="http://127.0.0.1:8102",
    )

    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["observer_scope_sha256"]
        != receipt_b["context"]["observer_scope_sha256"]
    )
    assert (
        receipt_a["context"]["effective_policy_sha256"]
        != receipt_b["context"]["effective_policy_sha256"]
    )


@pytest.mark.asyncio
async def test_sensitive_named_tenant_probe_preserves_check_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_a, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="tenant-a",
        identity_name="invalid_token",
        tenant_probe_denial=True,
    )
    run_b, _ = await _run_synthetic_contract(
        tmp_path,
        monkeypatch,
        secret="same-secret",
        output_name="tenant-b",
        identity_name="invalid_token",
        tenant_probe_denial=False,
    )

    receipt_a = json.loads((run_a / "receipt.json").read_text(encoding="utf-8"))
    receipt_b = json.loads((run_b / "receipt.json").read_text(encoding="utf-8"))

    assert (
        receipt_a["context"]["effective_policy_sha256"]
        != receipt_b["context"]["effective_policy_sha256"]
    )
    assert receipt_a["checks"]["definition_sha256"] != receipt_b["checks"]["definition_sha256"]


# ---- Phase 1B.1 B1/B3 acceptance freeze ----


def _phase1b1_load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _phase1b1_write(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _phase1b1_set_runner_and_report(
    run_dir: Path,
    *,
    receipt_field: str,
    report_field: str,
    receipt_value: Any,
    report_value: Any,
) -> None:
    report_path = run_dir / "report.json"
    receipt_path = run_dir / "receipt.json"
    report = _phase1b1_load(report_path)
    receipt = _phase1b1_load(receipt_path)
    report[report_field] = report_value
    _phase1b1_write(report_path, report)
    receipt["runner"][receipt_field] = receipt_value
    receipt["artifacts"]["report_json_sha256"] = _sha256(report_path)
    _phase1b1_write(receipt_path, receipt)


def _phase1b1_set_receipt_value(
    run_dir: Path,
    section: str,
    field: str,
    value: Any,
) -> None:
    receipt_path = run_dir / "receipt.json"
    receipt = _phase1b1_load(receipt_path)
    receipt[section][field] = value
    _phase1b1_write(receipt_path, receipt)


@pytest.mark.parametrize(
    ("receipt_field", "report_field", "receipt_value", "report_value"),
    [
        pytest.param("mcp_sdk_version", "sdk_version", None, "1.28.1", id="sdk-null-known"),
        pytest.param("mcp_sdk_version", "sdk_version", "1.28.1", None, id="sdk-known-null"),
        pytest.param("mcp_sdk_version", "sdk_version", "1.28.1", "9.9.9", id="sdk-different"),
        pytest.param("transport", "transport", None, "stdio", id="transport-null-known"),
        pytest.param("transport", "transport", "stdio", None, id="transport-known-null"),
        pytest.param(
            "transport",
            "transport",
            "stdio",
            "streamable-http",
            id="transport-different",
        ),
        pytest.param(
            "state_strategy",
            "state_strategy",
            None,
            "stdio_process",
            id="state-null-known",
        ),
        pytest.param(
            "state_strategy",
            "state_strategy",
            "stdio_process",
            None,
            id="state-known-null",
        ),
        pytest.param(
            "state_strategy",
            "state_strategy",
            "stdio_process",
            "legacy_session",
            id="state-different",
        ),
    ],
)
def test_phase1b1_receipt_report_runner_mismatch_is_invalid(
    tmp_path: Path,
    receipt_field: str,
    report_field: str,
    receipt_value: Any,
    report_value: Any,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    _phase1b1_set_runner_and_report(
        candidate,
        receipt_field=receipt_field,
        report_field=report_field,
        receipt_value=receipt_value,
        report_value=report_value,
    )

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match=receipt_field):
        _compare_saved_runs(reference, candidate)


@pytest.mark.parametrize(
    ("section", "field", "report_field"),
    [
        pytest.param("context", "deployment_identity", None, id="deployment"),
        pytest.param("context", "credential_principal", None, id="principal"),
        pytest.param("runner", "mcp_sdk_version", "sdk_version", id="sdk"),
        pytest.param("runner", "transport", "transport", id="transport"),
        pytest.param("runner", "state_strategy", "state_strategy", id="state"),
    ],
)
@pytest.mark.parametrize("value", ["", "   "], ids=["empty", "whitespace"])
def test_phase1b1_nullable_known_strings_reject_blank_values(
    tmp_path: Path,
    section: str,
    field: str,
    report_field: str | None,
    value: str,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])

    if report_field is None:
        _phase1b1_set_receipt_value(candidate, section, field, value)
    else:
        _phase1b1_set_runner_and_report(
            candidate,
            receipt_field=field,
            report_field=report_field,
            receipt_value=value,
            report_value=value,
        )

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match=field):
        _compare_saved_runs(reference, candidate)


@pytest.mark.parametrize(
    "protocol_versions",
    [
        pytest.param([], id="empty-list"),
        pytest.param([""], id="blank-entry"),
        pytest.param(["   "], id="whitespace-entry"),
        pytest.param(["2025-03-26", "2025-03-26"], id="duplicate"),
        pytest.param(["2025-03-26", "2024-11-05"], id="noncanonical-order"),
        pytest.param(["2025-03-26", 7], id="non-string-entry"),
    ],
)
def test_phase1b1_protocol_versions_require_null_or_canonical_nonempty_list(
    tmp_path: Path,
    protocol_versions: list[Any],
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    _phase1b1_set_receipt_value(
        candidate,
        "runner",
        "protocol_versions",
        protocol_versions,
    )

    error_type = _comparison_error_type()
    with pytest.raises(error_type, match="protocol_versions"):
        _compare_saved_runs(reference, candidate)


def test_phase1b1_protocol_versions_accept_canonical_known_list(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    canonical = ["2024-11-05", "2025-03-26"]
    _phase1b1_set_receipt_value(reference, "runner", "protocol_versions", canonical)
    _phase1b1_set_receipt_value(candidate, "runner", "protocol_versions", canonical)

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "comparable"
    assert "runner.protocol_versions" not in result["comparability"]["unknown_fields"]


@pytest.mark.parametrize(
    ("field", "known_value"),
    [
        pytest.param("deployment_identity", "deployment-a", id="deployment"),
        pytest.param("credential_principal", "principal-a", id="principal"),
    ],
)
@pytest.mark.parametrize(
    "known_on_reference",
    [True, False],
    ids=["known-to-null", "null-to-known"],
)
def test_phase1b1_asymmetric_unknown_identity_is_unsupported(
    tmp_path: Path,
    field: str,
    known_value: str,
    known_on_reference: bool,
) -> None:
    reference_kwargs = {field: known_value} if known_on_reference else {}
    candidate_kwargs = {} if known_on_reference else {field: known_value}
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        **reference_kwargs,
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        **candidate_kwargs,
    )

    result = _compare_saved_runs(reference, candidate)

    dotted = f"context.{field}"
    assert result["comparability"]["state"] == "unsupported"
    assert dotted in result["comparability"]["reasons"]
    assert dotted in result["comparability"]["unknown_fields"]


@pytest.mark.parametrize(
    ("receipt_field", "report_field", "known_value"),
    [
        pytest.param("mcp_sdk_version", "sdk_version", "1.28.1", id="sdk"),
        pytest.param("transport", "transport", "stdio", id="transport"),
        pytest.param("state_strategy", "state_strategy", "stdio_process", id="state"),
    ],
)
@pytest.mark.parametrize(
    "known_on_reference",
    [True, False],
    ids=["known-to-null", "null-to-known"],
)
def test_phase1b1_asymmetric_unknown_runner_context_is_unsupported(
    tmp_path: Path,
    receipt_field: str,
    report_field: str,
    known_value: str,
    known_on_reference: bool,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    unknown_dir = candidate if known_on_reference else reference
    _phase1b1_set_runner_and_report(
        unknown_dir,
        receipt_field=receipt_field,
        report_field=report_field,
        receipt_value=None,
        report_value=None,
    )

    result = _compare_saved_runs(reference, candidate)

    dotted = f"runner.{receipt_field}"
    assert result["comparability"]["state"] == "unsupported"
    assert dotted in result["comparability"]["reasons"]
    assert dotted in result["comparability"]["unknown_fields"]


@pytest.mark.parametrize(
    "known_on_reference",
    [True, False],
    ids=["known-to-null", "null-to-known"],
)
def test_phase1b1_asymmetric_unknown_protocol_versions_is_unsupported(
    tmp_path: Path,
    known_on_reference: bool,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    known_dir = reference if known_on_reference else candidate
    _phase1b1_set_receipt_value(
        known_dir,
        "runner",
        "protocol_versions",
        ["2025-03-26"],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "unsupported"
    assert "runner.protocol_versions" in result["comparability"]["reasons"]
    assert "runner.protocol_versions" in result["comparability"]["unknown_fields"]


@pytest.mark.parametrize(
    ("receipt_field", "report_field"),
    [
        pytest.param("mcp_sdk_version", "sdk_version", id="sdk"),
        pytest.param("transport", "transport", id="transport"),
        pytest.param("state_strategy", "state_strategy", id="state"),
    ],
)
def test_phase1b1_both_unknown_runner_context_remains_explicit(
    tmp_path: Path,
    receipt_field: str,
    report_field: str,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    for run_dir in (reference, candidate):
        _phase1b1_set_runner_and_report(
            run_dir,
            receipt_field=receipt_field,
            report_field=report_field,
            receipt_value=None,
            report_value=None,
        )

    result = _compare_saved_runs(reference, candidate)

    dotted = f"runner.{receipt_field}"
    assert result["comparability"]["state"] == "comparable"
    assert dotted in result["comparability"]["unknown_fields"]


@pytest.mark.parametrize(
    ("receipt_field", "report_field", "candidate_value"),
    [
        pytest.param("mcp_sdk_version", "sdk_version", "1.29.0", id="sdk"),
        pytest.param("transport", "transport", "streamable-http", id="transport"),
        pytest.param("state_strategy", "state_strategy", "legacy_session", id="state"),
    ],
)
def test_phase1b1_known_runner_change_is_changed_context(
    tmp_path: Path,
    receipt_field: str,
    report_field: str,
    candidate_value: str,
) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    _phase1b1_set_runner_and_report(
        candidate,
        receipt_field=receipt_field,
        report_field=report_field,
        receipt_value=candidate_value,
        report_value=candidate_value,
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "changed_context"
    assert f"runner.{receipt_field}" in result["comparability"]["reasons"]


def test_phase1b1_known_protocol_change_is_changed_context(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    _phase1b1_set_receipt_value(
        reference,
        "runner",
        "protocol_versions",
        ["2024-11-05"],
    )
    _phase1b1_set_receipt_value(
        candidate,
        "runner",
        "protocol_versions",
        ["2025-03-26"],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "changed_context"
    assert "runner.protocol_versions" in result["comparability"]["reasons"]


def test_phase1b1_asymmetric_unknown_suppresses_established_regression(
    tmp_path: Path,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        credential_principal="principal-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "failed")],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "unsupported"
    assert result["conformance"]["candidate"] == "fail"
    assert result["regression"]["new_failures"] == []
    assert result["regression"]["has_new_regression"] is False


@pytest.mark.parametrize(
    ("before", "after", "expected_regression"),
    [
        pytest.param("complete", "partial", True, id="complete-partial"),
        pytest.param("complete", "unavailable", True, id="complete-unavailable"),
        pytest.param("complete", "not_required", True, id="complete-not-required"),
        pytest.param("partial", "unavailable", True, id="partial-unavailable"),
        pytest.param("partial", "not_required", True, id="partial-not-required"),
        pytest.param("unavailable", "not_required", True, id="unavailable-not-required"),
        pytest.param("not_required", "not_required", False, id="not-required-same"),
        pytest.param("not_required", "complete", False, id="not-required-complete"),
        pytest.param("not_required", "partial", True, id="not-required-partial"),
        pytest.param("not_required", "unavailable", True, id="not-required-unavailable"),
    ],
)
def test_phase1b1_observation_requirement_transition_matrix(
    tmp_path: Path,
    before: str,
    after: str,
    expected_regression: bool,
) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed", observation=before)],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed", observation=after)],
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "comparable"
    assert result["coverage"]["regression"] is expected_regression
    if before == after:
        assert result["coverage"]["observation_changes"] == []
    else:
        assert result["coverage"]["observation_changes"] == [
            {"test_id": "AUTH-X", "before": before, "after": after}
        ]
    if expected_regression:
        assert result["coverage"]["observation_regressions"] == [
            {"test_id": "AUTH-X", "before": before, "after": after}
        ]
    else:
        assert result["coverage"]["observation_regressions"] == []


def test_phase1b1_cli_invalid_receipt_report_pair_returns_two(tmp_path: Path) -> None:
    reference = _write_saved_run(tmp_path / "reference", [_finding("AUTH-X", "passed")])
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    _phase1b1_set_runner_and_report(
        candidate,
        receipt_field="mcp_sdk_version",
        report_field="sdk_version",
        receipt_value=None,
        report_value="1.28.1",
    )
    output = tmp_path / "invalid-pair.json"

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2, result.output
    assert not output.exists()


def test_phase1b1_cli_asymmetric_unknown_returns_two(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        credential_principal="principal-a",
    )
    candidate = _write_saved_run(tmp_path / "candidate", [_finding("AUTH-X", "passed")])
    output = tmp_path / "unsupported-asymmetric.json"

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["comparability"]["state"] == "unsupported"
    assert "context.credential_principal" in payload["comparability"]["reasons"]


def test_phase1b1_cli_observation_requirement_loss_returns_one(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed", observation="complete")],
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed", observation="not_required")],
    )
    output = tmp_path / "observation-requirement-loss.json"

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["coverage"]["regression"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("deployment_identity", "deployment-a", id="deployment"),
        pytest.param("credential_principal", "principal-a", id="principal"),
    ],
)
def test_phase1b1_known_identity_equal_remains_comparable(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    kwargs = {field: value}
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        **kwargs,
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        **kwargs,
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "comparable"
    assert f"context.{field}" not in result["comparability"]["unknown_fields"]


def test_phase1b1_known_deployment_change_is_unsupported(tmp_path: Path) -> None:
    reference = _write_saved_run(
        tmp_path / "reference",
        [_finding("AUTH-X", "passed")],
        deployment_identity="deployment-a",
    )
    candidate = _write_saved_run(
        tmp_path / "candidate",
        [_finding("AUTH-X", "passed")],
        deployment_identity="deployment-b",
    )

    result = _compare_saved_runs(reference, candidate)

    assert result["comparability"]["state"] == "unsupported"
    assert "context.deployment_identity" in result["comparability"]["reasons"]
