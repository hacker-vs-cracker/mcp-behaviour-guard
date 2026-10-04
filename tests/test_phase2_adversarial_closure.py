from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STORE_PATH = PROJECT_ROOT / "assurance/phase2/fixture/store.py"
GATE_PATH = PROJECT_ROOT / "assurance/phase2/gate/gate.py"
PROFILE_PATH = PROJECT_ROOT / "assurance/phase2/fixture-profile.json"
CANDIDATE_PATH = PROJECT_ROOT / "assurance/phase2/vertical/candidate_server.py"
RUNNER_PATH = PROJECT_ROOT / "assurance/phase2/run_adversarial_closure.py"


def _store_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "phase2_fixture_store_adversarial_test", STORE_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Phase 2 fixture store module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_STORE = _store_module()
FixtureStore = _STORE.FixtureStore
StaleCredential = _STORE.StaleCredential


def _gate_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase2_gate_adversarial_test", GATE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Phase 2 gate module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _base_report() -> dict[str, Any]:
    required = {
        "INVENTORY-001": "not_required",
        "AUTH-LOOKUP-RECORD-REVIEWER": "complete",
        "AUTH-LOOKUP-RECORD-ANONYMOUS": "complete",
        "BEHAVIOUR-LOOKUP-RECORD": "complete",
    }
    return {
        "findings": [
            {
                "test_id": test_id,
                "status": "passed",
                "observation": observation,
            }
            for test_id, observation in required.items()
        ]
    }


def test_restart_marks_active_attempt_recovery_required_and_trusted_abort_revokes_it(
    tmp_path: Path,
) -> None:
    db = tmp_path / "fixture.db"
    first = FixtureStore(db)
    first.bootstrap()
    credential = first.create_attempt("orphan")
    first.open_attempt("orphan")
    first.business_write(
        credential.token,
        record_id="record",
        value="before-crash",
        request_id="committed-before-crash",
    )

    restarted = FixtureStore(db)
    restarted.bootstrap()
    snapshot = restarted.snapshot("orphan")
    assert snapshot["attempt"]["state"] == "RECOVERY_REQUIRED"
    assert len(snapshot["audit"]) == 1

    rejected = restarted.business_write(
        credential.token,
        record_id="record",
        value="must-not-commit",
        request_id="after-restart",
    )
    assert rejected.committed is False
    assert rejected.state == "REJECTED"

    restarted.abort_recovery("orphan")
    assert restarted.snapshot("orphan")["attempt"]["state"] == "ABORTED"
    assert restarted.active_attempt_id() is None

    replacement = restarted.create_attempt("replacement")
    restarted.open_attempt("replacement")
    with pytest.raises(StaleCredential):
        restarted.business_write(
            credential.token,
            record_id="record",
            value="stale",
            request_id="stale-token",
        )
    restarted.close_attempt("replacement")
    final = restarted.final_snapshot("replacement")
    assert final["audit"] == []
    restarted.finalize_attempt("replacement")
    assert replacement.token != credential.token


def test_fixture_profile_freezes_fail_closed_restart_recovery() -> None:
    payload = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    assert payload["profile_id"] == "phase2-fixture-v2"
    assert payload["restart_recovery"] == {
        "active_nonterminal_on_bootstrap": "RECOVERY_REQUIRED",
        "resume_allowed": False,
        "trusted_abort_required": True,
        "old_credentials_after_abort": "stale",
    }


def test_gate_binds_execution_platform_to_selected_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _gate_module()
    monkeypatch.setattr(
        gate,
        "_manifest_for_run",
        lambda _root: {
            "report_json_sha256": "report",
            "receipt_json_sha256": "receipt",
            "tool_inventory_sha256": "inventory",
        },
    )
    monkeypatch.setattr(gate, "_sha", lambda _path: "final")

    context = {
        "schema_version": 1,
        "policy_profile_digest": "policy",
        "attempt_id": "attempt",
        "candidate_image": "candidate-image",
        "candidate_mode": "good",
        "orchestrator_sha256": "orchestrator",
        "subject_binding": "valid",
        "gate_image": "gate-image",
        "evaluator_image": "evaluator-image",
        "fixture_image": "fixture-image",
        "logical_candidate_origin": "http://candidate:7000",
        "logical_control_origin": "http://fixture-control:9000",
        "logical_fixture_app_origin": "http://fixture-app:8001",
        "report_json_sha256": "report",
        "receipt_json_sha256": "receipt",
        "tool_inventory_sha256": "inventory",
        "final_snapshot_sha256": "final",
        "platform": "linux/amd64",
    }
    policy = {
        "platform": "linux/arm64",
        "orchestrator_sha256": "orchestrator",
        "images": {
            "gate": "gate-image",
            "evaluator": "evaluator-image",
            "fixture": "fixture-image",
        },
    }
    errors = gate._validate_context_files(
        context=context,
        context_path=Path("context.json"),
        run_dir=Path("run"),
        final_path=Path("final.json"),
        policy_digest="policy",
        policy=policy,
        expected_attempt_id="attempt",
        expected_candidate_image="candidate-image",
        expected_candidate_mode="good",
    )
    assert "execution context platform differs from selected policy" in errors


def test_gate_missing_trusted_artifact_raises_gate_error(tmp_path: Path) -> None:
    gate = _gate_module()
    with pytest.raises(gate.GateError, match="cannot hash trusted artifact"):
        gate._sha(tmp_path / "missing.json")


def test_unexpected_and_conditional_findings_follow_frozen_gate_semantics() -> None:
    gate = _gate_module()

    report = _base_report()
    report["findings"].append(
        {
            "test_id": "UNEXPECTED-PASSED",
            "status": "passed",
            "observation": "not_required",
        }
    )
    assessment = gate._matrix(report)
    assert not assessment.block
    assert not assessment.invalid
    assert assessment.review == ("unexpected finding requires review: UNEXPECTED-PASSED",)

    report = _base_report()
    report["findings"].append(
        {
            "test_id": "UNEXPECTED-FAILED",
            "status": "failed",
            "observation": "complete",
        }
    )
    assessment = gate._matrix(report)
    assert "unexpected current-contract failure: UNEXPECTED-FAILED" in assessment.block

    report = _base_report()
    report["findings"].append(
        {
            "test_id": "AUTH-LOOKUP-RECORD-REVIEWER-EFFECTS",
            "status": "error",
            "observation": "unavailable",
        }
    )
    assessment = gate._matrix(report)
    assert any("conditional effect finding is incomplete" in item for item in assessment.invalid)


def _valid_write_snapshot(
    *,
    attempt_id: str = "attempt",
    audit_complete: bool = True,
) -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "state": "FENCED",
        "audit_complete": audit_complete,
        "final_watermark": 1,
        "requests": [
            {
                "attempt_id": attempt_id,
                "request_id": "write-1",
                "operation": "record_write",
                "state": "COMMITTED",
            }
        ],
        "audit": [
            {
                "seq": 1,
                "event_id": "event-1",
                "kind": "database_write",
                "request_id": "write-1",
                "operation": "record_write",
                "principal": "candidate_app",
            }
        ],
    }


def _clean_snapshot(*, attempt_id: str = "attempt") -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "state": "FENCED",
        "audit_complete": True,
        "final_watermark": 0,
        "requests": [],
        "audit": [],
    }


def test_database_write_requires_valid_snapshot_attribution() -> None:
    gate = _gate_module()
    assessment = gate._validate_snapshot(_valid_write_snapshot(), "attempt")
    assert len(assessment.violations) == 1
    assert assessment.attribution_invalid == ()
    assert assessment.completion_invalid == ()
    assert assessment.review == ()

    assessment = gate._validate_snapshot(_valid_write_snapshot(attempt_id="other"), "attempt")
    assert assessment.violations == ()
    assert "final snapshot attempt_id mismatch" in assessment.attribution_invalid


def test_snapshot_rejects_malformed_identity_and_bool_integer_fields() -> None:
    gate = _gate_module()

    unknown_state = _valid_write_snapshot()
    unknown_state["requests"][0]["state"] = "BROKEN_STATE"
    assessment = gate._validate_snapshot(unknown_state, "attempt")
    assert assessment.violations == ()
    assert any(
        "request state is missing/invalid" in item for item in assessment.attribution_invalid
    )

    missing_state = _valid_write_snapshot()
    del missing_state["requests"][0]["state"]
    assessment = gate._validate_snapshot(missing_state, "attempt")
    assert assessment.violations == ()
    assert any(
        "request state is missing/invalid" in item for item in assessment.attribution_invalid
    )

    bool_watermark = _clean_snapshot()
    bool_watermark["final_watermark"] = True
    assessment = gate._validate_snapshot(bool_watermark, "attempt")
    assert assessment.violations == ()
    assert "final audit watermark is not a non-negative integer" in assessment.attribution_invalid

    bool_seq = _valid_write_snapshot()
    bool_seq["audit"][0]["seq"] = True
    assessment = gate._validate_snapshot(bool_seq, "attempt")
    assert assessment.violations == ()
    assert "audit event sequence is invalid" in assessment.attribution_invalid

    duplicate = _valid_write_snapshot()
    duplicate["final_watermark"] = 2
    duplicate["audit"].append(
        {
            "seq": 2,
            "event_id": "event-1",
            "kind": "database_write",
            "request_id": "write-2",
            "operation": "record_write",
            "principal": "candidate_app",
        }
    )
    duplicate["requests"].append(
        {
            "attempt_id": "attempt",
            "request_id": "write-2",
            "operation": "record_write",
            "state": "COMMITTED",
        }
    )
    assessment = gate._validate_snapshot(duplicate, "attempt")
    assert assessment.violations == ()
    assert "duplicate audit event_id: event-1" in assessment.attribution_invalid

    duplicate_request = _valid_write_snapshot()
    duplicate_request["requests"].append(dict(duplicate_request["requests"][0]))
    assessment = gate._validate_snapshot(duplicate_request, "attempt")
    assert assessment.violations == ()
    assert "duplicate request_id: write-1" in assessment.attribution_invalid


def test_confirmed_write_survives_completion_failure() -> None:
    gate = _gate_module()
    assessment = gate._validate_snapshot(
        _valid_write_snapshot(audit_complete=False),
        "attempt",
    )
    assert len(assessment.violations) == 1
    assert assessment.attribution_invalid == ()
    assert "audit_complete is not true" in assessment.completion_invalid


def test_rejected_request_is_review_not_committed_violation() -> None:
    gate = _gate_module()
    snapshot = _clean_snapshot()
    snapshot["requests"] = [
        {
            "attempt_id": "attempt",
            "request_id": "rejected-1",
            "operation": "record_write",
            "state": "REJECTED",
        }
    ]
    assessment = gate._validate_snapshot(snapshot, "attempt")
    assert assessment.violations == ()
    assert assessment.attribution_invalid == ()
    assert assessment.completion_invalid == ()
    assert assessment.review == ("trusted fixture rejected request: rejected-1",)


def _evaluate_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    snapshot: dict[str, Any],
    report_mode: str = "valid",
    report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gate = _gate_module()
    candidate_dir = tmp_path / "candidate"
    candidate_dir.mkdir()
    final_path = tmp_path / "final.json"
    final_path.write_text(json.dumps(snapshot), encoding="utf-8")

    receipt_path = candidate_dir / "receipt.json"
    inventory_path = candidate_dir / "tool-inventory.json"
    receipt_path.write_text("{}\n", encoding="utf-8")
    inventory_path.write_text("{}\n", encoding="utf-8")

    report_path = candidate_dir / "report.json"
    if report_mode == "valid":
        report_path.write_text(json.dumps(report or _base_report()), encoding="utf-8")
    elif report_mode == "malformed":
        report_path.write_text("{not-json", encoding="utf-8")
    elif report_mode != "missing":
        raise AssertionError(f"unknown report_mode: {report_mode}")

    policy = {
        "platform": "linux/arm64",
        "orchestrator_sha256": "orchestrator",
        "images": {
            "gate": "gate-image",
            "evaluator": "evaluator-image",
            "fixture": "fixture-image",
        },
    }
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(
        json.dumps(
            {
                "policy_profile_digest": "policy",
                "reference": {
                    "origin_attempt_id": "reference-attempt",
                    "compatibility": {},
                },
            }
        ),
        encoding="utf-8",
    )

    context = {
        "schema_version": 1,
        "policy_profile_digest": "policy",
        "platform": "linux/arm64",
        "attempt_id": "attempt",
        "candidate_image": "candidate-image",
        "candidate_mode": "good",
        "orchestrator_sha256": "orchestrator",
        "subject_binding": "valid",
        "gate_image": "gate-image",
        "evaluator_image": "evaluator-image",
        "fixture_image": "fixture-image",
        "logical_candidate_origin": "http://candidate:7000",
        "logical_control_origin": "http://fixture-control:9000",
        "logical_fixture_app_origin": "http://fixture-app:8001",
        "report_json_sha256": gate._sha(report_path) if report_path.exists() else "0" * 64,
        "receipt_json_sha256": gate._sha(receipt_path),
        "tool_inventory_sha256": gate._sha(inventory_path),
        "final_snapshot_sha256": gate._sha(final_path),
        "attempt_completion": "finalized",
        "cleanup_complete": True,
    }
    context_path = tmp_path / "context.json"
    context_path.write_text(json.dumps(context), encoding="utf-8")

    comparator = {
        "comparability": {"state": "comparable"},
        "conformance": {"candidate": "pass"},
        "regression": {"new_failures": [], "new_errors": []},
        "coverage": {"regression": False},
        "capabilities": {"review_required": False},
    }
    monkeypatch.setattr(gate, "_validate_policy", lambda *_args: (policy, "policy"))
    monkeypatch.setattr(gate, "_verify_reference", lambda **_kwargs: [])
    monkeypatch.setattr(gate, "_receipt_compatibility", lambda _path: {})
    monkeypatch.setattr(gate, "compare_saved_runs", lambda *_args: comparator)

    captured: dict[str, Any] = {}

    def fake_publish(**kwargs: Any) -> Path:
        captured["outcome"] = kwargs["outcome"]
        captured["decision"] = kwargs["decision"]
        return tmp_path / "published"

    monkeypatch.setattr(gate, "_publish", fake_publish)
    args = SimpleNamespace(
        policy=str(tmp_path / "policy.json"),
        approval=str(approval_path),
        selected_approval_digest=gate._sha(approval_path),
        reference_dir=str(tmp_path / "reference"),
        reference_context=str(tmp_path / "reference-context.json"),
        reference_final=str(tmp_path / "reference-final.json"),
        candidate_dir=str(candidate_dir),
        candidate_context=str(context_path),
        candidate_final=str(final_path),
        expected_attempt_id="attempt",
        expected_candidate_image="candidate-image",
        expected_candidate_mode="good",
        selected_gate_image="gate-image",
        result_root=str(tmp_path / "results"),
        result_id="case",
    )
    assert gate._evaluate(args) == 0
    return captured


def test_gate_clean_valid_candidate_can_still_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _evaluate_case(tmp_path, monkeypatch, snapshot=_clean_snapshot())
    assert result["outcome"] == "PASS"


@pytest.mark.parametrize("report_mode", ["missing", "malformed"])
def test_gate_preserves_snapshot_violation_when_report_is_unusable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    report_mode: str,
) -> None:
    result = _evaluate_case(
        tmp_path,
        monkeypatch,
        snapshot=_valid_write_snapshot(),
        report_mode=report_mode,
    )
    assert result["outcome"] == "BLOCK"
    assert result["decision"]["confirmed_violations"]
    assert any("guard_report" in item for item in result["decision"]["completion_errors"])


def test_gate_clean_snapshot_with_missing_report_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _evaluate_case(
        tmp_path,
        monkeypatch,
        snapshot=_clean_snapshot(),
        report_mode="missing",
    )
    assert result["outcome"] == "INVALID"


def test_gate_preserves_guard_violation_when_snapshot_attribution_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _base_report()
    report["findings"][0]["status"] = "failed"
    result = _evaluate_case(
        tmp_path,
        monkeypatch,
        snapshot=_valid_write_snapshot(attempt_id="other-attempt"),
        report=report,
    )
    assert result["outcome"] == "BLOCK"
    assert any(
        item.get("source") == "guard"
        for item in result["decision"]["confirmed_violations"]
        if isinstance(item, dict)
    )
    assert (
        result["decision"]["source_validation"]["final_snapshot"]["validation"]
        == "invalid_attribution"
    )


def test_gate_write_plus_incomplete_audit_is_block_with_completion_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _evaluate_case(
        tmp_path,
        monkeypatch,
        snapshot=_valid_write_snapshot(audit_complete=False),
    )
    assert result["outcome"] == "BLOCK"
    assert any(
        "audit_complete is not true" in item for item in result["decision"]["completion_errors"]
    )


def test_gate_rejected_only_candidate_is_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _clean_snapshot()
    snapshot["requests"] = [
        {
            "attempt_id": "attempt",
            "request_id": "rejected-1",
            "operation": "record_write",
            "state": "REJECTED",
        }
    ]
    result = _evaluate_case(tmp_path, monkeypatch, snapshot=snapshot)
    assert result["outcome"] == "REVIEW"


def test_controller_crash_before_atomic_rename_never_creates_completed_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _gate_module()

    def crash_before_rename(_source: Path, _destination: Path) -> None:
        raise OSError("injected controller crash before publish rename")

    monkeypatch.setattr(os, "rename", crash_before_rename)
    with pytest.raises(OSError, match="injected controller crash"):
        gate._publish(
            result_root=tmp_path,
            result_id="candidate",
            outcome="PASS",
            decision={"assessed_outcome": "PASS"},
            comparator=None,
            candidate_context_path=None,
            candidate_final_path=None,
            candidate_dir=None,
            approval_digest="approval",
            policy_digest="policy",
        )
    assert not (tmp_path / "completed" / "candidate").exists()
    assert any(path.name.startswith(".staging-candidate-") for path in tmp_path.iterdir())


def test_candidate_and_runner_expose_only_bounded_adversarial_controls() -> None:
    candidate = CANDIDATE_PATH.read_text(encoding="utf-8")
    runner = RUNNER_PATH.read_text(encoding="utf-8")
    for mode in ("startup-write", "interprobe-write", "delayed-write", "crash"):
        assert mode in candidate
    assert "/phase2/background/release" in candidate
    assert "/phase2/state" in candidate
    assert "fixture-control" not in candidate
    assert "docker.sock" not in candidate

    for case in ("startup", "interprobe", "delayed", "crash", "recovery"):
        assert f'"{case}"' in runner
    assert "gate_invoked" in runner
    assert "git push" not in runner
    assert "gh api" not in runner


def test_adversarial_runner_commits_real_gate_outcomes_for_selected_cases() -> None:
    runner = RUNNER_PATH.read_text(encoding="utf-8")

    assert '"gate_invoked": True' in runner
    assert "_gate_run(" in runner
    assert "approval-bundle.json" in runner
    assert "actual_gate_outcome" in runner
    assert "source_validation" in runner
    assert "gate-resource-ledger.json" in runner
    assert "phase2c_r3_adversarial_gate_bridge_local_arm64" in runner

    expected_pairs = {
        "startup": "BLOCK",
        "interprobe": "BLOCK",
        "delayed": "BLOCK",
        "crash": "INVALID",
        "recovery": "INVALID",
    }
    for case, outcome in expected_pairs.items():
        assert f'"{case}": "{outcome}"' in runner

    crash_start = runner.index("def _case_crash(")
    recovery_start = runner.index("def _case_recovery(")
    crash_source = runner[crash_start:recovery_start]
    assert "_finalize(" not in crash_source
    assert "preserve_on_failure=True" in crash_source
    assert 'failure_stage="candidate_crash"' in crash_source

    assert "recovery-required-state.json" in runner
    assert "recovery-aborted-state.json" in runner
    assert "recovery-new-attempt-final-snapshot.json" in runner

    assert '"expected_gate_effect": "BLOCK"' in runner
    assert '"expected_gate_effect": "INVALID"' in runner
    assert '"gate_invoked": False' not in runner
