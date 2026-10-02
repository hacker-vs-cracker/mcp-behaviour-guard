from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
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


def test_database_write_in_final_snapshot_is_always_a_confirmed_violation() -> None:
    gate = _gate_module()
    snapshot = {
        "attempt_id": "attempt",
        "state": "FENCED",
        "audit_complete": True,
        "final_watermark": 1,
        "requests": [{"request_id": "write-1", "state": "COMMITTED"}],
        "audit": [
            {
                "seq": 1,
                "kind": "database_write",
                "request_id": "write-1",
            }
        ],
    }
    violations, invalid, review = gate._validate_snapshot(snapshot, "attempt")
    assert len(violations) == 1
    assert invalid == []
    assert review == []


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
