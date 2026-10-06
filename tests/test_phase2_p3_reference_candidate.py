from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
RUNNER = ROOT / "assurance/phase2/run_approval_demo.py"
WORKFLOW = ROOT / ".github/workflows/phase2-p3-reference-candidate.yml"
PROFILE = CI / "p3-runtime-candidate.json"
TRUST = CI / "trust-boundary.json"
P3_SCRIPT = CI / "p3_reference_candidate.py"


def _module():
    spec = importlib.util.spec_from_file_location("p3_reference_candidate_test", P3_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_p3_input_is_exact_accepted_p2_runtime_and_unpromoted() -> None:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    assert profile["status"] == "P3_REFERENCE_CONSTRUCTION_INPUT"
    assert profile["consumable"] is False
    assert profile["platform"] == "linux/amd64"
    assert profile["decision_scope"] == "phase2c_trusted_ci_gate_only"
    assert profile["reference"]["status"] == "UNPROMOTED"
    assert profile["publisher"]["status"] == "UNBOOTSTRAPPED"
    assert profile["proof"]["source_commit"] == "f21f4ef7afc5704eee36df888d7d7fc98e9677b9"
    assert profile["proof"]["source_tree"] == "644285bab85478ef44d609f2f278fee4f335f572"
    assert profile["p2_acceptance"]["native_proof_run_id"] == 37284672075
    assert profile["p2_acceptance"]["native_proof_run_conclusion"] == "success"
    assert profile["p3_reference_construction"]["promotion_enabled"] is False

    for role in ("evaluator", "fixture", "gate", "vertical_candidate", "candidate_probe"):
        ref = profile["images"][role]["execution_ref"]
        assert ref.startswith("ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-")
        assert "@sha256:" in ref
        assert profile["images"][role]["architecture"] == "amd64"


def test_p3_input_validator_rejects_promotion_and_tag_refs(tmp_path: Path) -> None:
    module = _module()
    payload = json.loads(PROFILE.read_text(encoding="utf-8"))

    promoted = json.loads(json.dumps(payload))
    promoted["reference"]["status"] = "PROMOTED"
    path = tmp_path / "promoted.json"
    path.write_text(json.dumps(promoted), encoding="utf-8")
    with pytest.raises(module.P3Error, match="promoted reference"):
        module.validate_input(path)

    tagged = json.loads(json.dumps(payload))
    tagged["images"]["evaluator"]["execution_ref"] = (
        "ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-evaluator:latest"
    )
    path.write_text(json.dumps(tagged), encoding="utf-8")
    with pytest.raises(module.P3Error, match="digest execution ref"):
        module.validate_input(path)

    drifted = json.loads(json.dumps(payload))
    drifted["images"]["evaluator"]["execution_ref"] = (
        "ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-evaluator@sha256:" + ("0" * 64)
    )
    drifted["images"]["evaluator"]["registry_digest"] = "sha256:" + ("0" * 64)
    drifted["images"]["evaluator"]["platform_manifest_digest"] = "sha256:" + ("0" * 64)
    path.write_text(json.dumps(drifted), encoding="utf-8")
    with pytest.raises(module.P3Error, match="inherited runtime differs"):
        module.validate_input(path)


def test_approval_runner_uses_digest_execution_refs_and_binds_selected_images() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert "def _image_ref(" in source
    assert '"execution_ref"' in source
    assert '_image_ref(images, "evaluator")' in source
    assert '_image_ref(images, "fixture")' in source
    assert '_image_ref(images, "gate")' in source
    assert '_image_ref(images, "vertical_candidate")' in source
    assert "selected gate image differs from runtime profile" in source
    assert "selected candidate image differs from runtime profile" in source
    assert '"scope": approval_scope' in source
    assert '"platform": platform' in source
    assert '"decision_scope": decision_scope' in source
    assert '"phase2c_reference_candidate_only"' in source


def test_every_gate_evaluate_call_binds_expected_candidate_mode() -> None:
    tree = ast.parse(RUNNER.read_text(encoding="utf-8"))
    evaluate_argument_lists: list[ast.List] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "_gate_run":
            continue
        keyword = next((item for item in node.keywords if item.arg == "arguments"), None)
        if keyword is None or not isinstance(keyword.value, ast.List) or not keyword.value.elts:
            continue
        first = keyword.value.elts[0]
        if isinstance(first, ast.Constant) and first.value == "evaluate":
            evaluate_argument_lists.append(keyword.value)

    assert len(evaluate_argument_lists) == 3
    for arguments in evaluate_argument_lists:
        flag_positions = [
            index
            for index, item in enumerate(arguments.elts)
            if isinstance(item, ast.Constant) and item.value == "--expected-candidate-mode"
        ]
        assert len(flag_positions) == 1
        position = flag_positions[0]
        assert position + 1 < len(arguments.elts)
        following = arguments.elts[position + 1]
        assert not (
            isinstance(following, ast.Constant)
            and isinstance(following.value, str)
            and following.value.startswith("--")
        )


def test_p3_workflow_is_manual_exact_commit_packages_read_only_and_stops_before_promotion() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "expected_commit:" in text
    assert "EXPECTED_COMMIT: ${{ inputs.expected_commit }}" in text
    assert 'test "$GITHUB_SHA" = "$EXPECTED_COMMIT"' in text
    assert "runs-on: ubuntu-24.04" in text
    assert "packages: read" in text
    assert "packages: write" not in text
    assert "docker push" not in text
    assert "run_approval_demo.py" in text
    assert "p3_reference_candidate.py adjudicate" in text
    assert "trap cleanup_registry_auth EXIT" in text
    assert 'rglob("*.json")' in text
    assert 'rglob("*recovery*.json")' not in text
    assert "finish_only_evidence" in text
    assert "id: cleanup" in text
    assert "CLEANUP_OUTCOME: ${{ steps.cleanup.outcome }}" in text
    assert 'cleanup_problem=runtime_attempted and cleanup!="success"' in text
    assert 'and cleanup=="success"' in text
    assert "docker-baseline-cleanup:" in text
    assert "reference_promotion" not in text
    p3_source = P3_SCRIPT.read_text(encoding="utf-8")
    assert 'row.get("operation") == "record_write"' in p3_source
    assert 'good_decision.get("assessed_outcome")' in p3_source
    assert 'good_decision.get("outcome")' not in p3_source
    gate_source = (ROOT / "assurance/phase2/gate/gate.py").read_text(encoding="utf-8")
    assert '"assessed_outcome": outcome' in gate_source
    assert "gh pr " not in text
    assert "gh api " not in text
    assert "pull_request_target" not in text


def test_trust_boundary_records_p3_construction_without_publisher_or_promotion() -> None:
    boundary = json.loads(TRUST.read_text(encoding="utf-8"))
    p3 = boundary["p3_reference_candidate"]
    assert p3["stage"] == "REFERENCE_CONSTRUCTION_ONLY"
    assert p3["platform"] == "linux/amd64"
    assert p3["packages_permission"] == "read"
    assert p3["promotion_enabled"] is False
    assert p3["publisher_bootstrap_enabled"] is False
    assert p3["ruleset_mutation_enabled"] is False
    consumed = set(boundary["consumed_trusted_inputs"])
    assert {
        ".github/workflows/phase2-p3-reference-candidate.yml",
        "assurance/phase2/ci/p3-runtime-candidate.json",
        "assurance/phase2/ci/p3_reference_candidate.py",
    } <= consumed


def test_committed_bundle_manifest_validation_detects_tamper(tmp_path: Path) -> None:
    module = _module()
    bundle = tmp_path / "completed" / "candidate-good"
    bundle.mkdir(parents=True)
    decision = bundle / "decision.json"
    pointer = bundle / "authority-pointer.json"
    decision.write_text('{"assessed_outcome":"PASS"}\n', encoding="utf-8")
    pointer.write_text('{"approval_bundle_digest":"abc"}\n', encoding="utf-8")

    files = {
        decision.name: hashlib.sha256(decision.read_bytes()).hexdigest(),
        pointer.name: hashlib.sha256(pointer.read_bytes()).hexdigest(),
    }
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "files": files,
                "manifest_self_hash": None,
            }
        ),
        encoding="utf-8",
    )
    module._validate_committed_bundle(bundle)

    decision.write_text('{"assessed_outcome":"BLOCK"}\n', encoding="utf-8")
    with pytest.raises(module.P3Error, match="manifest hash mismatch"):
        module._validate_committed_bundle(bundle)


def _sha_test(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json_test(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _refresh_manifest_test(bundle: Path) -> None:
    files = {
        path.name: _sha_test(path)
        for path in sorted(bundle.iterdir())
        if path.is_file() and path.name != "manifest.json"
    }
    _write_json_test(
        bundle / "manifest.json",
        {"schema_version": 1, "files": files, "manifest_self_hash": None},
    )


def _decision_test(
    outcome: str,
    *,
    authority_binding: str = "valid",
    subject_binding: str = "valid",
    evidence_completeness: str = "complete",
    authority_errors: list[str] | None = None,
    binding_errors: list[str] | None = None,
    completion_errors: list[str] | None = None,
    review_reasons: list[str] | None = None,
    confirmed_violations: list[dict[str, str]] | None = None,
    source_validation: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "assessed_outcome": outcome,
        "authority_binding": authority_binding,
        "subject_binding": subject_binding,
        "source_validation": source_validation or {},
        "confirmed_violations": confirmed_violations or [],
        "evidence_completeness": evidence_completeness,
        "attempt_completion": "finalized",
        "authority_errors": authority_errors or [],
        "binding_errors": binding_errors or [],
        "completion_errors": completion_errors or [],
        "review_reasons": review_reasons or [],
        "freshness_basis": "test fixture",
        "scope": "phase2c_trusted_ci_gate_only",
    }


def _build_q2_full_matrix(tmp_path: Path):
    module = _module()
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    output = tmp_path / "output"
    result = tmp_path / "p3-result.json"

    policy_path = output / "policy-profile.json"
    policy = {
        "platform": "linux/amd64",
        "decision_scope": "phase2c_trusted_ci_gate_only",
        "contract_sha256": _sha_test(ROOT / "assurance/phase2/vertical/contract.yaml"),
        "expected_checks_sha256": _sha_test(ROOT / "assurance/phase2/gate/expected-checks.json"),
        "gate_rules_sha256": _sha_test(ROOT / "assurance/phase2/gate/gate-rules.json"),
        "gate_source_sha256": _sha_test(ROOT / "assurance/phase2/gate/gate.py"),
        "orchestrator_sha256": _sha_test(RUNNER),
        "runtime_profile_sha256": _sha_test(PROFILE),
        "fixture_profile_sha256": _sha_test(ROOT / "assurance/phase2/fixture-profile.json"),
        "images": {
            "evaluator": profile["images"]["evaluator"]["execution_ref"],
            "fixture": profile["images"]["fixture"]["execution_ref"],
            "gate": profile["images"]["gate"]["execution_ref"],
        },
    }
    _write_json_test(policy_path, policy)
    policy_digest = _sha_test(policy_path)

    reference_id = "reference-attempt"
    ref_root = output / "evidence" / "reference"
    for name, value in {
        "report.json": {"schema_version": 2},
        "receipt.json": {"schema_version": 1},
        "tool-inventory.json": {"tools": []},
    }.items():
        _write_json_test(ref_root / "run" / name, value)
    _write_json_test(
        ref_root / "execution-context.json",
        {
            "attempt_id": reference_id,
            "candidate_mode": "good",
            "attempt_completion": "finalized",
            "cleanup_complete": True,
            "platform": "linux/amd64",
            "candidate_image": profile["images"]["vertical_candidate"]["execution_ref"],
            "evaluator_image": profile["images"]["evaluator"]["execution_ref"],
            "fixture_image": profile["images"]["fixture"]["execution_ref"],
            "gate_image": profile["images"]["gate"]["execution_ref"],
        },
    )
    _write_json_test(
        ref_root / "final-snapshot.json",
        {
            "state": "FENCED",
            "audit_complete": True,
            "requests": [{"state": "COMMITTED"}],
        },
    )
    _write_json_test(ref_root / "finalize-response.json", {"state": "FINALIZED"})

    authority = output / "authority" / "approval-bundle.json"
    approval = {
        "schema_version": 1,
        "policy_profile_digest": policy_digest,
        "reference": {
            "origin_attempt_id": reference_id,
            "candidate_image": profile["images"]["vertical_candidate"]["execution_ref"],
            "manifest": {
                "report_json_sha256": _sha_test(ref_root / "run" / "report.json"),
                "receipt_json_sha256": _sha_test(ref_root / "run" / "receipt.json"),
                "tool_inventory_sha256": _sha_test(ref_root / "run" / "tool-inventory.json"),
                "execution_context_sha256": _sha_test(ref_root / "execution-context.json"),
                "final_snapshot_sha256": _sha_test(ref_root / "final-snapshot.json"),
            },
        },
    }
    _write_json_test(authority, approval)
    approval_digest = _sha_test(authority)
    _write_json_test(
        output / "authority" / "approval-bundle.json.meta.json",
        {"approval_bundle_sha256": approval_digest},
    )

    candidate_ids = {
        "candidate-good": "candidate-good-attempt",
        "candidate-write": "candidate-write-attempt",
        "candidate-review": "candidate-review-attempt",
        "candidate-missing": "candidate-missing-attempt",
    }
    summary_path = output / "approval-summary.json"
    _write_json_test(
        summary_path,
        {
            "schema_version": 1,
            "scope": "phase2c_reference_candidate_only",
            "platform": "linux/amd64",
            "decision_scope": "phase2c_trusted_ci_gate_only",
            "runtime_profile_sha256": _sha_test(PROFILE),
            "policy_profile_digest": policy_digest,
            "approval_bundle_digest": approval_digest,
            "reference_attempt_id": reference_id,
            "candidate_attempt_ids": candidate_ids,
            "outcomes": dict(module.EXPECTED_OUTCOMES),
        },
    )

    write_final = {
        "audit_complete": True,
        "requests": [{"request_id": "write-1", "state": "COMMITTED"}],
        "audit": [{"request_id": "write-1", "operation": "record_write"}],
    }
    _write_json_test(output / "evidence" / "candidate-write" / "final-snapshot.json", write_final)

    decisions = {
        "candidate-good": _decision_test("PASS"),
        "candidate-write": _decision_test(
            "BLOCK", confirmed_violations=[{"operation": "record_write"}]
        ),
        "candidate-review": _decision_test(
            "REVIEW", review_reasons=["structured review condition"]
        ),
        "candidate-missing": _decision_test(
            "INVALID",
            evidence_completeness="invalid",
            completion_errors=["structured incomplete evidence"],
        ),
        "tampered-context": _decision_test(
            "INVALID",
            subject_binding="invalid",
            binding_errors=["structured binding invalidity"],
        ),
        "swapped-run": _decision_test(
            "INVALID",
            source_validation={
                "guard_report": {
                    "binding": "invalid",
                    "validation": "invalid",
                    "errors": ["structured source mismatch"],
                }
            },
        ),
        "stale-attempt": _decision_test(
            "INVALID",
            subject_binding="invalid",
            binding_errors=["structured stale attempt binding"],
        ),
        "tampered-approval": _decision_test(
            "INVALID",
            authority_binding="invalid",
            authority_errors=["structured authority invalidity"],
        ),
    }

    completed = output / "results" / "completed"
    for case, decision in decisions.items():
        bundle = completed / case
        bundle.mkdir(parents=True)
        _write_json_test(bundle / "decision.json", decision)
        _write_json_test(
            bundle / "authority-pointer.json",
            {
                "approval_bundle_digest": approval_digest,
                "policy_profile_digest": policy_digest,
            },
        )
        if case in candidate_ids:
            _write_json_test(
                bundle / "execution-context.json",
                {"attempt_id": candidate_ids[case]},
            )
        if case == "candidate-write":
            _write_json_test(bundle / "final-snapshot.json", write_final)
        _write_json_test(bundle / "comparator.json", {})
        _refresh_manifest_test(bundle)

    _write_json_test(
        output / "gate-resource-ledger.json",
        {
            "cleanup_complete": True,
            "finish_only_recovery_required": False,
            "committed_pass_permitted": True,
        },
    )
    return module, output, result, summary_path, reference_id


def _rewrite_bundle_json_test(bundle: Path, name: str, mutate) -> None:
    path = bundle / name
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    _write_json_test(path, value)
    _refresh_manifest_test(bundle)


def test_q2_composed_full_matrix_adjudicates_complete_committed_evidence(tmp_path: Path) -> None:
    module, output, result, _, _ = _build_q2_full_matrix(tmp_path)
    adjudicated = module.adjudicate(
        repo=ROOT,
        profile_path=PROFILE,
        output_dir=output,
        result=result,
    )
    assert adjudicated["status"] == "P3_REFERENCE_CANDIDATE_VALID"
    assert adjudicated["actual_gate_pass"] is True


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing-negative-bundle", "case set mismatch"),
        ("unexpected-extra-bundle", "case set mismatch"),
        ("changed-negative-decision", "outcome mismatch"),
        ("corrupted-negative-file", "manifest hash mismatch"),
        ("wrong-authority-pointer", "wrong approval authority"),
        ("wrong-policy-pointer", "wrong policy"),
        ("duplicate-primary-attempt", "not unique"),
        ("primary-attempt-equals-reference", "not distinct"),
        ("missing-primary-mapping", "mapping mismatch"),
        ("extra-primary-mapping", "mapping mismatch"),
        ("summary-decision-mismatch", "outcome mismatch"),
        ("missing-review-reason", "structured review cause"),
        ("missing-candidate-missing-reason", "structured invalid evidence"),
        ("missing-tampered-context-reason", "subject/binding invalidity"),
        ("missing-swapped-run-reason", "structural mismatch evidence"),
        ("missing-stale-attempt-reason", "attempt/binding invalidity"),
        ("missing-tampered-approval-reason", "authority invalidity"),
        ("primary-context-mismatch", "attempt binding mismatch"),
        ("committed-write-positive-control-missing", "committed bundle lacks matching"),
    ],
)
def test_q2_composed_full_matrix_rejects_invalid_committed_evidence(
    tmp_path: Path, mutation: str, message: str
) -> None:
    module, output, result, summary_path, reference_id = _build_q2_full_matrix(tmp_path / mutation)
    completed = output / "results" / "completed"

    if mutation == "missing-negative-bundle":
        shutil.rmtree(completed / "candidate-review")
    elif mutation == "unexpected-extra-bundle":
        (completed / "unexpected").mkdir()
    elif mutation == "changed-negative-decision":
        _rewrite_bundle_json_test(
            completed / "tampered-context",
            "decision.json",
            lambda value: value.__setitem__("assessed_outcome", "PASS"),
        )
    elif mutation == "corrupted-negative-file":
        path = completed / "candidate-review" / "decision.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["review_reasons"] = ["corrupted without manifest refresh"]
        _write_json_test(path, value)
    elif mutation == "wrong-authority-pointer":
        _rewrite_bundle_json_test(
            completed / "candidate-review",
            "authority-pointer.json",
            lambda value: value.__setitem__("approval_bundle_digest", "0" * 64),
        )
    elif mutation == "wrong-policy-pointer":
        _rewrite_bundle_json_test(
            completed / "candidate-review",
            "authority-pointer.json",
            lambda value: value.__setitem__("policy_profile_digest", "0" * 64),
        )
    elif mutation in {
        "duplicate-primary-attempt",
        "primary-attempt-equals-reference",
        "missing-primary-mapping",
        "extra-primary-mapping",
    }:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        mapping = summary["candidate_attempt_ids"]
        if mutation == "duplicate-primary-attempt":
            mapping["candidate-review"] = mapping["candidate-good"]
        elif mutation == "primary-attempt-equals-reference":
            mapping["candidate-review"] = reference_id
        elif mutation == "missing-primary-mapping":
            mapping.pop("candidate-review")
        else:
            mapping["tampered-context"] = "unexpected-attempt"
        _write_json_test(summary_path, summary)
    elif mutation == "summary-decision-mismatch":
        _rewrite_bundle_json_test(
            completed / "candidate-review",
            "decision.json",
            lambda value: value.__setitem__("assessed_outcome", "BLOCK"),
        )
    elif mutation == "missing-review-reason":
        _rewrite_bundle_json_test(
            completed / "candidate-review",
            "decision.json",
            lambda value: value.__setitem__("review_reasons", []),
        )
    elif mutation == "missing-candidate-missing-reason":

        def clear_candidate_missing(value):
            value["evidence_completeness"] = "complete"
            value["completion_errors"] = []
            value["source_validation"] = {}

        _rewrite_bundle_json_test(
            completed / "candidate-missing",
            "decision.json",
            clear_candidate_missing,
        )
    elif mutation == "missing-tampered-context-reason":

        def clear_tampered_context(value):
            value["subject_binding"] = "valid"
            value["binding_errors"] = []

        _rewrite_bundle_json_test(
            completed / "tampered-context",
            "decision.json",
            clear_tampered_context,
        )
    elif mutation == "missing-swapped-run-reason":

        def clear_swapped_run(value):
            value["subject_binding"] = "valid"
            value["binding_errors"] = []
            value["evidence_completeness"] = "complete"
            value["completion_errors"] = []
            value["source_validation"] = {}

        _rewrite_bundle_json_test(
            completed / "swapped-run",
            "decision.json",
            clear_swapped_run,
        )
    elif mutation == "missing-stale-attempt-reason":

        def clear_stale_attempt(value):
            value["subject_binding"] = "valid"
            value["binding_errors"] = []

        _rewrite_bundle_json_test(
            completed / "stale-attempt",
            "decision.json",
            clear_stale_attempt,
        )
    elif mutation == "missing-tampered-approval-reason":

        def clear_tampered_approval(value):
            value["authority_binding"] = "valid"
            value["authority_errors"] = []

        _rewrite_bundle_json_test(
            completed / "tampered-approval",
            "decision.json",
            clear_tampered_approval,
        )
    elif mutation == "primary-context-mismatch":
        _rewrite_bundle_json_test(
            completed / "candidate-good",
            "execution-context.json",
            lambda value: value.__setitem__("attempt_id", "wrong-attempt"),
        )
    elif mutation == "committed-write-positive-control-missing":

        def clear_committed_write(value):
            value["requests"] = []
            value["audit"] = []
            value["audit_complete"] = True

        _rewrite_bundle_json_test(
            completed / "candidate-write",
            "final-snapshot.json",
            clear_committed_write,
        )
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(module.P3Error, match=message):
        module.adjudicate(
            repo=ROOT,
            profile_path=PROFILE,
            output_dir=output,
            result=result,
        )
