from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_behaviour_guard.baseline import SavedRunComparisonError, compare_saved_runs

HERE = Path(__file__).resolve().parent
EXPECTED_PATH = HERE / "expected-checks.json"
RULES_PATH = HERE / "gate-rules.json"
GATE_PATH = HERE / "gate.py"

OUTCOMES = {"PASS", "BLOCK", "REVIEW", "INVALID"}


class GateError(RuntimeError):
    pass


@dataclass(frozen=True)
class MatrixAssessment:
    block: tuple[str, ...]
    invalid: tuple[str, ...]
    review: tuple[str, ...]


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GateError(f"cannot hash trusted artifact {path}: {exc}") from exc
    return digest.hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"{label} is unreadable/invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"{label} must be a JSON object")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with path.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    _write_json(temp, value)
    os.rename(temp, path)
    _fsync_dir(path.parent)


def _validate_policy(policy_path: Path, selected_gate_image: str) -> tuple[dict[str, Any], str]:
    policy = _load(policy_path, "policy profile")
    if policy.get("schema_version") != 1:
        raise GateError("policy profile schema_version must be 1")
    digest = _sha(policy_path)
    if policy.get("platform") != "linux/arm64":
        raise GateError("policy platform must be linux/arm64")
    images = policy.get("images")
    if not isinstance(images, dict):
        raise GateError("policy images mapping missing")
    if images.get("gate") != selected_gate_image:
        raise GateError("selected gate image does not match policy profile")
    if policy.get("expected_checks_sha256") != _sha(EXPECTED_PATH):
        raise GateError("gate embedded expected-check matrix differs from policy")
    if policy.get("gate_rules_sha256") != _sha(RULES_PATH):
        raise GateError("gate embedded rules differ from policy")
    if policy.get("gate_source_sha256") != _sha(GATE_PATH):
        raise GateError("gate source differs from policy")
    guard = policy.get("guard")
    if not isinstance(guard, dict) or guard.get("version") != "0.6.2":
        raise GateError("policy Guard version is not 0.6.2")
    return policy, digest


def _findings(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = report.get("findings")
    if not isinstance(raw, list):
        raise GateError("report findings missing")
    indexed: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise GateError("report contains non-object finding")
        test_id = item.get("test_id")
        if not isinstance(test_id, str) or not test_id:
            raise GateError("report finding has invalid test_id")
        if test_id in indexed:
            raise GateError(f"duplicate finding id: {test_id}")
        indexed[test_id] = item
    return indexed


def _matrix(report: dict[str, Any]) -> MatrixAssessment:
    expected = _load(EXPECTED_PATH, "embedded expected-check matrix")
    required = expected.get("required_findings")
    suffixes = expected.get("conditional_suffixes")
    if not isinstance(required, dict) or not isinstance(suffixes, list):
        raise GateError("embedded expected-check matrix is malformed")
    findings = _findings(report)

    block: list[str] = []
    invalid: list[str] = []
    review: list[str] = []

    for test_id, rule in required.items():
        finding = findings.get(test_id)
        if finding is None:
            invalid.append(f"missing required finding {test_id}")
            continue
        if not isinstance(rule, dict):
            raise GateError(f"matrix rule for {test_id} is malformed")
        status = finding.get("status")
        observation = finding.get("observation")
        if status == "failed":
            block.append(f"required finding failed: {test_id}")
        elif status != rule.get("status"):
            invalid.append(
                f"required finding status mismatch: {test_id}={status!r}, "
                f"expected {rule.get('status')!r}"
            )
        if observation != rule.get("observation"):
            invalid.append(
                f"required finding observation mismatch: {test_id}={observation!r}, "
                f"expected {rule.get('observation')!r}"
            )

    for test_id, finding in findings.items():
        if test_id in required:
            continue
        conditional = any(test_id.endswith(str(suffix)) for suffix in suffixes)
        status = finding.get("status")
        if conditional:
            if status == "failed":
                block.append(f"conditional effect finding failed: {test_id}")
            elif status in {"error", "skipped"}:
                invalid.append(f"conditional effect finding is incomplete: {test_id}={status}")
            elif status != "passed":
                invalid.append(f"conditional effect finding has unknown status: {test_id}")
            continue

        if status == "failed":
            block.append(f"unexpected current-contract failure: {test_id}")
        elif status in {"error", "skipped"}:
            invalid.append(f"unexpected incomplete finding: {test_id}={status}")
        else:
            review.append(f"unexpected finding requires review: {test_id}")

    return MatrixAssessment(tuple(block), tuple(invalid), tuple(review))


def _validate_snapshot(
    snapshot: dict[str, Any], attempt_id: str
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    invalid: list[str] = []
    review: list[str] = []
    audit = snapshot.get("audit")
    requests = snapshot.get("requests")
    if snapshot.get("attempt_id") != attempt_id:
        invalid.append("final snapshot attempt_id mismatch")
    if not isinstance(audit, list):
        invalid.append("final snapshot audit is not a list")
        audit = []
    if not isinstance(requests, list):
        invalid.append("final snapshot requests is not a list")
        requests = []
    watermark = snapshot.get("final_watermark")
    if not isinstance(watermark, int) or watermark != len(audit):
        invalid.append("final audit watermark is inconsistent")
    if snapshot.get("state") != "FENCED":
        invalid.append(f"final snapshot state is not FENCED: {snapshot.get('state')!r}")

    seqs: list[int] = []
    violations: list[dict[str, Any]] = []
    for item in audit:
        if not isinstance(item, dict):
            invalid.append("audit contains non-object event")
            continue
        seq = item.get("seq")
        if not isinstance(seq, int):
            invalid.append("audit event sequence is invalid")
        else:
            seqs.append(seq)
        if item.get("kind") == "database_write":
            violations.append(item)
    if seqs and seqs != list(range(1, len(seqs) + 1)):
        invalid.append("audit sequence is not contiguous")

    for request in requests:
        if not isinstance(request, dict):
            invalid.append("request ledger contains non-object item")
            continue
        state = request.get("state")
        if state in {"ADMITTED", "RUNNING", "OPEN"}:
            invalid.append(f"request did not reach terminal state: {request.get('request_id')}")
        elif state == "REJECTED":
            review.append(f"trusted fixture rejected request: {request.get('request_id')}")

    if snapshot.get("audit_complete") is not True:
        invalid.append("audit_complete is not true")
    return violations, invalid, review


def _manifest_for_run(run_dir: Path) -> dict[str, Any]:
    report = run_dir / "report.json"
    receipt = run_dir / "receipt.json"
    inventory = run_dir / "tool-inventory.json"
    if not report.is_file() or not receipt.is_file() or not inventory.is_file():
        raise GateError("saved run is missing report.json, receipt.json or tool-inventory.json")
    return {
        "report_json_sha256": _sha(report),
        "receipt_json_sha256": _sha(receipt),
        "tool_inventory_sha256": _sha(inventory),
    }


def _validate_context_files(
    *,
    context: dict[str, Any],
    context_path: Path,
    run_dir: Path,
    final_path: Path,
    policy_digest: str,
    policy: dict[str, Any],
    expected_attempt_id: str | None,
    expected_candidate_image: str | None,
    expected_candidate_mode: str | None,
) -> list[str]:
    errors: list[str] = []
    if context.get("schema_version") != 1:
        errors.append("execution context schema_version is not 1")
    if context.get("policy_profile_digest") != policy_digest:
        errors.append("execution context policy profile digest mismatch")
    if context.get("platform") != policy.get("platform"):
        errors.append("execution context platform differs from selected policy")
    if expected_attempt_id is not None and context.get("attempt_id") != expected_attempt_id:
        errors.append("execution context attempt differs from trusted selected attempt")
    if (
        expected_candidate_image is not None
        and context.get("candidate_image") != expected_candidate_image
    ):
        errors.append("execution context candidate image differs from trusted selected subject")
    if (
        expected_candidate_mode is not None
        and context.get("candidate_mode") != expected_candidate_mode
    ):
        errors.append("execution context candidate mode differs from trusted selected subject")
    if context.get("orchestrator_sha256") != policy.get("orchestrator_sha256"):
        errors.append("execution context orchestrator identity differs from policy")
    if context.get("subject_binding") != "valid":
        errors.append("execution context subject binding is not valid")
    if context.get("gate_image") != policy.get("images", {}).get("gate"):
        errors.append("execution context gate image mismatch")
    if context.get("evaluator_image") != policy.get("images", {}).get("evaluator"):
        errors.append("execution context evaluator image mismatch")
    if context.get("fixture_image") != policy.get("images", {}).get("fixture"):
        errors.append("execution context fixture image mismatch")
    if context.get("logical_candidate_origin") != "http://candidate:7000":
        errors.append("execution context candidate logical origin is unstable/unapproved")
    if context.get("logical_control_origin") != "http://fixture-control:9000":
        errors.append("execution context control logical origin is unstable/unapproved")
    if context.get("logical_fixture_app_origin") != "http://fixture-app:8001":
        errors.append("execution context fixture-app logical origin is unstable/unapproved")

    manifest = _manifest_for_run(run_dir)
    if context.get("report_json_sha256") != manifest["report_json_sha256"]:
        errors.append("execution context report hash mismatch")
    if context.get("receipt_json_sha256") != manifest["receipt_json_sha256"]:
        errors.append("execution context receipt hash mismatch")
    if context.get("tool_inventory_sha256") != manifest["tool_inventory_sha256"]:
        errors.append("execution context inventory hash mismatch")
    if context.get("final_snapshot_sha256") != _sha(final_path):
        errors.append("execution context final snapshot hash mismatch")
    if context.get("execution_context_sha256") not in {None, _sha(context_path)}:
        errors.append("execution context self-digest field is not permitted")
    return errors


def _receipt_compatibility(run_dir: Path) -> dict[str, Any]:
    receipt = _load(run_dir / "receipt.json", "receipt")
    context = receipt.get("context")
    runner = receipt.get("runner")
    checks = receipt.get("checks")
    if not isinstance(context, dict):
        raise GateError("receipt context mapping missing")
    if not isinstance(runner, dict):
        raise GateError("receipt runner mapping missing")
    if not isinstance(checks, dict):
        raise GateError("receipt checks mapping missing")
    return {
        "normalization_version": receipt.get("normalization_version"),
        "report_schema_version": receipt.get("report_schema_version"),
        "contract_source_sha256": context.get("contract_source_sha256"),
        "logical_target": context.get("logical_target"),
        "fixture_profile": context.get("fixture_profile"),
        "effective_policy_sha256": context.get("effective_policy_sha256"),
        "identity_profile_sha256": context.get("identity_profile_sha256"),
        "observer_scope_sha256": context.get("observer_scope_sha256"),
        "target_input_sha256": context.get("target_input_sha256"),
        "checks_definition_sha256": checks.get("definition_sha256"),
        "runner_version": runner.get("version"),
        "mcp_sdk_version": runner.get("mcp_sdk_version"),
        "transport": runner.get("transport"),
        "state_strategy": runner.get("state_strategy"),
        "protocol_versions": runner.get("protocol_versions"),
    }


def _verify_reference(
    *,
    approval: dict[str, Any],
    reference_dir: Path,
    reference_context_path: Path,
    reference_final_path: Path,
) -> list[str]:
    errors: list[str] = []
    reference = approval.get("reference")
    if not isinstance(reference, dict):
        return ["approval bundle reference mapping missing"]
    manifest = reference.get("manifest")
    if not isinstance(manifest, dict):
        return ["approval reference manifest missing"]
    current = _manifest_for_run(reference_dir)
    expected = {
        **current,
        "execution_context_sha256": _sha(reference_context_path),
        "final_snapshot_sha256": _sha(reference_final_path),
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            errors.append(f"approved reference manifest mismatch: {key}")
    return errors


def _promote(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy)
    reference_dir = Path(args.reference_dir)
    context_path = Path(args.reference_context)
    final_path = Path(args.reference_final)
    output = Path(args.output)

    policy, policy_digest = _validate_policy(policy_path, args.selected_gate_image)
    context = _load(context_path, "reference execution context")
    context_errors = _validate_context_files(
        context=context,
        context_path=context_path,
        run_dir=reference_dir,
        final_path=final_path,
        policy_digest=policy_digest,
        policy=policy,
        expected_attempt_id=context.get("attempt_id"),
        expected_candidate_image=context.get("candidate_image"),
        expected_candidate_mode="good",
    )
    if context_errors:
        raise GateError("reference execution context invalid: " + "; ".join(context_errors))
    if context.get("attempt_completion") != "finalized":
        raise GateError("reference attempt is not finalized")
    if context.get("cleanup_complete") is not True:
        raise GateError("reference runtime cleanup is not complete")

    report = _load(reference_dir / "report.json", "reference report")
    if report.get("assessment") != "pass":
        raise GateError("reference report is not PASS")
    matrix = _matrix(report)
    if matrix.block or matrix.invalid or matrix.review:
        raise GateError(
            "reference does not satisfy expected matrix: "
            + "; ".join((*matrix.block, *matrix.invalid, *matrix.review))
        )

    final_snapshot = _load(final_path, "reference final snapshot")
    violations, snapshot_invalid, snapshot_review = _validate_snapshot(
        final_snapshot, str(context.get("attempt_id"))
    )
    if violations or snapshot_invalid or snapshot_review:
        raise GateError("reference final evidence is not approval-clean")

    receipt_compatibility = _receipt_compatibility(reference_dir)
    if receipt_compatibility.get("normalization_version") != 3:
        raise GateError("reference normalization version is not 3")
    if receipt_compatibility.get("report_schema_version") != 2:
        raise GateError("reference report schema version is not 2")
    if receipt_compatibility.get("contract_source_sha256") != policy.get("contract_sha256"):
        raise GateError("reference contract hash differs from selected policy")

    manifest = _manifest_for_run(reference_dir)
    manifest.update(
        {
            "execution_context_sha256": _sha(context_path),
            "final_snapshot_sha256": _sha(final_path),
        }
    )
    bundle = {
        "schema_version": 1,
        "policy_profile_digest": policy_digest,
        "reference": {
            "origin_attempt_id": context.get("attempt_id"),
            "guard_run_id": context.get("guard_run_id"),
            "candidate_image": context.get("candidate_image"),
            "manifest": manifest,
            "compatibility": receipt_compatibility,
        },
    }
    _atomic_json(output, bundle)
    digest = _sha(output)
    _atomic_json(
        output.with_suffix(output.suffix + ".meta.json"),
        {"approval_bundle_sha256": digest},
    )
    print(json.dumps({"approval_bundle_digest": digest, "path": str(output)}, sort_keys=True))
    return 0


def _publish(
    *,
    result_root: Path,
    result_id: str,
    outcome: str,
    decision: dict[str, Any],
    comparator: dict[str, Any] | None,
    candidate_context_path: Path | None,
    candidate_final_path: Path | None,
    candidate_dir: Path | None,
    approval_digest: str,
    policy_digest: str,
) -> Path:
    if outcome not in OUTCOMES:
        raise GateError(f"invalid outcome: {outcome}")
    if not result_id or "/" in result_id or result_id in {".", ".."}:
        raise GateError("result_id is not a safe single path component")
    completed = result_root / "completed"
    completed.mkdir(parents=True, exist_ok=True)
    final_dir = completed / result_id
    if final_dir.exists():
        raise GateError(f"committed result already exists: {result_id}")
    staging = result_root / f".staging-{result_id}-{uuid.uuid4().hex}"
    staging.mkdir(parents=True, exist_ok=False)

    _write_json(staging / "decision.json", decision)
    _write_json(staging / "comparator.json", comparator or {})
    _write_json(
        staging / "authority-pointer.json",
        {
            "policy_profile_digest": policy_digest,
            "approval_bundle_digest": approval_digest,
        },
    )

    if candidate_context_path and candidate_context_path.is_file():
        shutil.copyfile(candidate_context_path, staging / "execution-context.json")
    if candidate_final_path and candidate_final_path.is_file():
        shutil.copyfile(candidate_final_path, staging / "final-snapshot.json")
    if candidate_dir and candidate_dir.is_dir():
        for name in ("report.json", "receipt.json", "tool-inventory.json"):
            source = candidate_dir / name
            if source.is_file():
                shutil.copyfile(source, staging / name)

    file_hashes: dict[str, str] = {}
    for path in sorted(item for item in staging.iterdir() if item.is_file()):
        file_hashes[path.name] = _sha(path)
    _write_json(
        staging / "manifest.json",
        {
            "schema_version": 1,
            "files": file_hashes,
            "manifest_self_hash": None,
        },
    )
    for path in staging.iterdir():
        if path.is_file():
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
    _fsync_dir(staging)
    os.rename(staging, final_dir)
    _fsync_dir(completed)
    return final_dir


def _evaluate(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy)
    approval_path = Path(args.approval)
    reference_dir = Path(args.reference_dir)
    reference_context_path = Path(args.reference_context)
    reference_final_path = Path(args.reference_final)
    candidate_dir = Path(args.candidate_dir)
    context_path = Path(args.candidate_context)
    final_path = Path(args.candidate_final)
    result_root = Path(args.result_root)

    authority_invalid: list[str] = []
    binding_invalid: list[str] = []
    completion_invalid: list[str] = []
    review_reasons: list[str] = []
    confirmed_violations: list[dict[str, Any]] = []
    comparator: dict[str, Any] | None = None
    policy: dict[str, Any] = {}
    policy_digest = ""
    approval: dict[str, Any] = {}

    try:
        policy, policy_digest = _validate_policy(policy_path, args.selected_gate_image)
    except GateError as exc:
        authority_invalid.append(str(exc))
        policy_digest = _sha(policy_path) if policy_path.is_file() else "unavailable"

    actual_approval_digest = _sha(approval_path) if approval_path.is_file() else "missing"
    if actual_approval_digest != args.selected_approval_digest:
        authority_invalid.append("selected approval bundle digest mismatch")
    try:
        approval = _load(approval_path, "approval bundle")
    except GateError as exc:
        authority_invalid.append(str(exc))
    if approval and approval.get("policy_profile_digest") != policy_digest:
        authority_invalid.append("approval bundle selects a different policy profile")

    if not authority_invalid:
        try:
            authority_invalid.extend(
                _verify_reference(
                    approval=approval,
                    reference_dir=reference_dir,
                    reference_context_path=reference_context_path,
                    reference_final_path=reference_final_path,
                )
            )
        except GateError as exc:
            authority_invalid.append(str(exc))

    context: dict[str, Any] = {}
    report: dict[str, Any] = {}
    snapshot: dict[str, Any] = {}
    if not authority_invalid:
        try:
            context = _load(context_path, "candidate execution context")
            binding_invalid.extend(
                _validate_context_files(
                    context=context,
                    context_path=context_path,
                    run_dir=candidate_dir,
                    final_path=final_path,
                    policy_digest=policy_digest,
                    policy=policy,
                    expected_attempt_id=args.expected_attempt_id,
                    expected_candidate_image=args.expected_candidate_image,
                    expected_candidate_mode=args.expected_candidate_mode,
                )
            )
            reference = approval.get("reference")
            if isinstance(reference, dict) and context.get("attempt_id") == reference.get(
                "origin_attempt_id"
            ):
                binding_invalid.append("candidate attempt reuses the approved reference attempt")
        except GateError as exc:
            binding_invalid.append(str(exc))

    if not authority_invalid and not binding_invalid:
        try:
            report = _load(candidate_dir / "report.json", "candidate report")
            snapshot = _load(final_path, "candidate final snapshot")
            violations, snapshot_invalid, snapshot_review = _validate_snapshot(
                snapshot, str(context.get("attempt_id"))
            )
            confirmed_violations.extend(violations)
            completion_invalid.extend(snapshot_invalid)
            review_reasons.extend(snapshot_review)
            if context.get("attempt_completion") != "finalized":
                completion_invalid.append("trusted attempt finalization is incomplete")
            if context.get("cleanup_complete") is not True:
                completion_invalid.append("trusted runtime cleanup is incomplete")
        except GateError as exc:
            completion_invalid.append(str(exc))

        try:
            compatibility = _receipt_compatibility(candidate_dir)
            reference = approval.get("reference", {})
            approved_compatibility = (
                reference.get("compatibility") if isinstance(reference, dict) else None
            )
            if not isinstance(approved_compatibility, dict):
                completion_invalid.append("approval compatibility mapping missing")
            else:
                for key in (
                    "normalization_version",
                    "report_schema_version",
                    "contract_source_sha256",
                    "logical_target",
                    "fixture_profile",
                    "effective_policy_sha256",
                    "identity_profile_sha256",
                    "observer_scope_sha256",
                    "target_input_sha256",
                    "checks_definition_sha256",
                    "runner_version",
                    "mcp_sdk_version",
                    "transport",
                    "state_strategy",
                    "protocol_versions",
                ):
                    if compatibility.get(key) != approved_compatibility.get(key):
                        completion_invalid.append(
                            f"candidate/reference compatibility mismatch: {key}"
                        )
        except GateError as exc:
            completion_invalid.append(str(exc))

        try:
            matrix = _matrix(report)
            confirmed_violations.extend(
                {"source": "guard", "reason": reason} for reason in matrix.block
            )
            completion_invalid.extend(matrix.invalid)
            review_reasons.extend(matrix.review)
        except GateError as exc:
            completion_invalid.append(str(exc))

        try:
            comparator = compare_saved_runs(reference_dir, candidate_dir)
        except SavedRunComparisonError as exc:
            completion_invalid.append(f"saved-run comparator rejected evidence: {exc}")
        except Exception as exc:  # trusted evaluator internal failure
            completion_invalid.append(
                f"saved-run comparator internal error: {type(exc).__name__}: {exc}"
            )

        if comparator is not None:
            comparison_state = comparator.get("comparability", {}).get("state")
            candidate_conformance = comparator.get("conformance", {}).get("candidate")
            regression = comparator.get("regression", {})
            coverage = comparator.get("coverage", {})
            capabilities = comparator.get("capabilities", {})
            if candidate_conformance == "fail":
                confirmed_violations.append(
                    {"source": "comparator", "reason": "candidate current conformance failed"}
                )
            elif candidate_conformance != "pass":
                completion_invalid.append(
                    f"candidate conformance is not pass: {candidate_conformance!r}"
                )
            if regression.get("new_failures"):
                confirmed_violations.append(
                    {"source": "comparator", "reason": "new failed findings vs approved reference"}
                )
            if regression.get("new_errors"):
                completion_invalid.append("candidate introduced new error findings")
            if coverage.get("regression"):
                completion_invalid.append("candidate evidence coverage regressed")
            if comparison_state == "unsupported":
                completion_invalid.append("saved-run comparison is unsupported")
            elif comparison_state == "changed_context":
                review_reasons.append("saved-run comparison reports changed context")
            if capabilities.get("review_required"):
                review_reasons.append("capability/schema comparison requires review")

    if authority_invalid or binding_invalid:
        outcome = "INVALID"
    elif confirmed_violations:
        outcome = "BLOCK"
    elif completion_invalid:
        outcome = "INVALID"
    elif review_reasons:
        outcome = "REVIEW"
    else:
        outcome = "PASS"

    decision = {
        "schema_version": 1,
        "assessed_outcome": outcome,
        "authority_binding": "invalid" if authority_invalid else "valid",
        "subject_binding": "invalid" if binding_invalid else "valid",
        "confirmed_violations": confirmed_violations,
        "evidence_completeness": "invalid" if completion_invalid else "complete",
        "attempt_completion": context.get("attempt_completion") if context else "unknown",
        "authority_errors": authority_invalid,
        "binding_errors": binding_invalid,
        "completion_errors": completion_invalid,
        "review_reasons": review_reasons,
        "freshness_basis": (
            "trusted current-attempt execution context; comparator freshness remains explicit unknown"
        ),
        "scope": "phase2b4_local_synthetic_gate_only",
    }
    published = _publish(
        result_root=result_root,
        result_id=args.result_id,
        outcome=outcome,
        decision=decision,
        comparator=comparator,
        candidate_context_path=context_path if context_path.exists() else None,
        candidate_final_path=final_path if final_path.exists() else None,
        candidate_dir=candidate_dir if candidate_dir.exists() else None,
        approval_digest=args.selected_approval_digest,
        policy_digest=policy_digest,
    )
    print(
        json.dumps(
            {"outcome": outcome, "bundle": str(published), "result_id": args.result_id},
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    promote = sub.add_parser("promote")
    promote.add_argument("--policy", required=True)
    promote.add_argument("--reference-dir", required=True)
    promote.add_argument("--reference-context", required=True)
    promote.add_argument("--reference-final", required=True)
    promote.add_argument("--output", required=True)
    promote.add_argument("--selected-gate-image", required=True)
    promote.set_defaults(func=_promote)

    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--policy", required=True)
    evaluate.add_argument("--approval", required=True)
    evaluate.add_argument("--selected-approval-digest", required=True)
    evaluate.add_argument("--reference-dir", required=True)
    evaluate.add_argument("--reference-context", required=True)
    evaluate.add_argument("--reference-final", required=True)
    evaluate.add_argument("--candidate-dir", required=True)
    evaluate.add_argument("--candidate-context", required=True)
    evaluate.add_argument("--candidate-final", required=True)
    evaluate.add_argument("--expected-attempt-id", required=True)
    evaluate.add_argument("--expected-candidate-image", required=True)
    evaluate.add_argument("--expected-candidate-mode", required=True)
    evaluate.add_argument("--selected-gate-image", required=True)
    evaluate.add_argument("--result-root", required=True)
    evaluate.add_argument("--result-id", required=True)
    evaluate.set_defaults(func=_evaluate)

    args = parser.parse_args()
    try:
        return int(args.func(args))
    except GateError as exc:
        print(json.dumps({"internal_error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
