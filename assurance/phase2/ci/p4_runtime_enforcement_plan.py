from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import p4_resource_enforcement as enforcement


class P4RuntimeEnforcementPlanError(RuntimeError):
    pass


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TRUST_REL = "assurance/phase2/ci/trust-boundary.json"
POLICY_REL = "assurance/phase2/ci/p4-resource-policy.json"
ENFORCEMENT_REL = "assurance/phase2/ci/p4_resource_enforcement.py"
AUTHORITY_REL = "assurance/phase2/ci/p3-promoted-authority.json"
PROOF_REL = "assurance/phase2/ci/p4-live-materialization-proof.json"
MODULE_REL = "assurance/phase2/ci/p4_runtime_enforcement_plan.py"


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise P4RuntimeEnforcementPlanError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise P4RuntimeEnforcementPlanError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise P4RuntimeEnforcementPlanError(f"{label} must be a positive integer")
    return value


def _sha(value: Any, label: str) -> str:
    raw = _string(value, label)
    if not _SHA_RE.fullmatch(raw):
        raise P4RuntimeEnforcementPlanError(f"{label} must be an exact 40-hex SHA")
    return raw


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise P4RuntimeEnforcementPlanError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _tracked_checkout_unchanged(repo: Path) -> None:
    for args in (
        ("diff", "--quiet", "HEAD", "--", "."),
        ("diff", "--cached", "--quiet", "HEAD", "--", "."),
    ):
        result = subprocess.run(["git", "-C", str(repo), *args], check=False)
        if result.returncode == 1:
            raise P4RuntimeEnforcementPlanError("trusted runtime-plan checkout is dirty")
        if result.returncode != 0:
            raise P4RuntimeEnforcementPlanError("could not verify runtime-plan checkout")


def _regular_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise P4RuntimeEnforcementPlanError(f"{label} must be a regular file")
    return path.read_bytes()


def _bounded_object(raw: bytes, policy: dict[str, Any], label: str) -> dict[str, Any]:
    try:
        return enforcement.load_bounded_json(raw, policy, expected_schema_version=1)
    except enforcement.P4ResourceEnforcementError as exc:
        raise P4RuntimeEnforcementPlanError(f"invalid {label}: {exc}") from exc


def validate_static_binding(repo: Path, trusted_commit: str) -> dict[str, Any]:
    repo = repo.resolve()
    if not _SHA_RE.fullmatch(trusted_commit):
        raise P4RuntimeEnforcementPlanError("trusted_commit must be an exact 40-hex SHA")
    if _git(repo, "rev-parse", "HEAD") != trusted_commit:
        raise P4RuntimeEnforcementPlanError("runtime-plan HEAD differs from trusted_commit")
    if _git(repo, "cat-file", "-t", trusted_commit) != "commit":
        raise P4RuntimeEnforcementPlanError("trusted_commit does not identify a commit")
    _tracked_checkout_unchanged(repo)

    policy_path = repo / POLICY_REL
    trust_path = repo / TRUST_REL
    proof_path = repo / PROOF_REL
    module_path = repo / MODULE_REL
    authority_path = repo / AUTHORITY_REL

    policy = enforcement.load_policy(policy_path)
    try:
        enforcement.validate_trust_binding(repo, trust_path, policy_path)
    except enforcement.P4ResourceEnforcementError as exc:
        raise P4RuntimeEnforcementPlanError(f"resource-enforcement binding invalid: {exc}") from exc

    trust_raw = _regular_bytes(trust_path, "trust boundary")
    proof_raw = _regular_bytes(proof_path, "live materialization proof")
    module_raw = _regular_bytes(module_path, "runtime enforcement plan module")
    authority_raw = _regular_bytes(authority_path, "promoted authority")

    trust = _bounded_object(trust_raw, policy, "trust boundary")
    proof = _bounded_object(proof_raw, policy, "live materialization proof")
    authority = _bounded_object(authority_raw, policy, "promoted authority")

    controller = _mapping(trust.get("controller"), "trust.controller")
    publisher = _mapping(trust.get("publisher"), "trust.publisher")
    promotion = _mapping(trust.get("p3_promotion"), "trust.p3_promotion")
    materialization = _mapping(
        trust.get("p4_candidate_materialization"), "trust.p4_candidate_materialization"
    )

    if controller.get("controller_stage") != "INTAKE_ONLY":
        raise P4RuntimeEnforcementPlanError("controller must remain INTAKE_ONLY")
    if controller.get("candidate_execution_enabled") is not False:
        raise P4RuntimeEnforcementPlanError("candidate execution must remain disabled")
    if controller.get("verdict_publication_enabled") is not False:
        raise P4RuntimeEnforcementPlanError("verdict publication must remain disabled")
    if (
        publisher.get("bootstrap_status") != "UNBOOTSTRAPPED"
        or publisher.get("integration_id") is not None
    ):
        raise P4RuntimeEnforcementPlanError("publisher must remain unbootstrapped")
    if (
        promotion.get("status") != "PROMOTED"
        or type(promotion.get("authority_generation")) is not int
        or promotion.get("authority_generation") != 1
    ):
        raise P4RuntimeEnforcementPlanError("promoted authority generation 1 is not active")
    if _sha256(authority_raw) != promotion.get("authority_sha256"):
        raise P4RuntimeEnforcementPlanError("promoted authority digest mismatch")
    if authority.get("status") != "PROMOTED" or authority.get("consumable") is not True:
        raise P4RuntimeEnforcementPlanError("promoted authority is not consumable")
    generation = _mapping(authority.get("generation"), "authority.generation")
    if (
        type(generation.get("number")) is not int
        or generation.get("number") != 1
        or generation.get("supersedes") is not None
    ):
        raise P4RuntimeEnforcementPlanError("authority generation differs from generation 1")
    if authority.get("platform") != "linux/amd64":
        raise P4RuntimeEnforcementPlanError("promoted authority platform mismatch")
    authority_publisher = _mapping(authority.get("publisher"), "authority.publisher")
    if authority_publisher != {"integration_id": None, "status": "UNBOOTSTRAPPED"}:
        raise P4RuntimeEnforcementPlanError("promoted authority publisher mismatch")
    reference = _mapping(authority.get("reference"), "authority.reference")
    approval = _string(reference.get("approval_bundle_digest"), "authority approval digest")
    if approval != promotion.get("approval_bundle_digest"):
        raise P4RuntimeEnforcementPlanError("promoted authority approval digest mismatch")
    if materialization.get("candidate_execution_enabled") is not False:
        raise P4RuntimeEnforcementPlanError(
            "materialization boundary unexpectedly enables execution"
        )
    if materialization.get("runtime_enforcement_proven") is not False:
        raise P4RuntimeEnforcementPlanError("materialization boundary falsely claims runtime proof")

    proof_binding = _mapping(
        trust.get("p4_live_materialization_proof"), "trust.p4_live_materialization_proof"
    )
    proof_sha = _sha256(proof_raw)
    expected_proof_binding = {
        "status": "ACCEPTED_NON_EXECUTING",
        "stage": "LIVE_CURRENT_HEAD_MATERIALIZATION_PROOF",
        "proof_path": PROOF_REL,
        "proof_sha256": proof_sha,
        "proof_pr_number": 51,
        "proof_base_sha": "05412cfc43aca2bb246300b5c5bef8452cfb1253",
        "proof_head_sha": "1686adaee6387b47e3928c94766f1ffe7b9fed5d",
        "trusted_intake_run_id": 37563924035,
        "trusted_intake_artifact_id": 11458475964,
        "candidate_execution_performed": False,
        "hostile_execution_authorized": False,
        "runtime_enforcement_proven": False,
        "proof_pr_merged": False,
        "proof_pr_closed": True,
        "proof_branch_deleted": True,
    }
    if proof_binding != expected_proof_binding:
        raise P4RuntimeEnforcementPlanError("live materialization proof trust binding mismatch")

    if proof.get("status") != "ACCEPTED_NON_EXECUTING":
        raise P4RuntimeEnforcementPlanError("live materialization proof is not accepted")
    if proof.get("candidate_execution_performed") is not False:
        raise P4RuntimeEnforcementPlanError("live materialization proof executed the candidate")
    if proof.get("runtime_enforcement_proven") is not False:
        raise P4RuntimeEnforcementPlanError(
            "live materialization proof falsely claims runtime proof"
        )
    if _positive_int(proof.get("proof_pr_number"), "proof.proof_pr_number") != 51:
        raise P4RuntimeEnforcementPlanError("live materialization proof PR mismatch")
    _sha(proof.get("proof_base_sha"), "proof.proof_base_sha")
    _sha(proof.get("proof_head_sha"), "proof.proof_head_sha")

    binding = _mapping(
        trust.get("p4_runtime_enforcement_plan"), "trust.p4_runtime_enforcement_plan"
    )
    expected_binding = {
        "status": "PLAN_ONLY_NOT_RUNTIME_PROVEN",
        "stage": "PRE_HOSTILE_RUNTIME_ENFORCEMENT_PLAN",
        "module_path": MODULE_REL,
        "module_sha256": _sha256(module_raw),
        "proof_path": PROOF_REL,
        "proof_sha256": proof_sha,
        "candidate_execution_enabled": False,
        "hostile_execution_authorized": False,
        "runtime_execution_enabled": False,
        "runtime_enforcement_proven": False,
        "verdict_publication_enabled": False,
    }
    if binding != expected_binding:
        raise P4RuntimeEnforcementPlanError("runtime enforcement plan trust binding mismatch")

    consumed = trust.get("consumed_trusted_inputs")
    if not isinstance(consumed, list) or not all(isinstance(item, str) for item in consumed):
        raise P4RuntimeEnforcementPlanError("consumed_trusted_inputs must be a string list")
    for required in (PROOF_REL, MODULE_REL):
        if consumed.count(required) != 1:
            raise P4RuntimeEnforcementPlanError(
                f"consumed trusted input count mismatch: {required}"
            )

    return {
        "policy": policy,
        "trust": trust,
        "proof": proof,
        "proof_sha256": proof_sha,
        "module_sha256": _sha256(module_raw),
    }


def build_plan(*, repo: Path, trusted_commit: str, output_path: Path) -> dict[str, Any]:
    static = validate_static_binding(repo, trusted_commit)
    policy = _mapping(static["policy"], "policy")

    docker_args = enforcement.docker_resource_args(policy)
    build = enforcement.build_command_limits(policy)
    subprocess_limits = enforcement.subprocess_limits(policy)
    traffic = enforcement.TrafficBudget.from_policy(policy)
    resources = enforcement.OwnedResourceBudget.from_policy(policy)
    deadline = enforcement.AttemptDeadline.from_policy(policy, now=0.0)

    artifacts = _mapping(
        _mapping(policy.get("limits"), "limits").get("artifacts"), "limits.artifacts"
    )
    archive = _mapping(policy.get("archive_extraction"), "archive_extraction")
    json_intake = _mapping(policy.get("json_intake"), "json_intake")
    cleanup = _mapping(policy.get("cleanup_semantics"), "cleanup_semantics")
    required = policy.get("required_before_hostile_execution")
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        raise P4RuntimeEnforcementPlanError(
            "required_before_hostile_execution must be a string list"
        )

    proof_cases = {
        "docker_log_budget_enforced": ["docker_log_options_applied", "docker_log_rotation_bounded"],
        "build_log_budget_enforced": ["build_output_budget_breach_terminates_owned_process"],
        "artifact_budget_enforced": ["artifact_total_per_file_count_depth_rejection"],
        "archive_safe_extraction_enforced": [
            "archive_traversal_absolute_symlink_hardlink_device_duplicate_collision_rejection",
            "archive_expansion_ratio_and_byte_budget_rejection",
        ],
        "json_bounded_parser_enforced": [
            "json_byte_depth_duplicate_key_type_string_and_count_rejection"
        ],
        "fixture_traffic_budget_enforced": [
            "fixture_request_response_count_and_aggregate_budget_rejection"
        ],
        "execution_concurrency_budget_enforced": [
            "single_attempt_lease_rejects_concurrency",
            "attempt_deadline_and_cleanup_timeout_enforced",
            "owned_docker_resource_counts_enforced",
        ],
        "malformed_cleanup_maps_to_unknown": [
            "malformed_cleanup_returns_unknown_recovery_required"
        ],
    }
    if sorted(proof_cases) != sorted(required):
        raise P4RuntimeEnforcementPlanError(
            "runtime proof coverage does not match frozen policy requirements"
        )

    plan = {
        "schema_version": 1,
        "stage": "P4_RUNTIME_ENFORCEMENT_PLAN_ONLY",
        "trusted_commit": trusted_commit,
        "authority_generation": 1,
        "live_materialization_proof_sha256": static["proof_sha256"],
        "runtime": {
            "execution_enabled": False,
            "candidate_execution_enabled": False,
            "hostile_execution_authorized": False,
            "runtime_enforcement_proven": False,
            "verdict_publication_enabled": False,
        },
        "docker": {
            "resource_args": docker_args,
            "max_owned_containers": resources.max_containers,
            "max_owned_networks": resources.max_networks,
            "max_owned_volumes": resources.max_volumes,
        },
        "build": build,
        "subprocess": subprocess_limits,
        "fixture_traffic": {
            "request_bytes": traffic.request_bytes,
            "response_bytes": traffic.response_bytes,
            "max_requests": traffic.max_requests,
            "aggregate_bytes": traffic.aggregate_bytes,
        },
        "execution": {
            "attempt_timeout_seconds": int(deadline.deadline),
            "cleanup_timeout_seconds": deadline.cleanup_timeout_seconds,
            "max_concurrent_attempts": 1,
        },
        "artifacts": artifacts,
        "archive_extraction": archive,
        "json_intake": json_intake,
        "cleanup_semantics": cleanup,
        "required_before_hostile_execution": required,
        "proof_cases": {
            key: {"status": "PLANNED_NOT_PROVEN", "cases": value}
            for key, value in proof_cases.items()
        },
        "next_boundary": {
            "wire_policy_into_p4_runtime": True,
            "run_non_hostile_negative_resource_proofs": True,
            "prove_cleanup_fail_closed": True,
            "hostile_execution_allowed_after_this_plan": False,
        },
    }
    if output_path.exists():
        raise P4RuntimeEnforcementPlanError("runtime plan output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--trusted-commit", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate-binding-only", action="store_true")
    args = parser.parse_args()

    if args.validate_binding_only:
        value = validate_static_binding(args.repo, args.trusted_commit)
        print(
            json.dumps(
                {
                    "status": "P4_RUNTIME_ENFORCEMENT_PLAN_BINDING_VALID",
                    "live_materialization_proof_sha256": value["proof_sha256"],
                    "candidate_execution_enabled": False,
                    "runtime_execution_enabled": False,
                    "runtime_enforcement_proven": False,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.output is None:
        parser.error("--output is required unless --validate-binding-only is used")
    build_plan(repo=args.repo, trusted_commit=args.trusted_commit, output_path=args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
