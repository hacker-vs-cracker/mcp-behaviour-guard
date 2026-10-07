from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import p4_resource_enforcement as enforcement


class P4ControllerPlanError(RuntimeError):
    pass


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TRUST_REL = "assurance/phase2/ci/trust-boundary.json"
AUTHORITY_REL = "assurance/phase2/ci/p3-promoted-authority.json"
POLICY_REL = "assurance/phase2/ci/p4-resource-policy.json"
ENFORCEMENT_REL = "assurance/phase2/ci/p4_resource_enforcement.py"
MODULE_REL = "assurance/phase2/ci/p4_controller_plan.py"
WORKFLOW_REL = ".github/workflows/phase2-trusted-intake.yml"


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise P4ControllerPlanError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise P4ControllerPlanError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise P4ControllerPlanError(f"{label} must be a positive integer")
    return value


def _sha(value: Any, label: str) -> str:
    raw = _string(value, label)
    if not _SHA_RE.fullmatch(raw):
        raise P4ControllerPlanError(f"{label} must be an exact 40-hex SHA")
    return raw


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        raise P4ControllerPlanError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def _tracked_checkout_unchanged(repo: Path) -> None:
    for args in (
        ("diff", "--quiet", "HEAD", "--", "."),
        ("diff", "--cached", "--quiet", "HEAD", "--", "."),
    ):
        result = subprocess.run(["git", "-C", str(repo), *args], check=False)
        if result.returncode == 1:
            raise P4ControllerPlanError("trusted controller tracked checkout is dirty")
        if result.returncode != 0:
            raise P4ControllerPlanError("could not verify trusted controller tracked checkout")


def _regular_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise P4ControllerPlanError(f"{label} must be a regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise P4ControllerPlanError(f"cannot read {label}: {exc}") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _bounded_object(raw: bytes, policy: dict[str, Any], label: str) -> dict[str, Any]:
    try:
        return enforcement.load_bounded_json(raw, policy, expected_schema_version=1)
    except enforcement.P4ResourceEnforcementError as exc:
        raise P4ControllerPlanError(f"invalid {label}: {exc}") from exc


def validate_static_binding(repo: Path, trusted_commit: str) -> dict[str, Any]:
    repo = repo.resolve()
    if not _SHA_RE.fullmatch(trusted_commit):
        raise P4ControllerPlanError("trusted_commit must be an exact 40-hex SHA")
    if _git(repo, "rev-parse", "HEAD") != trusted_commit:
        raise P4ControllerPlanError("trusted controller HEAD differs from trusted_commit")
    if _git(repo, "cat-file", "-t", trusted_commit) != "commit":
        raise P4ControllerPlanError("trusted_commit does not identify a commit")
    _tracked_checkout_unchanged(repo)

    trust_path = repo / TRUST_REL
    policy_path = repo / POLICY_REL
    authority_path = repo / AUTHORITY_REL
    enforcement_path = repo / ENFORCEMENT_REL
    module_path = repo / MODULE_REL
    workflow_path = repo / WORKFLOW_REL

    policy = enforcement.load_policy(policy_path)
    try:
        enforcement_binding = enforcement.validate_trust_binding(repo, trust_path, policy_path)
    except enforcement.P4ResourceEnforcementError as exc:
        raise P4ControllerPlanError(f"resource enforcement binding invalid: {exc}") from exc

    trust_raw = _regular_bytes(trust_path, "trust boundary")
    authority_raw = _regular_bytes(authority_path, "promoted authority")
    enforcement_raw = _regular_bytes(enforcement_path, "resource enforcement module")
    module_raw = _regular_bytes(module_path, "controller plan module")
    workflow_raw = _regular_bytes(workflow_path, "trusted intake workflow")

    trust = _bounded_object(trust_raw, policy, "trust boundary")
    authority = _bounded_object(authority_raw, policy, "promoted authority")

    controller = _mapping(trust.get("controller"), "trust.controller")
    publisher = _mapping(trust.get("publisher"), "trust.publisher")
    promotion = _mapping(trust.get("p3_promotion"), "trust.p3_promotion")
    resource_policy = _mapping(trust.get("p4_resource_policy"), "trust.p4_resource_policy")
    resource_enforcement = _mapping(
        trust.get("p4_resource_enforcement"), "trust.p4_resource_enforcement"
    )

    if controller.get("controller_stage") != "INTAKE_ONLY":
        raise P4ControllerPlanError("controller must remain INTAKE_ONLY")
    if controller.get("candidate_execution_enabled") is not False:
        raise P4ControllerPlanError("candidate execution must remain disabled")
    if controller.get("verdict_publication_enabled") is not False:
        raise P4ControllerPlanError("verdict publication must remain disabled")
    if (
        publisher.get("bootstrap_status") != "UNBOOTSTRAPPED"
        or publisher.get("integration_id") is not None
    ):
        raise P4ControllerPlanError("publisher must remain unbootstrapped")
    if promotion.get("status") != "PROMOTED" or promotion.get("authority_generation") != 1:
        raise P4ControllerPlanError("promoted authority generation 1 is not active")
    if (
        resource_policy.get("candidate_execution_enabled") is not False
        or resource_policy.get("runtime_enforcement_proven") is not False
    ):
        raise P4ControllerPlanError("resource policy boundary unexpectedly authorizes execution")
    if (
        resource_enforcement.get("candidate_execution_enabled") is not False
        or resource_enforcement.get("hostile_execution_authorized") is not False
        or resource_enforcement.get("runtime_enforcement_proven") is not False
    ):
        raise P4ControllerPlanError(
            "resource enforcement boundary unexpectedly authorizes execution"
        )
    if (
        enforcement_binding.get("candidate_execution_enabled") is not False
        or enforcement_binding.get("hostile_execution_authorized") is not False
        or enforcement_binding.get("runtime_enforcement_proven") is not False
    ):
        raise P4ControllerPlanError(
            "validated resource enforcement unexpectedly authorizes execution"
        )

    authority_digest = _sha256(authority_raw)
    if authority_digest != promotion.get("authority_sha256"):
        raise P4ControllerPlanError("promoted authority digest differs from trust boundary")
    if authority.get("status") != "PROMOTED" or authority.get("consumable") is not True:
        raise P4ControllerPlanError("promoted authority is not consumable")
    generation = _mapping(authority.get("generation"), "authority.generation")
    if generation.get("number") != 1 or generation.get("supersedes") is not None:
        raise P4ControllerPlanError("promoted authority generation differs from generation 1")
    if authority.get("platform") != "linux/amd64":
        raise P4ControllerPlanError("promoted authority platform mismatch")
    authority_publisher = _mapping(authority.get("publisher"), "authority.publisher")
    if authority_publisher != {"integration_id": None, "status": "UNBOOTSTRAPPED"}:
        raise P4ControllerPlanError("promoted authority publisher state mismatch")
    reference = _mapping(authority.get("reference"), "authority.reference")
    approval_digest = _string(reference.get("approval_bundle_digest"), "authority approval digest")
    if approval_digest != promotion.get("approval_bundle_digest"):
        raise P4ControllerPlanError(
            "promoted authority approval digest differs from trust boundary"
        )

    plan_binding = _mapping(trust.get("p4_controller_plan"), "trust.p4_controller_plan")
    expected_binding = {
        "status": "PLAN_ONLY_NOT_RUNTIME_PROVEN",
        "stage": "TRUSTED_INTAKE_PLAN_ONLY",
        "module_path": MODULE_REL,
        "module_sha256": _sha256(module_raw),
        "workflow_path": WORKFLOW_REL,
        "workflow_sha256": _sha256(workflow_raw),
        "candidate_materialization_performed": False,
        "candidate_execution_enabled": False,
        "hostile_execution_authorized": False,
        "runtime_enforcement_proven": False,
        "verdict_publication_enabled": False,
    }
    if plan_binding != expected_binding:
        raise P4ControllerPlanError("trust-boundary controller-plan binding mismatch")

    consumed = trust.get("consumed_trusted_inputs")
    if not isinstance(consumed, list) or not all(isinstance(item, str) for item in consumed):
        raise P4ControllerPlanError("consumed_trusted_inputs must be a string list")
    for required in (MODULE_REL, WORKFLOW_REL):
        if consumed.count(required) != 1:
            raise P4ControllerPlanError(f"consumed trusted input count mismatch: {required}")

    return {
        "trust": trust,
        "policy": policy,
        "authority": authority,
        "authority_sha256": authority_digest,
        "trust_boundary_sha256": _sha256(trust_raw),
        "workflow_sha256": _sha256(workflow_raw),
        "resource_enforcement_sha256": _sha256(enforcement_raw),
    }


def build_plan(
    *,
    repo: Path,
    intake_path: Path,
    trusted_commit: str,
    output_path: Path,
) -> dict[str, Any]:
    static = validate_static_binding(repo, trusted_commit)
    trust = _mapping(static["trust"], "trust")
    policy = _mapping(static["policy"], "policy")
    authority = _mapping(static["authority"], "authority")

    intake_raw = _regular_bytes(intake_path, "normalized trusted intake")
    intake = _bounded_object(intake_raw, policy, "normalized trusted intake")
    if intake.get("source_event") != "workflow_run":
        raise P4ControllerPlanError("intake source_event mismatch")

    controller = _mapping(trust.get("controller"), "trust.controller")
    expected_repo = _string(controller.get("expected_repository"), "expected repository")
    repository = _mapping(intake.get("repository"), "intake.repository")
    if repository.get("full_name") != expected_repo:
        raise P4ControllerPlanError("intake repository mismatch")

    trusted = _mapping(intake.get("trusted_controller"), "intake.trusted_controller")
    if _sha(trusted.get("commit_sha"), "intake trusted commit") != trusted_commit:
        raise P4ControllerPlanError("intake trusted controller commit mismatch")
    if trusted.get("trust_boundary_sha256") != static["trust_boundary_sha256"]:
        raise P4ControllerPlanError("intake trust-boundary digest mismatch")

    upstream = _mapping(intake.get("upstream"), "intake.upstream")
    if _positive_int(upstream.get("workflow_id"), "upstream.workflow_id") != _positive_int(
        controller.get("expected_upstream_workflow_id"), "controller.expected_upstream_workflow_id"
    ):
        raise P4ControllerPlanError("eligible workflow id mismatch")
    if upstream.get("workflow_name") != controller.get("expected_upstream_workflow_name"):
        raise P4ControllerPlanError("eligible workflow name mismatch")
    if upstream.get("event") != controller.get("expected_upstream_event"):
        raise P4ControllerPlanError("eligible workflow event mismatch")
    if upstream.get("status") != controller.get("require_workflow_run_status"):
        raise P4ControllerPlanError("eligible workflow status mismatch")
    run_id = _positive_int(upstream.get("run_id"), "upstream.run_id")
    run_attempt = _positive_int(upstream.get("run_attempt"), "upstream.run_attempt")
    conclusion_value = upstream.get("conclusion")
    if conclusion_value is not None and not isinstance(conclusion_value, str):
        raise P4ControllerPlanError("upstream conclusion must be a string or null")
    if upstream.get("conclusion_is_authoritative") is not False:
        raise P4ControllerPlanError("upstream CI conclusion must remain non-authoritative")
    if upstream.get("event_pull_requests_are_authority") is not False:
        raise P4ControllerPlanError("workflow_run event PRs must remain non-authoritative")

    current_pr = _mapping(intake.get("pull_request"), "intake.pull_request")
    pr_number = _positive_int(current_pr.get("number"), "pull_request.number")
    if current_pr.get("state") != controller.get("require_current_pull_request_state"):
        raise P4ControllerPlanError("current PR state mismatch")
    head_sha = _sha(current_pr.get("head_sha"), "pull_request.head_sha")
    base_sha = _sha(current_pr.get("base_sha"), "pull_request.base_sha")
    if current_pr.get("base_ref") != "main":
        raise P4ControllerPlanError("current PR base ref mismatch")
    if (
        current_pr.get("head_repository") != expected_repo
        or current_pr.get("base_repository") != expected_repo
    ):
        raise P4ControllerPlanError("current PR repository scope mismatch")
    if current_pr.get("source_scope") != "same-repository-pull-request-only":
        raise P4ControllerPlanError("current PR source scope mismatch")
    if current_pr.get("lookup_source") != "trusted-github-rest-commit-pulls":
        raise P4ControllerPlanError("current PR lookup source mismatch")

    intake_authority = _mapping(intake.get("authority"), "intake.authority")
    for key in (
        "candidate_workflow_artifacts_are_authority",
        "upstream_ci_conclusion_is_phase2_verdict",
        "workflow_run_event_pull_requests_are_authority",
    ):
        if intake_authority.get(key) is not False:
            raise P4ControllerPlanError(f"intake authority flag must remain false: {key}")
    if intake_authority.get("stale_workflow_run_rejected_if_current_pr_head_moved") is not True:
        raise P4ControllerPlanError("stale workflow-run rejection guarantee is missing")

    promotion = _mapping(trust.get("p3_promotion"), "trust.p3_promotion")
    reference = _mapping(authority.get("reference"), "authority.reference")
    resource_policy = _mapping(trust.get("p4_resource_policy"), "trust.p4_resource_policy")
    resource_enforcement = _mapping(
        trust.get("p4_resource_enforcement"), "trust.p4_resource_enforcement"
    )
    candidate = _mapping(trust.get("candidate"), "trust.candidate")
    publisher = _mapping(trust.get("publisher"), "trust.publisher")

    allowed_paths = candidate.get("allowed_paths")
    if allowed_paths != ["assurance/phase2/vertical/candidate_server.py"]:
        raise P4ControllerPlanError("candidate source allowlist differs from frozen boundary")

    plan = {
        "schema_version": 1,
        "stage": "P4_CONTROLLER_PLAN_ONLY",
        "trusted_controller": {
            "commit_sha": trusted_commit,
            "trust_boundary_sha256": static["trust_boundary_sha256"],
            "workflow_path": WORKFLOW_REL,
            "workflow_sha256": static["workflow_sha256"],
        },
        "eligible_workflow": {
            "workflow_id": upstream["workflow_id"],
            "workflow_name": upstream["workflow_name"],
            "run_id": run_id,
            "run_attempt": run_attempt,
            "event": upstream["event"],
            "status": upstream["status"],
            "conclusion": conclusion_value,
            "conclusion_is_authoritative": False,
        },
        "pull_request": {
            "number": pr_number,
            "state": current_pr["state"],
            "head_sha": head_sha,
            "head_ref": _string(current_pr.get("head_ref"), "pull_request.head_ref"),
            "base_sha": base_sha,
            "base_ref": "main",
            "repository": expected_repo,
            "current_identity_source": "trusted-github-rest-commit-pulls",
        },
        "promoted_authority": {
            "generation": promotion["authority_generation"],
            "authority_sha256": static["authority_sha256"],
            "approval_bundle_digest": reference["approval_bundle_digest"],
            "platform": authority["platform"],
        },
        "resource_controls": {
            "policy_sha256": resource_policy["policy_sha256"],
            "enforcement_module_sha256": resource_enforcement["module_sha256"],
            "runtime_enforcement_proven": False,
        },
        "candidate": {
            "source_path": allowed_paths[0],
            "trusted_dockerfile_path": candidate["trusted_dockerfile_path"],
            "source_scope": candidate["source_scope"],
            "materialization_performed": False,
            "execution_enabled": False,
            "hostile_execution_authorized": False,
            "execution_time_current_pr_recheck_required": True,
        },
        "publisher": {
            "enabled": False,
            "bootstrap_status": publisher["bootstrap_status"],
            "integration_id": publisher["integration_id"],
        },
        "next_boundary": {
            "candidate_materialization_requires_exact_head": True,
            "execution_requires_current_pr_head_base_recheck": True,
            "execution_requires_runtime_enforcement_proof": True,
            "verdict_publication_enabled": False,
        },
    }

    if output_path.exists():
        raise P4ControllerPlanError("controller plan output already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--trusted-commit", required=True)
    parser.add_argument("--intake", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate-binding-only", action="store_true")
    args = parser.parse_args()

    if args.validate_binding_only:
        value = validate_static_binding(args.repo, args.trusted_commit)
        print(
            json.dumps(
                {
                    "status": "P4_CONTROLLER_PLAN_BINDING_VALID",
                    "authority_generation": value["trust"]["p3_promotion"]["authority_generation"],
                    "candidate_execution_enabled": False,
                    "runtime_enforcement_proven": False,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.intake is None or args.output is None:
        parser.error("--intake and --output are required unless --validate-binding-only is used")
    build_plan(
        repo=args.repo,
        intake_path=args.intake,
        trusted_commit=args.trusted_commit,
        output_path=args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
