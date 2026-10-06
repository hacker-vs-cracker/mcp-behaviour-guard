from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any


class P4ResourcePolicyError(RuntimeError):
    pass


POLICY_REL = "assurance/phase2/ci/p4-resource-policy.json"
VALIDATOR_REL = "assurance/phase2/ci/p4_resource_policy.py"
RUNNER_REL = "assurance/phase2/run_isolation_check.py"

EXPECTED_REQUIRED_PROOFS = [
    "docker_log_budget_enforced",
    "build_log_budget_enforced",
    "artifact_budget_enforced",
    "archive_safe_extraction_enforced",
    "json_bounded_parser_enforced",
    "fixture_traffic_budget_enforced",
    "execution_concurrency_budget_enforced",
    "malformed_cleanup_maps_to_unknown",
]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise P4ResourcePolicyError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(path: Path, *, max_bytes: int = 131_072) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise P4ResourcePolicyError(f"cannot read JSON {path}: {exc}") from exc
    if len(raw) > max_bytes:
        raise P4ResourcePolicyError(f"JSON {path} exceeds {max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise P4ResourcePolicyError(f"JSON {path} is not UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except P4ResourcePolicyError:
        raise
    except json.JSONDecodeError as exc:
        raise P4ResourcePolicyError(f"invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise P4ResourcePolicyError(f"JSON {path} must be an object")
    return value


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise P4ResourcePolicyError(f"{label} must be an object")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise P4ResourcePolicyError(f"{label} must be a positive integer")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise P4ResourcePolicyError(
            f"{label} keys differ: missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _numeric_literal(node: ast.AST) -> int | float:
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, (int, float))
        and not isinstance(node.value, bool)
    ):
        return node.value
    if isinstance(node, ast.BinOp):
        left = _numeric_literal(node.left)
        right = _numeric_literal(node.right)
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.FloorDiv):
            return left // right
    raise P4ResourcePolicyError("unsupported numeric constant expression")


def _source_constants(path: Path, names: set[str]) -> dict[str, int | float]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise P4ResourcePolicyError(f"cannot parse trusted source {path}: {exc}") from exc
    found: dict[str, int | float] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id in names:
                found[target.id] = _numeric_literal(statement.value)
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
            if isinstance(target, ast.Name) and target.id in names and statement.value is not None:
                found[target.id] = _numeric_literal(statement.value)
    missing = names - set(found)
    if missing:
        raise P4ResourcePolicyError(f"trusted source constants missing: {sorted(missing)}")
    return found


def validate(repo: Path, policy_path: Path, trust_boundary_path: Path) -> dict[str, Any]:
    policy = _load_json(policy_path)
    trust = _load_json(trust_boundary_path)

    _exact_keys(
        policy,
        {
            "schema_version",
            "profile_id",
            "status",
            "scope",
            "stage",
            "candidate_execution_enabled",
            "runtime_enforcement_proven",
            "limits",
            "archive_extraction",
            "json_intake",
            "cleanup_semantics",
            "required_before_hostile_execution",
        },
        "policy",
    )
    if policy.get("schema_version") != 1:
        raise P4ResourcePolicyError("policy schema_version must be 1")
    if policy.get("profile_id") != "phase2c-p4-resource-policy-v1":
        raise P4ResourcePolicyError("policy profile_id mismatch")
    if policy.get("status") != "PRE_P4_RESOURCE_POLICY_FROZEN":
        raise P4ResourcePolicyError("policy status mismatch")
    if policy.get("scope") != "phase2c_p4_hostile_candidate":
        raise P4ResourcePolicyError("policy scope mismatch")
    if policy.get("stage") != "POLICY_FOUNDATION_ONLY":
        raise P4ResourcePolicyError("policy stage mismatch")
    if policy.get("candidate_execution_enabled") is not False:
        raise P4ResourcePolicyError("policy must not enable candidate execution")
    if policy.get("runtime_enforcement_proven") is not False:
        raise P4ResourcePolicyError("policy must not claim runtime enforcement proof")

    limits = _mapping(policy.get("limits"), "limits")
    _exact_keys(
        limits,
        {
            "subprocess",
            "candidate_source",
            "docker_runtime",
            "build",
            "artifacts",
            "fixture_traffic",
            "execution",
        },
        "limits",
    )

    subprocess_policy = _mapping(limits.get("subprocess"), "limits.subprocess")
    _exact_keys(
        subprocess_policy,
        {
            "aggregate_output_bytes",
            "retained_bytes_per_stream",
            "command_timeout_seconds",
            "breach_action",
            "breach_outcome",
            "implementation_path",
        },
        "limits.subprocess",
    )
    constants = _source_constants(
        repo / RUNNER_REL,
        {"_OUTPUT_BUDGET_BYTES", "_CAPTURE_LIMIT_BYTES", "_COMMAND_TIMEOUT_SECONDS"},
    )
    if subprocess_policy.get("aggregate_output_bytes") != constants["_OUTPUT_BUDGET_BYTES"]:
        raise P4ResourcePolicyError("subprocess aggregate output budget differs from merged Q1")
    if subprocess_policy.get("retained_bytes_per_stream") != constants["_CAPTURE_LIMIT_BYTES"]:
        raise P4ResourcePolicyError("subprocess retained limit differs from merged Q1")
    if subprocess_policy.get("command_timeout_seconds") != constants["_COMMAND_TIMEOUT_SECONDS"]:
        raise P4ResourcePolicyError("subprocess timeout differs from merged Q1")
    if subprocess_policy.get("breach_action") != "terminate_owned_process_group":
        raise P4ResourcePolicyError("subprocess breach action mismatch")
    if subprocess_policy.get("breach_outcome") != "resource_limit":
        raise P4ResourcePolicyError("subprocess breach outcome mismatch")
    if subprocess_policy.get("implementation_path") != RUNNER_REL:
        raise P4ResourcePolicyError("subprocess implementation path mismatch")

    candidate = _mapping(limits.get("candidate_source"), "limits.candidate_source")
    _exact_keys(candidate, {"max_bytes", "allowed_files"}, "limits.candidate_source")
    candidate_trust = _mapping(trust.get("candidate"), "trust.candidate")
    if candidate.get("max_bytes") != candidate_trust.get("max_source_bytes"):
        raise P4ResourcePolicyError("candidate source budget differs from trust boundary")
    if candidate.get("allowed_files") != 1:
        raise P4ResourcePolicyError("candidate source allowed_files must be 1")

    docker = _mapping(limits.get("docker_runtime"), "limits.docker_runtime")
    _exact_keys(
        docker,
        {
            "memory_bytes",
            "pids_limit",
            "nano_cpus",
            "tmpfs_bytes",
            "log_driver",
            "log_max_size_bytes",
            "log_max_files",
            "max_owned_containers_per_attempt",
            "max_owned_networks_per_attempt",
            "max_owned_volumes_per_attempt",
        },
        "limits.docker_runtime",
    )
    expected_docker = {
        "memory_bytes": 268_435_456,
        "pids_limit": 64,
        "nano_cpus": 500_000_000,
        "tmpfs_bytes": 16_777_216,
        "log_driver": "local",
        "log_max_size_bytes": 1_048_576,
        "log_max_files": 2,
        "max_owned_containers_per_attempt": 5,
        "max_owned_networks_per_attempt": 3,
        "max_owned_volumes_per_attempt": 2,
    }
    if docker != expected_docker:
        raise P4ResourcePolicyError("docker runtime policy differs from frozen v1")

    build = _mapping(limits.get("build"), "limits.build")
    _exact_keys(build, {"timeout_seconds", "log_output_bytes", "context_bytes"}, "limits.build")
    if build != {"timeout_seconds": 300, "log_output_bytes": 1_048_576, "context_bytes": 2_097_152}:
        raise P4ResourcePolicyError("build policy differs from frozen v1")

    artifacts = _mapping(limits.get("artifacts"), "limits.artifacts")
    _exact_keys(
        artifacts,
        {"total_bytes", "per_file_bytes", "max_files", "max_depth"},
        "limits.artifacts",
    )
    if artifacts != {
        "total_bytes": 16_777_216,
        "per_file_bytes": 4_194_304,
        "max_files": 128,
        "max_depth": 8,
    }:
        raise P4ResourcePolicyError("artifact policy differs from frozen v1")
    if _positive_int(artifacts["per_file_bytes"], "artifacts.per_file_bytes") > _positive_int(
        artifacts["total_bytes"], "artifacts.total_bytes"
    ):
        raise P4ResourcePolicyError("artifact per-file limit exceeds total limit")

    fixture = _mapping(limits.get("fixture_traffic"), "limits.fixture_traffic")
    _exact_keys(
        fixture,
        {"request_bytes", "response_bytes", "max_requests", "aggregate_bytes"},
        "limits.fixture_traffic",
    )
    if fixture != {
        "request_bytes": 65_536,
        "response_bytes": 262_144,
        "max_requests": 512,
        "aggregate_bytes": 8_388_608,
    }:
        raise P4ResourcePolicyError("fixture traffic policy differs from frozen v1")

    execution = _mapping(limits.get("execution"), "limits.execution")
    _exact_keys(
        execution,
        {"attempt_timeout_seconds", "cleanup_timeout_seconds", "max_concurrent_attempts"},
        "limits.execution",
    )
    if execution != {
        "attempt_timeout_seconds": 600,
        "cleanup_timeout_seconds": 60,
        "max_concurrent_attempts": 1,
    }:
        raise P4ResourcePolicyError("execution policy differs from frozen v1")

    archive = _mapping(policy.get("archive_extraction"), "archive_extraction")
    _exact_keys(
        archive,
        {
            "compressed_bytes",
            "expanded_bytes",
            "max_files",
            "max_depth",
            "max_expansion_ratio",
            "reject_absolute_paths",
            "reject_parent_traversal",
            "reject_symlinks",
            "reject_hardlinks",
            "reject_device_entries",
            "reject_duplicate_names",
            "reject_type_collisions",
        },
        "archive_extraction",
    )
    expected_archive = {
        "compressed_bytes": 16_777_216,
        "expanded_bytes": 33_554_432,
        "max_files": 128,
        "max_depth": 8,
        "max_expansion_ratio": 20,
        "reject_absolute_paths": True,
        "reject_parent_traversal": True,
        "reject_symlinks": True,
        "reject_hardlinks": True,
        "reject_device_entries": True,
        "reject_duplicate_names": True,
        "reject_type_collisions": True,
    }
    if archive != expected_archive:
        raise P4ResourcePolicyError("archive extraction policy differs from frozen v1")

    json_policy = _mapping(policy.get("json_intake"), "json_intake")
    _exact_keys(
        json_policy,
        {
            "max_bytes",
            "max_depth",
            "max_string_bytes",
            "max_array_items",
            "max_object_members",
            "duplicate_keys",
            "schema_version_required",
            "field_types",
        },
        "json_intake",
    )
    expected_json = {
        "max_bytes": 1_048_576,
        "max_depth": 32,
        "max_string_bytes": 65_536,
        "max_array_items": 1024,
        "max_object_members": 1024,
        "duplicate_keys": "reject",
        "schema_version_required": True,
        "field_types": "strict",
    }
    if json_policy != expected_json:
        raise P4ResourcePolicyError("JSON intake policy differs from frozen v1")

    cleanup = _mapping(policy.get("cleanup_semantics"), "cleanup_semantics")
    _exact_keys(
        cleanup,
        {"malformed_or_missing_evidence_outcome", "recovery_required", "fabricate_clean_state"},
        "cleanup_semantics",
    )
    if cleanup != {
        "malformed_or_missing_evidence_outcome": "UNKNOWN",
        "recovery_required": True,
        "fabricate_clean_state": False,
    }:
        raise P4ResourcePolicyError("cleanup semantics differ from frozen v1")

    proofs = policy.get("required_before_hostile_execution")
    if proofs != EXPECTED_REQUIRED_PROOFS:
        raise P4ResourcePolicyError("required hostile-execution proof list differs")

    controller = _mapping(trust.get("controller"), "trust.controller")
    if controller.get("controller_stage") != "INTAKE_ONLY":
        raise P4ResourcePolicyError("controller must remain INTAKE_ONLY")
    if controller.get("candidate_execution_enabled") is not False:
        raise P4ResourcePolicyError("controller candidate execution must remain disabled")
    publisher = _mapping(trust.get("publisher"), "trust.publisher")
    if publisher.get("bootstrap_status") != "UNBOOTSTRAPPED":
        raise P4ResourcePolicyError("publisher must remain unbootstrapped")
    if publisher.get("integration_id") is not None:
        raise P4ResourcePolicyError("publisher integration must remain unset")
    promotion = _mapping(trust.get("p3_promotion"), "trust.p3_promotion")
    if promotion.get("status") != "PROMOTED" or promotion.get("authority_generation") != 1:
        raise P4ResourcePolicyError("promoted P3 authority generation 1 is not active")

    binding = _mapping(trust.get("p4_resource_policy"), "trust.p4_resource_policy")
    _exact_keys(
        binding,
        {
            "status",
            "stage",
            "policy_path",
            "policy_sha256",
            "validator_path",
            "candidate_execution_enabled",
            "runtime_enforcement_proven",
        },
        "trust.p4_resource_policy",
    )
    if binding != {
        "status": "PRE_P4_RESOURCE_POLICY_FROZEN",
        "stage": "POLICY_FOUNDATION_ONLY",
        "policy_path": POLICY_REL,
        "policy_sha256": _sha256(policy_path),
        "validator_path": VALIDATOR_REL,
        "candidate_execution_enabled": False,
        "runtime_enforcement_proven": False,
    }:
        raise P4ResourcePolicyError("trust-boundary P4 resource policy binding mismatch")

    consumed = trust.get("consumed_trusted_inputs")
    if not isinstance(consumed, list) or not all(isinstance(item, str) for item in consumed):
        raise P4ResourcePolicyError("consumed_trusted_inputs must be a string list")
    for required in (POLICY_REL, VALIDATOR_REL):
        if consumed.count(required) != 1:
            raise P4ResourcePolicyError(f"consumed trusted input count mismatch: {required}")

    return policy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--trust-boundary", type=Path, required=True)
    args = parser.parse_args()
    policy = validate(args.repo.resolve(), args.policy.resolve(), args.trust_boundary.resolve())
    print(
        json.dumps(
            {
                "status": "P4_RESOURCE_POLICY_VALID",
                "profile_id": policy["profile_id"],
                "candidate_execution_enabled": policy["candidate_execution_enabled"],
                "runtime_enforcement_proven": policy["runtime_enforcement_proven"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
