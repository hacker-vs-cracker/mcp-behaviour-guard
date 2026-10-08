from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
MODULE = CI / "p4_runtime_enforcement_plan.py"
TRUST = CI / "trust-boundary.json"
POLICY = CI / "p4-resource-policy.json"
ENFORCEMENT = CI / "p4_resource_enforcement.py"
AUTHORITY = CI / "p3-promoted-authority.json"
PROOF = CI / "p4-live-materialization-proof.json"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase2_p4_runtime_plan_test", MODULE)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load P4 runtime enforcement plan module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    search_path = str(CI)
    added = search_path not in sys.path
    if added:
        sys.path.insert(0, search_path)
    try:
        spec.loader.exec_module(module)
    finally:
        if added:
            sys.path.remove(search_path)
    return module


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _trusted_repo(tmp_path: Path, *, tamper_proof: bool = False) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "phase2c@example.invalid")
    _git(repo, "config", "user.name", "Phase 2C Test")
    for source in (TRUST, POLICY, ENFORCEMENT, AUTHORITY, PROOF, MODULE):
        relative = source.relative_to(ROOT)
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    if tamper_proof:
        path = repo / PROOF.relative_to(ROOT)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["candidate_execution_performed"] = True
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "trusted runtime plan")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_static_binding_is_non_executing_and_bound_to_accepted_live_proof(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    value = module.validate_static_binding(repo, trusted)
    binding = value["trust"]["p4_runtime_enforcement_plan"]
    assert binding["status"] == "PLAN_ONLY_NOT_RUNTIME_PROVEN"
    assert binding["candidate_execution_enabled"] is False
    assert binding["runtime_execution_enabled"] is False
    assert binding["hostile_execution_authorized"] is False
    assert binding["runtime_enforcement_proven"] is False
    assert value["proof"]["status"] == "ACCEPTED_NON_EXECUTING"


def test_build_plan_derives_exact_frozen_runtime_limits(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    output = tmp_path / "runtime-plan.json"
    plan = module.build_plan(repo=repo, trusted_commit=trusted, output_path=output)
    assert plan["docker"]["resource_args"] == [
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "64",
        "--memory",
        "268435456",
        "--cpus",
        "0.50",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "--log-driver",
        "local",
        "--log-opt",
        "max-size=1m",
        "--log-opt",
        "max-file=2",
    ]
    assert plan["docker"]["max_owned_containers"] == 5
    assert plan["docker"]["max_owned_networks"] == 3
    assert plan["docker"]["max_owned_volumes"] == 2
    assert plan["build"] == {
        "timeout_seconds": 300,
        "output_budget_bytes": 1048576,
        "context_bytes": 2097152,
    }
    assert plan["subprocess"] == {
        "timeout_seconds": 120,
        "output_budget_bytes": 1048576,
        "capture_limit_bytes": 131072,
    }
    assert plan["fixture_traffic"] == {
        "request_bytes": 65536,
        "response_bytes": 262144,
        "max_requests": 512,
        "aggregate_bytes": 8388608,
    }
    assert plan["execution"] == {
        "attempt_timeout_seconds": 600,
        "cleanup_timeout_seconds": 60,
        "max_concurrent_attempts": 1,
    }
    assert output.is_file()


def test_plan_covers_every_frozen_pre_hostile_requirement(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    plan = module.build_plan(repo=repo, trusted_commit=trusted, output_path=tmp_path / "plan.json")
    assert set(plan["proof_cases"]) == set(plan["required_before_hostile_execution"])
    assert all(item["status"] == "PLANNED_NOT_PROVEN" for item in plan["proof_cases"].values())
    assert plan["next_boundary"]["hostile_execution_allowed_after_this_plan"] is False


def test_static_binding_rejects_tampered_live_materialization_proof(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path, tamper_proof=True)
    with pytest.raises(module.P4RuntimeEnforcementPlanError, match="proof trust binding|executed"):
        module.validate_static_binding(repo, trusted)


def test_cleanup_policy_remains_fail_closed(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    plan = module.build_plan(repo=repo, trusted_commit=trusted, output_path=tmp_path / "plan.json")
    assert plan["cleanup_semantics"] == {
        "malformed_or_missing_evidence_outcome": "UNKNOWN",
        "recovery_required": True,
        "fabricate_clean_state": False,
    }
    assert (
        "malformed_cleanup_returns_unknown_recovery_required"
        in plan["proof_cases"]["malformed_cleanup_maps_to_unknown"]["cases"]
    )


def test_runtime_plan_module_has_no_execution_or_remote_mutation_surface() -> None:
    source = MODULE.read_text(encoding="utf-8")
    for forbidden in (
        "subprocess.Popen",
        "docker run",
        "docker build",
        "gh api",
        "urllib.request",
        "workflow_dispatch",
        "statuses: write",
        "checks: write",
    ):
        assert forbidden not in source


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("reference.approval_bundle_digest", "0" * 64, "approval digest"),
        ("platform", "linux/arm64", "platform"),
        ("generation.number", 1.0, "generation"),
        ("generation.number", 2, "generation"),
        ("generation.supersedes", 0, "generation"),
        ("consumable", False, "consumable"),
        ("publisher.status", "BOOTSTRAPPED", "publisher"),
    ],
)
def test_r24_committed_inconsistent_authority_rejected(
    tmp_path: Path, field: str, value: object, match: str
) -> None:
    module = _module()
    repo, _ = _trusted_repo(tmp_path)
    path = repo / AUTHORITY.relative_to(ROOT)
    doc = json.loads(path.read_text(encoding="utf-8"))
    cursor = doc
    keys = field.split(".")
    for key in keys[:-1]:
        cursor = cursor[key]
    cursor[keys[-1]] = value
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    trust_path = repo / TRUST.relative_to(ROOT)
    trust_doc = json.loads(trust_path.read_text(encoding="utf-8"))
    import hashlib

    trust_doc["p3_promotion"]["authority_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    trust_path.write_text(json.dumps(trust_doc, indent=2) + "\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "mutate fixture authority")
    with pytest.raises(module.P4RuntimeEnforcementPlanError, match=match):
        module.validate_static_binding(repo, _git(repo, "rev-parse", "HEAD"))


def test_r24_committed_stale_authority_digest_rejected(tmp_path: Path) -> None:
    module = _module()
    repo, _ = _trusted_repo(tmp_path)
    path = repo / AUTHORITY.relative_to(ROOT)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["reference"]["approval_bundle_digest"] = "0" * 64
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "mutate fixture authority without rebinding")
    with pytest.raises(module.P4RuntimeEnforcementPlanError, match="authority digest"):
        module.validate_static_binding(repo, _git(repo, "rev-parse", "HEAD"))
