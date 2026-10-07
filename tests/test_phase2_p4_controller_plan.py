from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
MODULE = CI / "p4_controller_plan.py"
TRUST = CI / "trust-boundary.json"
POLICY = CI / "p4-resource-policy.json"
ENFORCEMENT = CI / "p4_resource_enforcement.py"
AUTHORITY = CI / "p3-promoted-authority.json"
WORKFLOW = ROOT / ".github/workflows/phase2-trusted-intake.yml"
REPOSITORY = "hacker-vs-cracker/mcp-behaviour-guard"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase2_p4_controller_plan_test", MODULE)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load P4 controller plan module")
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
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _trusted_repo(tmp_path: Path, *, tamper_authority: bool = False) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "phase2c@example.invalid")
    _git(repo, "config", "user.name", "Phase 2C Test")

    for source in (TRUST, POLICY, ENFORCEMENT, AUTHORITY, MODULE, WORKFLOW):
        relative = source.relative_to(ROOT)
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())

    if tamper_authority:
        path = repo / AUTHORITY.relative_to(ROOT)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["generation"]["number"] = 2
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "trusted controller")
    return repo, _git(repo, "rev-parse", "HEAD")


def _intake(repo: Path, trusted: str) -> dict[str, object]:
    trust_raw = (repo / TRUST.relative_to(ROOT)).read_bytes()
    return {
        "schema_version": 1,
        "source_event": "workflow_run",
        "repository": {"full_name": REPOSITORY},
        "trusted_controller": {
            "commit_sha": trusted,
            "trust_boundary_sha256": _sha256(trust_raw),
        },
        "upstream": {
            "workflow_id": 316477065,
            "workflow_name": "ci",
            "run_id": 9001,
            "run_attempt": 2,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "failure",
            "conclusion_is_authoritative": False,
            "event_pull_requests_are_authority": False,
        },
        "pull_request": {
            "number": 77,
            "state": "open",
            "head_sha": "a" * 40,
            "head_ref": "feature/example",
            "head_repository": REPOSITORY,
            "base_sha": "b" * 40,
            "base_ref": "main",
            "base_repository": REPOSITORY,
            "source_scope": "same-repository-pull-request-only",
            "lookup_source": "trusted-github-rest-commit-pulls",
        },
        "authority": {
            "candidate_workflow_artifacts_are_authority": False,
            "upstream_ci_conclusion_is_phase2_verdict": False,
            "workflow_run_event_pull_requests_are_authority": False,
            "stale_workflow_run_rejected_if_current_pr_head_moved": True,
        },
    }


def _write_intake(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "intake.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_static_binding_is_plan_only_and_non_executing(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    value = module.validate_static_binding(repo, trusted)
    binding = value["trust"]["p4_controller_plan"]
    assert binding["status"] == "PLAN_ONLY_NOT_RUNTIME_PROVEN"
    assert binding["candidate_materialization_performed"] is False
    assert binding["candidate_execution_enabled"] is False
    assert binding["hostile_execution_authorized"] is False
    assert binding["runtime_enforcement_proven"] is False
    assert binding["verdict_publication_enabled"] is False


def test_build_plan_binds_current_pr_workflow_and_promoted_generation(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    output = tmp_path / "plan.json"
    value = module.build_plan(
        repo=repo,
        intake_path=_write_intake(tmp_path, _intake(repo, trusted)),
        trusted_commit=trusted,
        output_path=output,
    )
    assert value["eligible_workflow"]["run_id"] == 9001
    assert value["eligible_workflow"]["run_attempt"] == 2
    assert value["eligible_workflow"]["conclusion"] == "failure"
    assert value["eligible_workflow"]["conclusion_is_authoritative"] is False
    assert value["pull_request"]["number"] == 77
    assert value["pull_request"]["head_sha"] == "a" * 40
    assert value["pull_request"]["base_sha"] == "b" * 40
    assert value["promoted_authority"]["generation"] == 1
    assert value["candidate"]["materialization_performed"] is False
    assert value["candidate"]["execution_enabled"] is False
    assert value["publisher"]["enabled"] is False
    assert output.is_file()


def test_plan_rejects_intake_trust_digest_or_workflow_identity_mismatch(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)

    intake = _intake(repo, trusted)
    controller = intake["trusted_controller"]
    assert isinstance(controller, dict)
    controller["trust_boundary_sha256"] = "0" * 64
    with pytest.raises(module.P4ControllerPlanError, match="trust-boundary digest"):
        module.build_plan(
            repo=repo,
            intake_path=_write_intake(tmp_path, intake),
            trusted_commit=trusted,
            output_path=tmp_path / "bad-plan.json",
        )

    intake = _intake(repo, trusted)
    upstream = intake["upstream"]
    assert isinstance(upstream, dict)
    upstream["workflow_id"] = 123
    with pytest.raises(module.P4ControllerPlanError, match="workflow id mismatch"):
        module.build_plan(
            repo=repo,
            intake_path=_write_intake(tmp_path, intake),
            trusted_commit=trusted,
            output_path=tmp_path / "bad-plan-2.json",
        )


def test_plan_rejects_wrong_pr_scope_or_authority_flags(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)

    intake = _intake(repo, trusted)
    pr = intake["pull_request"]
    assert isinstance(pr, dict)
    pr["base_ref"] = "develop"
    with pytest.raises(module.P4ControllerPlanError, match="base ref"):
        module.build_plan(
            repo=repo,
            intake_path=_write_intake(tmp_path, intake),
            trusted_commit=trusted,
            output_path=tmp_path / "bad-plan.json",
        )

    intake = _intake(repo, trusted)
    authority = intake["authority"]
    assert isinstance(authority, dict)
    authority["upstream_ci_conclusion_is_phase2_verdict"] = True
    with pytest.raises(module.P4ControllerPlanError, match="authority flag"):
        module.build_plan(
            repo=repo,
            intake_path=_write_intake(tmp_path, intake),
            trusted_commit=trusted,
            output_path=tmp_path / "bad-plan-2.json",
        )


def test_static_binding_rejects_tampered_promoted_authority(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path, tamper_authority=True)
    with pytest.raises(module.P4ControllerPlanError, match="authority digest"):
        module.validate_static_binding(repo, trusted)


def test_workflow_builds_and_uploads_plan_without_execution_permissions() -> None:
    value = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict)
    assert value["permissions"] == {"contents": "read", "pull-requests": "read"}
    job = value["jobs"]["intake"]
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    assert "Build non-executing P4 controller plan" in names
    upload = next(step for step in steps if step.get("name") == "Upload normalized trusted intake")
    paths = str(upload["with"]["path"])
    assert "phase2c-intake/intake.json" in paths
    assert "phase2c-intake/p4-controller-plan.json" in paths
    source = WORKFLOW.read_text(encoding="utf-8")
    for forbidden in (
        "docker run",
        "docker build",
        "git fetch",
        "pull_request_target",
        "statuses: write",
        "checks: write",
        "id-token: write",
        "secrets.",
    ):
        assert forbidden not in source
