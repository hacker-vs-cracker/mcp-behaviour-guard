from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
MODULE = CI / "p4_candidate_materialization.py"
TRUST = CI / "trust-boundary.json"
WORKFLOW = ROOT / ".github/workflows/phase2-trusted-intake.yml"
AUTHORITY = CI / "p3-promoted-authority.json"
REPOSITORY = "hacker-vs-cracker/mcp-behaviour-guard"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "phase2_p4_candidate_materialization_test", MODULE
    )
    if spec is None or spec.loader is None:
        raise AssertionError("could not load P4 candidate materialization module")
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


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _plan(trusted: str) -> dict[str, object]:
    trust = json.loads(TRUST.read_text(encoding="utf-8"))
    authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    return {
        "schema_version": 1,
        "stage": "P4_CONTROLLER_PLAN_ONLY",
        "trusted_controller": {
            "commit_sha": trusted,
            "trust_boundary_sha256": _sha256(TRUST),
            "workflow_path": ".github/workflows/phase2-trusted-intake.yml",
            "workflow_sha256": _sha256(WORKFLOW),
        },
        "eligible_workflow": {
            "workflow_id": 316477065,
            "workflow_name": "ci",
            "run_id": 9001,
            "run_attempt": 2,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "failure",
            "conclusion_is_authoritative": False,
        },
        "pull_request": {
            "number": 77,
            "state": "open",
            "head_sha": "a" * 40,
            "head_ref": "feature/example",
            "base_sha": "b" * 40,
            "base_ref": "main",
            "repository": REPOSITORY,
            "current_identity_source": "trusted-github-rest-commit-pulls",
        },
        "promoted_authority": {
            "generation": trust["p3_promotion"]["authority_generation"],
            "authority_sha256": trust["p3_promotion"]["authority_sha256"],
            "approval_bundle_digest": trust["p3_promotion"]["approval_bundle_digest"],
            "platform": authority["platform"],
        },
        "resource_controls": {
            "policy_sha256": trust["p4_resource_policy"]["policy_sha256"],
            "enforcement_module_sha256": trust["p4_resource_enforcement"]["module_sha256"],
            "runtime_enforcement_proven": False,
        },
        "candidate": {
            "source_path": "assurance/phase2/vertical/candidate_server.py",
            "trusted_dockerfile_path": "assurance/phase2/vertical/Dockerfile",
            "source_scope": "same-repository-pull-request-only",
            "materialization_performed": False,
            "execution_enabled": False,
            "hostile_execution_authorized": False,
            "execution_time_current_pr_recheck_required": True,
        },
        "publisher": {
            "enabled": False,
            "bootstrap_status": "UNBOOTSTRAPPED",
            "integration_id": None,
        },
    }


def _write_plan(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _fake_fetcher(
    candidate: bytes,
    *,
    stale_pr: bool = False,
    final_mode: str = "100644",
    declared_size: int | None = None,
    truncated_tree: bool = False,
) -> tuple[Any, list[str]]:
    calls: list[str] = []
    shas = {
        "root": "1" * 40,
        "assurance": "2" * 40,
        "phase2": "3" * 40,
        "vertical": "4" * 40,
        "blob": "5" * 40,
    }
    size = len(candidate) if declared_size is None else declared_size

    def fetch(url: str, _token: str, _policy: dict[str, Any]) -> dict[str, Any]:
        calls.append(url)
        if url.endswith("/pulls/77"):
            return {
                "number": 77,
                "state": "open",
                "head": {
                    "sha": ("c" * 40) if stale_pr else ("a" * 40),
                    "ref": "feature/example",
                    "repo": {"full_name": REPOSITORY},
                },
                "base": {
                    "sha": "b" * 40,
                    "ref": "main",
                    "repo": {"full_name": REPOSITORY},
                },
            }
        if url.endswith(f"/git/commits/{'a' * 40}"):
            return {"tree": {"sha": shas["root"]}}
        if url.endswith(f"/git/trees/{shas['root']}"):
            return {
                "truncated": False,
                "tree": [
                    {
                        "path": "assurance",
                        "mode": "040000",
                        "type": "tree",
                        "sha": shas["assurance"],
                    }
                ],
            }
        if url.endswith(f"/git/trees/{shas['assurance']}"):
            return {
                "truncated": False,
                "tree": [
                    {
                        "path": "phase2",
                        "mode": "040000",
                        "type": "tree",
                        "sha": shas["phase2"],
                    }
                ],
            }
        if url.endswith(f"/git/trees/{shas['phase2']}"):
            return {
                "truncated": False,
                "tree": [
                    {
                        "path": "vertical",
                        "mode": "040000",
                        "type": "tree",
                        "sha": shas["vertical"],
                    }
                ],
            }
        if url.endswith(f"/git/trees/{shas['vertical']}"):
            return {
                "truncated": truncated_tree,
                "tree": [
                    {
                        "path": "candidate_server.py",
                        "mode": final_mode,
                        "type": "blob",
                        "sha": shas["blob"],
                        "size": size,
                    }
                ],
            }
        if url.endswith(f"/git/blobs/{shas['blob']}"):
            return {
                "sha": shas["blob"],
                "size": size,
                "encoding": "base64",
                "content": base64.b64encode(candidate).decode("ascii"),
            }
        raise AssertionError(f"unexpected URL: {url}")

    return fetch, calls


def test_static_binding_is_wiring_only_and_nonexecuting() -> None:
    module = _module()
    trusted = _git("rev-parse", "HEAD")
    value = module.validate_static_binding(ROOT, trusted)
    binding = value["trust"]["p4_candidate_materialization"]
    assert binding["status"] == "WIRED_NOT_LIVE_PROVEN"
    assert binding["current_pr_recheck_required"] is True
    assert binding["candidate_context_outside_trusted_checkout"] is True
    assert binding["candidate_context_destroyed_before_artifact_upload"] is True
    assert binding["candidate_execution_enabled"] is False
    assert binding["hostile_execution_authorized"] is False
    assert binding["runtime_enforcement_proven"] is False
    assert binding["verdict_publication_enabled"] is False


def test_materialization_rechecks_current_pr_materializes_exact_blob_and_destroys_context(
    tmp_path: Path,
) -> None:
    module = _module()
    trusted = _git("rev-parse", "HEAD")
    candidate = b"print('candidate from exact PR head')\n"
    fetch, calls = _fake_fetcher(candidate)
    context = tmp_path / "candidate-context"
    manifest_path = tmp_path / "materialization.json"

    value = module.materialize_proof(
        repo=ROOT,
        plan_path=_write_plan(tmp_path, _plan(trusted)),
        trusted_commit=trusted,
        expected_repository=REPOSITORY,
        api_url="https://api.github.com",
        token="test-token",
        context_dir=context,
        manifest_path=manifest_path,
        fetch_json=fetch,
    )

    assert value["stage"] == "P4_CANDIDATE_MATERIALIZATION_PROOF_ONLY"
    assert value["pull_request"]["current_identity_rechecked"] is True
    assert value["candidate"]["sha256"] == hashlib.sha256(candidate).hexdigest()
    assert value["candidate"]["source_retained_after_proof"] is False
    assert value["resource_controls"]["context_budget"]["files"] == 2
    assert value["resource_controls"]["runtime_enforcement_proven"] is False
    assert value["lifecycle"] == {
        "context_outside_trusted_checkout": True,
        "context_destroyed_before_manifest_write": True,
        "candidate_execution_performed": False,
        "hostile_execution_authorized": False,
        "verdict_publication_performed": False,
    }
    assert not context.exists()
    assert manifest_path.is_file()
    assert calls[0].endswith("/pulls/77")
    assert calls[-1].endswith(f"/git/blobs/{'5' * 40}")


def test_stale_current_pr_is_rejected_before_candidate_tree_lookup(tmp_path: Path) -> None:
    module = _module()
    trusted = _git("rev-parse", "HEAD")
    fetch, calls = _fake_fetcher(b"print('candidate')\n", stale_pr=True)
    with pytest.raises(module.P4CandidateMaterializationError, match="current PR identity changed"):
        module.materialize_proof(
            repo=ROOT,
            plan_path=_write_plan(tmp_path, _plan(trusted)),
            trusted_commit=trusted,
            expected_repository=REPOSITORY,
            api_url="https://api.github.com",
            token="test-token",
            context_dir=tmp_path / "context",
            manifest_path=tmp_path / "manifest.json",
            fetch_json=fetch,
        )
    assert len(calls) == 1
    assert not (tmp_path / "context").exists()


@pytest.mark.parametrize(
    ("mode", "size", "truncated", "message"),
    [
        ("120000", None, False, "unexpected type/mode"),
        ("100644", 524289, False, "exceeds max_source_bytes"),
        ("100644", None, True, "truncated or ambiguous"),
    ],
)
def test_tree_boundary_rejects_symlink_oversize_or_truncated_before_blob_fetch(
    tmp_path: Path,
    mode: str,
    size: int | None,
    truncated: bool,
    message: str,
) -> None:
    module = _module()
    trusted = _git("rev-parse", "HEAD")
    fetch, calls = _fake_fetcher(
        b"print('candidate')\n",
        final_mode=mode,
        declared_size=size,
        truncated_tree=truncated,
    )
    with pytest.raises(module.P4CandidateMaterializationError, match=message):
        module.materialize_proof(
            repo=ROOT,
            plan_path=_write_plan(tmp_path, _plan(trusted)),
            trusted_commit=trusted,
            expected_repository=REPOSITORY,
            api_url="https://api.github.com",
            token="test-token",
            context_dir=tmp_path / "context",
            manifest_path=tmp_path / "manifest.json",
            fetch_json=fetch,
        )
    assert not any("/git/blobs/" in url for url in calls)
    assert not (tmp_path / "context").exists()


def test_context_inside_trusted_checkout_or_wrong_api_origin_is_rejected(tmp_path: Path) -> None:
    module = _module()
    trusted = _git("rev-parse", "HEAD")
    fetch, calls = _fake_fetcher(b"print('candidate')\n")

    with pytest.raises(module.P4CandidateMaterializationError, match="outside trusted checkout"):
        module.materialize_proof(
            repo=ROOT,
            plan_path=_write_plan(tmp_path, _plan(trusted)),
            trusted_commit=trusted,
            expected_repository=REPOSITORY,
            api_url="https://api.github.com",
            token="test-token",
            context_dir=ROOT / ".candidate-context-forbidden",
            manifest_path=tmp_path / "manifest.json",
            fetch_json=fetch,
        )
    assert calls == []

    with pytest.raises(module.P4CandidateMaterializationError, match="GitHub API URL"):
        module.materialize_proof(
            repo=ROOT,
            plan_path=_write_plan(tmp_path, _plan(trusted)),
            trusted_commit=trusted,
            expected_repository=REPOSITORY,
            api_url="https://api.github.com.attacker.invalid",
            token="test-token",
            context_dir=tmp_path / "context",
            manifest_path=tmp_path / "manifest-2.json",
            fetch_json=fetch,
        )
    assert calls == []


def test_workflow_materializes_to_runner_temp_and_uploads_only_manifest() -> None:
    value = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict)
    assert value["permissions"] == {"contents": "read", "pull-requests": "read"}
    job = value["jobs"]["intake"]
    names = [step.get("name") for step in job["steps"]]
    assert "Materialize exact candidate for non-executing P4 proof" in names
    step = next(
        item
        for item in job["steps"]
        if item.get("name") == "Materialize exact candidate for non-executing P4 proof"
    )
    run = str(step["run"])
    assert "$RUNNER_TEMP/phase2c-candidate-materialization" in run
    assert "p4_candidate_materialization.py" in run

    upload = next(
        item for item in job["steps"] if item.get("name") == "Upload normalized trusted intake"
    )
    upload_paths = str(upload["with"]["path"])
    assert "phase2c-intake/p4-candidate-materialization.json" in upload_paths
    assert "candidate_server.py" not in upload_paths
    assert "phase2c-candidate-materialization" not in upload_paths

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
