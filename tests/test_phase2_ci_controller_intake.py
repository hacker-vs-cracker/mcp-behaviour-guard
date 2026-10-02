from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
RESOLVER = ROOT / "assurance/phase2/ci/resolve_workflow_run.py"
BOUNDARY = ROOT / "assurance/phase2/ci/trust-boundary.json"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase2_ci_workflow_run_test", RESOLVER)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Phase 2C workflow_run resolver")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _trusted_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "phase2c@example.invalid")
    _git(repo, "config", "user.name", "Phase 2C Test")
    target = repo / "assurance/phase2/ci"
    target.mkdir(parents=True)
    (target / "trust-boundary.json").write_text(
        BOUNDARY.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "trusted controller")
    return repo, _git(repo, "rev-parse", "HEAD")


def _event(head_sha: str, base_sha: str) -> dict[str, object]:
    repository = {"full_name": "hacker-vs-cracker/mcp-behaviour-guard"}
    return {
        "action": "completed",
        "repository": repository,
        "workflow_run": {
            "id": 9001,
            "run_attempt": 2,
            "workflow_id": 316477065,
            "name": "ci",
            "event": "pull_request",
            "status": "completed",
            "conclusion": "failure",
            "head_sha": head_sha,
            "head_branch": "feature/example",
            "repository": repository,
            "head_repository": repository,
            "pull_requests": [
                {
                    "number": 77,
                    "head": {
                        "sha": head_sha,
                        "ref": "feature/example",
                        "repo": repository,
                    },
                    "base": {
                        "sha": base_sha,
                        "ref": "main",
                        "repo": repository,
                    },
                }
            ],
        },
    }


def _write_event(tmp_path: Path, value: dict[str, object]) -> Path:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_valid_workflow_run_binds_exact_pr_and_does_not_trust_upstream_conclusion(
    tmp_path: Path,
) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    value = module.resolve(
        repo=repo,
        event_path=_write_event(tmp_path, _event("a" * 40, "b" * 40)),
        trusted_commit=trusted,
    )
    assert value["trusted_controller"]["commit_sha"] == trusted
    assert value["upstream"]["conclusion"] == "failure"
    assert value["upstream"]["conclusion_is_authoritative"] is False
    assert value["pull_request"]["number"] == 77
    assert value["pull_request"]["head_sha"] == "a" * 40
    assert value["pull_request"]["base_sha"] == "b" * 40
    assert value["authority"]["upstream_ci_conclusion_is_phase2_verdict"] is False


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("workflow_id", 123, "workflow id mismatch"),
        ("name", "attacker-ci", "workflow name mismatch"),
        ("status", "in_progress", "workflow status mismatch"),
    ],
)
def test_rejects_wrong_upstream_identity(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    event = _event("a" * 40, "b" * 40)
    run = event["workflow_run"]
    assert isinstance(run, dict)
    run[field] = value
    with pytest.raises(module.WorkflowRunResolutionError, match=message):
        module.resolve(
            repo=repo,
            event_path=_write_event(tmp_path, event),
            trusted_commit=trusted,
        )


def test_rejects_wrong_action_or_fork_or_multiple_prs(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)

    event = _event("a" * 40, "b" * 40)
    event["action"] = "requested"
    with pytest.raises(module.WorkflowRunResolutionError, match="workflow_run action mismatch"):
        module.resolve(repo=repo, event_path=_write_event(tmp_path, event), trusted_commit=trusted)

    event = _event("a" * 40, "b" * 40)
    run = event["workflow_run"]
    assert isinstance(run, dict)
    run["head_repository"] = {"full_name": "attacker/fork"}
    with pytest.raises(
        module.WorkflowRunResolutionError, match="head_repository is not same-repository"
    ):
        module.resolve(repo=repo, event_path=_write_event(tmp_path, event), trusted_commit=trusted)

    event = _event("a" * 40, "b" * 40)
    run = event["workflow_run"]
    assert isinstance(run, dict)
    pulls = run["pull_requests"]
    assert isinstance(pulls, list)
    pulls.append(dict(pulls[0]))
    with pytest.raises(module.WorkflowRunResolutionError, match="exactly one associated PR"):
        module.resolve(repo=repo, event_path=_write_event(tmp_path, event), trusted_commit=trusted)


def test_rejects_head_mismatch_and_dirty_or_wrong_trusted_checkout(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    event = _event("a" * 40, "b" * 40)
    run = event["workflow_run"]
    assert isinstance(run, dict)
    run["head_sha"] = "c" * 40
    with pytest.raises(module.WorkflowRunResolutionError, match="head SHA differs"):
        module.resolve(repo=repo, event_path=_write_event(tmp_path, event), trusted_commit=trusted)

    event_path = _write_event(tmp_path, _event("a" * 40, "b" * 40))
    with pytest.raises(module.WorkflowRunResolutionError, match="trusted checkout HEAD differs"):
        module.resolve(repo=repo, event_path=event_path, trusted_commit="c" * 40)

    (repo / "untrusted.tmp").write_text("dirty", encoding="utf-8")
    with pytest.raises(
        module.WorkflowRunResolutionError, match="trusted controller checkout is dirty"
    ):
        module.resolve(repo=repo, event_path=event_path, trusted_commit=trusted)
