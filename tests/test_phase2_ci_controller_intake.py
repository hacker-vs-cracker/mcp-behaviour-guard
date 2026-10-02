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
REPOSITORY = "hacker-vs-cracker/mcp-behaviour-guard"


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


def _event(head_sha: str) -> dict[str, object]:
    repository = {"full_name": REPOSITORY}
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
            # Real repository history demonstrated this can be empty.
            "pull_requests": [],
        },
    }


def _pr(
    *,
    number: int = 77,
    state: str = "open",
    head_sha: str = "a" * 40,
    head_ref: str = "feature/example",
    head_repo: str = REPOSITORY,
    base_sha: str = "b" * 40,
    base_ref: str = "main",
    base_repo: str = REPOSITORY,
) -> dict[str, object]:
    return {
        "number": number,
        "state": state,
        "head": {
            "sha": head_sha,
            "ref": head_ref,
            "repo": {"full_name": head_repo},
        },
        "base": {
            "sha": base_sha,
            "ref": base_ref,
            "repo": {"full_name": base_repo},
        },
    }


def _write(tmp_path: Path, name: str, value: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _resolve(
    module: ModuleType,
    *,
    tmp_path: Path,
    repo: Path,
    trusted: str,
    event: dict[str, object],
    lookup: list[dict[str, object]],
) -> dict[str, object]:
    return module.resolve(
        repo=repo,
        event_path=_write(tmp_path, "event.json", event),
        pull_request_lookup_path=_write(tmp_path, "pulls.json", lookup),
        trusted_commit=trusted,
    )


def test_accepts_real_empty_event_pr_array_via_trusted_current_pr_lookup(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    value = _resolve(
        module,
        tmp_path=tmp_path,
        repo=repo,
        trusted=trusted,
        event=_event("a" * 40),
        lookup=[_pr()],
    )
    assert value["pull_request"]["number"] == 77
    assert value["pull_request"]["head_sha"] == "a" * 40
    assert value["pull_request"]["base_sha"] == "b" * 40
    assert value["pull_request"]["lookup_source"] == "trusted-github-rest-commit-pulls"
    assert value["upstream"]["event_pull_requests_are_authority"] is False
    assert value["upstream"]["conclusion"] == "failure"
    assert value["upstream"]["conclusion_is_authoritative"] is False


def test_event_pr_array_is_never_authority(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    event = _event("a" * 40)
    run = event["workflow_run"]
    assert isinstance(run, dict)
    run["pull_requests"] = [
        {
            "number": 999,
            "head": {"sha": "c" * 40},
            "base": {"sha": "d" * 40},
        }
    ]
    value = _resolve(
        module,
        tmp_path=tmp_path,
        repo=repo,
        trusted=trusted,
        event=event,
        lookup=[_pr(number=77)],
    )
    assert value["pull_request"]["number"] == 77
    assert value["authority"]["workflow_run_event_pull_requests_are_authority"] is False


def test_stale_workflow_run_is_rejected_after_pr_head_moves(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    with pytest.raises(
        module.WorkflowRunResolutionError,
        match="exactly one current PR matching workflow-run head",
    ):
        _resolve(
            module,
            tmp_path=tmp_path,
            repo=repo,
            trusted=trusted,
            event=_event("a" * 40),
            lookup=[_pr(head_sha="c" * 40)],
        )


@pytest.mark.parametrize(
    ("lookup", "message"),
    [
        ([_pr(state="closed")], "exactly one current PR"),
        ([_pr(head_repo="attacker/fork")], "exactly one current PR"),
        ([_pr(base_ref="develop")], "exactly one current PR"),
        ([_pr(), _pr(number=78)], "exactly one current PR"),
    ],
)
def test_rejects_closed_fork_wrong_base_or_ambiguous_current_pr(
    tmp_path: Path,
    lookup: list[dict[str, object]],
    message: str,
) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    with pytest.raises(module.WorkflowRunResolutionError, match=message):
        _resolve(
            module,
            tmp_path=tmp_path,
            repo=repo,
            trusted=trusted,
            event=_event("a" * 40),
            lookup=lookup,
        )


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
    event = _event("a" * 40)
    run = event["workflow_run"]
    assert isinstance(run, dict)
    run[field] = value
    with pytest.raises(module.WorkflowRunResolutionError, match=message):
        _resolve(
            module,
            tmp_path=tmp_path,
            repo=repo,
            trusted=trusted,
            event=event,
            lookup=[_pr()],
        )


def test_rejects_wrong_action_repository_or_dirty_trusted_checkout(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)

    event = _event("a" * 40)
    event["action"] = "requested"
    with pytest.raises(module.WorkflowRunResolutionError, match="workflow_run action mismatch"):
        _resolve(
            module,
            tmp_path=tmp_path,
            repo=repo,
            trusted=trusted,
            event=event,
            lookup=[_pr()],
        )

    event = _event("a" * 40)
    run = event["workflow_run"]
    assert isinstance(run, dict)
    run["head_repository"] = {"full_name": "attacker/fork"}
    with pytest.raises(
        module.WorkflowRunResolutionError, match="head_repository is not same-repository"
    ):
        _resolve(
            module,
            tmp_path=tmp_path,
            repo=repo,
            trusted=trusted,
            event=event,
            lookup=[_pr()],
        )

    (repo / "dirty.tmp").write_text("dirty", encoding="utf-8")
    with pytest.raises(
        module.WorkflowRunResolutionError, match="trusted controller checkout is dirty"
    ):
        _resolve(
            module,
            tmp_path=tmp_path,
            repo=repo,
            trusted=trusted,
            event=_event("a" * 40),
            lookup=[_pr()],
        )
