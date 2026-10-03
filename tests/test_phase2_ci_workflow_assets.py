from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/phase2-trusted-intake.yml"
COLLECTOR = ROOT / "assurance/phase2/ci/collect_workflow_run_intake.py"
BOUNDARY = ROOT / "assurance/phase2/ci/trust-boundary.json"

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase2_ci_collector_test", COLLECTOR)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Phase 2C collector")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    search_path = str(COLLECTOR.parent)
    added = search_path not in sys.path
    if added:
        sys.path.insert(0, search_path)
    try:
        spec.loader.exec_module(module)
    finally:
        if added:
            sys.path.remove(search_path)
    return module


def _workflow() -> dict[str, Any]:
    value = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    if not isinstance(value, dict):
        raise AssertionError("workflow YAML is not a mapping")
    return value


def _event() -> dict[str, object]:
    repository = {"full_name": "hacker-vs-cracker/mcp-behaviour-guard"}
    return {
        "action": "completed",
        "repository": repository,
        "workflow_run": {
            "id": 9001,
            "run_attempt": 1,
            "workflow_id": 316477065,
            "name": "ci",
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "a" * 40,
            "head_branch": "feature/example",
            "repository": repository,
            "head_repository": repository,
            "pull_requests": [],
        },
    }


def _pr() -> dict[str, object]:
    repository = {"full_name": "hacker-vs-cracker/mcp-behaviour-guard"}
    return {
        "number": 77,
        "state": "open",
        "head": {
            "sha": "a" * 40,
            "ref": "feature/example",
            "repo": repository,
        },
        "base": {
            "sha": "b" * 40,
            "ref": "main",
            "repo": repository,
        },
    }


def _trusted_repo(tmp_path: Path) -> tuple[Path, str]:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    git("init")
    git("config", "user.email", "phase2c@example.invalid")
    git("config", "user.name", "Phase 2C Test")
    target = repo / "assurance/phase2/ci"
    target.mkdir(parents=True)
    for source in (BOUNDARY, ROOT / "assurance/phase2/ci/resolve_workflow_run.py"):
        (target / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "trusted controller")
    return repo, git("rev-parse", "HEAD")


def test_workflow_is_intake_only_read_only_and_pinned() -> None:
    value = _workflow()
    assert value["name"] == "phase2-trusted-intake"
    trigger = value["on"]["workflow_run"]
    assert trigger["workflows"] == ["ci"]
    assert trigger["types"] == ["completed"]
    assert value["permissions"] == {"contents": "read", "pull-requests": "read"}

    jobs = value["jobs"]
    assert list(jobs) == ["intake"]
    job = jobs["intake"]
    assert job["if"] == "${{ github.event.workflow_run.event == 'pull_request' }}"
    assert job["timeout-minutes"] == "5"

    steps = job["steps"]
    uses = [step.get("uses") for step in steps if "uses" in step]
    assert uses == [
        f"actions/checkout@{CHECKOUT_SHA}",
        f"actions/setup-python@{SETUP_SHA}",
        f"actions/upload-artifact@{UPLOAD_SHA}",
    ]

    checkout = steps[0]
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "fetch-depth": "1",
        "persist-credentials": "false",
    }
    assert steps[1]["with"] == {"python-version": "3.11.14"}

    source = WORKFLOW.read_text(encoding="utf-8")
    for forbidden in (
        "pull_request_target",
        "docker ",
        "docker\n",
        "git fetch",
        "git checkout",
        "gh api",
        "statuses: write",
        "checks: write",
        "id-token: write",
    ):
        assert forbidden not in source
    assert "github.event.workflow_run.head_sha" not in source
    assert "secrets." not in source


def test_boundary_freezes_intake_only_stage() -> None:
    payload = json.loads(BOUNDARY.read_text(encoding="utf-8"))
    controller = payload["controller"]
    publisher = payload["publisher"]
    assert controller["controller_workflow_path"] == ".github/workflows/phase2-trusted-intake.yml"
    assert controller["controller_stage"] == "INTAKE_ONLY"
    assert controller["candidate_execution_enabled"] is False
    assert controller["verdict_publication_enabled"] is False
    assert controller["workflow_permissions"] == {
        "contents": "read",
        "pull-requests": "read",
    }
    assert publisher["bootstrap_status"] == "UNBOOTSTRAPPED"
    assert publisher["credential_available_to_controller_intake"] is False


def test_collector_fetches_only_exact_commit_pr_lookup_and_resolves(
    tmp_path: Path,
) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(_event()), encoding="utf-8")
    output = tmp_path / "out" / "intake.json"
    lookup_output = tmp_path / "out" / "lookup.json"

    seen: list[tuple[str, str]] = []

    def fetcher(url: str, token: str) -> object:
        seen.append((url, token))
        return [_pr()]

    value = module.collect(
        repo=repo,
        event_path=event_path,
        trusted_commit=trusted,
        expected_repository="hacker-vs-cracker/mcp-behaviour-guard",
        api_url="https://api.github.com",
        token="test-token",
        output=output,
        lookup_output=lookup_output,
        fetch_json=fetcher,
    )

    assert seen == [
        (
            "https://api.github.com/repos/hacker-vs-cracker/mcp-behaviour-guard/"
            f"commits/{'a' * 40}/pulls?per_page=100",
            "test-token",
        )
    ]
    assert value["pull_request"]["number"] == 77
    assert output.is_file()
    assert lookup_output.is_file()


def test_collector_resolves_before_writing_repo_local_evidence(
    tmp_path: Path,
) -> None:
    import subprocess

    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(_event()), encoding="utf-8")

    output = repo / "phase2c-intake" / "intake.json"
    lookup_output = repo / "phase2c-intake" / "pull-request-lookup.json"

    value = module.collect(
        repo=repo,
        event_path=event_path,
        trusted_commit=trusted,
        expected_repository="hacker-vs-cracker/mcp-behaviour-guard",
        api_url="https://api.github.com",
        token="test-token",
        output=output,
        lookup_output=lookup_output,
        fetch_json=lambda _url, _token: [_pr()],
    )

    assert value["pull_request"]["number"] == 77
    assert output.is_file()
    assert lookup_output.is_file()

    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain=v1", "--untracked-files=all"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert sorted(status) == [
        "?? phase2c-intake/intake.json",
        "?? phase2c-intake/pull-request-lookup.json",
    ]


def test_collector_rejects_api_origin_prefix_confusion_before_network(
    tmp_path: Path,
) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(_event()), encoding="utf-8")

    called = False

    def fetcher(_url: str, _token: str) -> object:
        nonlocal called
        called = True
        return []

    with pytest.raises(module.WorkflowRunCollectionError, match="GitHub API URL"):
        module.collect(
            repo=repo,
            event_path=event_path,
            trusted_commit=trusted,
            expected_repository="hacker-vs-cracker/mcp-behaviour-guard",
            api_url="https://api.github.com.attacker.invalid",
            token="test-token",
            output=tmp_path / "out.json",
            lookup_output=tmp_path / "lookup.json",
            fetch_json=fetcher,
        )
    assert called is False


def test_collector_rejects_wrong_workflow_before_network(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _trusted_repo(tmp_path)
    event = _event()
    run = event["workflow_run"]
    assert isinstance(run, dict)
    run["workflow_id"] = 123
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event), encoding="utf-8")

    called = False

    def fetcher(_url: str, _token: str) -> object:
        nonlocal called
        called = True
        return []

    with pytest.raises(module.WorkflowRunCollectionError, match="workflow_run id differs"):
        module.collect(
            repo=repo,
            event_path=event_path,
            trusted_commit=trusted,
            expected_repository="hacker-vs-cracker/mcp-behaviour-guard",
            api_url="https://api.github.com",
            token="test-token",
            output=tmp_path / "out.json",
            lookup_output=tmp_path / "lookup.json",
            fetch_json=fetcher,
        )
    assert called is False
