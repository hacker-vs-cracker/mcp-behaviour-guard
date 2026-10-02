from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BOUNDARY = Path("assurance/phase2/ci/trust-boundary.json")


class WorkflowRunResolutionError(RuntimeError):
    pass


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        raise WorkflowRunResolutionError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkflowRunResolutionError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorkflowRunResolutionError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WorkflowRunResolutionError(f"{label} must be a positive integer")
    return value


def _sha(value: Any, label: str) -> str:
    raw = _string(value, label)
    if not _SHA_RE.fullmatch(raw):
        raise WorkflowRunResolutionError(f"{label} must be an exact 40-hex SHA")
    return raw


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkflowRunResolutionError(f"cannot load {label}: {exc}") from exc
    return _object(value, label)


def _validate_trusted_checkout(repo: Path, trusted_commit: str) -> dict[str, Any]:
    if not _SHA_RE.fullmatch(trusted_commit):
        raise WorkflowRunResolutionError("trusted_commit must be an exact 40-hex SHA")
    head = _git(repo, "rev-parse", "HEAD")
    if head != trusted_commit:
        raise WorkflowRunResolutionError(
            f"trusted checkout HEAD differs from trusted_commit: {head} != {trusted_commit}"
        )
    if _git(repo, "cat-file", "-t", trusted_commit) != "commit":
        raise WorkflowRunResolutionError("trusted_commit does not identify a commit")
    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise WorkflowRunResolutionError("trusted controller checkout is dirty")

    boundary_path = repo / _BOUNDARY
    if boundary_path.is_symlink() or not boundary_path.is_file():
        raise WorkflowRunResolutionError("trusted trust-boundary is not a regular file")
    raw = boundary_path.read_bytes()
    try:
        boundary = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkflowRunResolutionError("trusted trust-boundary is invalid JSON") from exc
    if not isinstance(boundary, dict):
        raise WorkflowRunResolutionError("trusted trust-boundary must be an object")
    return {"boundary": boundary, "boundary_sha256": hashlib.sha256(raw).hexdigest()}


def resolve(*, repo: Path, event_path: Path, trusted_commit: str) -> dict[str, Any]:
    repo = repo.resolve()
    trusted = _validate_trusted_checkout(repo, trusted_commit)
    boundary = trusted["boundary"]
    controller = _object(boundary.get("controller"), "trust-boundary controller")
    candidate_policy = _object(boundary.get("candidate"), "trust-boundary candidate")

    expected_repo = _string(controller.get("expected_repository"), "expected_repository")
    expected_workflow_name = _string(
        controller.get("expected_upstream_workflow_name"), "expected_upstream_workflow_name"
    )
    expected_workflow_id = _positive_int(
        controller.get("expected_upstream_workflow_id"), "expected_upstream_workflow_id"
    )
    expected_event = _string(controller.get("expected_upstream_event"), "expected_upstream_event")
    expected_action = _string(
        controller.get("require_workflow_run_action"), "require_workflow_run_action"
    )
    expected_status = _string(
        controller.get("require_workflow_run_status"), "require_workflow_run_status"
    )
    if controller.get("require_exactly_one_associated_pull_request") is not True:
        raise WorkflowRunResolutionError("exactly-one-PR policy is not frozen")
    if candidate_policy.get("source_scope") != "same-repository-pull-request-only":
        raise WorkflowRunResolutionError("candidate source scope is not same-repository-only")
    if candidate_policy.get("fork_pull_requests_supported") is not False:
        raise WorkflowRunResolutionError("fork PR policy is not frozen off")

    event = _load_json(event_path, "workflow_run event")
    if event.get("action") != expected_action:
        raise WorkflowRunResolutionError(
            f"workflow_run action mismatch: {event.get('action')!r} != {expected_action!r}"
        )

    repository = _object(event.get("repository"), "event repository")
    repository_full_name = _string(repository.get("full_name"), "event repository.full_name")
    if repository_full_name != expected_repo:
        raise WorkflowRunResolutionError(
            f"event repository mismatch: {repository_full_name!r} != {expected_repo!r}"
        )

    run = _object(event.get("workflow_run"), "workflow_run")
    workflow_id = _positive_int(run.get("workflow_id"), "workflow_run.workflow_id")
    if workflow_id != expected_workflow_id:
        raise WorkflowRunResolutionError(
            f"workflow id mismatch: {workflow_id} != {expected_workflow_id}"
        )
    workflow_name = _string(run.get("name"), "workflow_run.name")
    if workflow_name != expected_workflow_name:
        raise WorkflowRunResolutionError(
            f"workflow name mismatch: {workflow_name!r} != {expected_workflow_name!r}"
        )
    upstream_event = _string(run.get("event"), "workflow_run.event")
    if upstream_event != expected_event:
        raise WorkflowRunResolutionError(
            f"workflow event mismatch: {upstream_event!r} != {expected_event!r}"
        )
    status = _string(run.get("status"), "workflow_run.status")
    if status != expected_status:
        raise WorkflowRunResolutionError(
            f"workflow status mismatch: {status!r} != {expected_status!r}"
        )

    run_id = _positive_int(run.get("id"), "workflow_run.id")
    run_attempt = _positive_int(run.get("run_attempt"), "workflow_run.run_attempt")
    head_sha = _sha(run.get("head_sha"), "workflow_run.head_sha")
    head_branch = _string(run.get("head_branch"), "workflow_run.head_branch")
    conclusion_value = run.get("conclusion")
    conclusion = conclusion_value if isinstance(conclusion_value, str) else None

    for key in ("repository", "head_repository"):
        nested = run.get(key)
        if nested is not None:
            nested_name = _string(
                _object(nested, f"workflow_run.{key}").get("full_name"),
                f"workflow_run.{key}.full_name",
            )
            if nested_name != expected_repo:
                raise WorkflowRunResolutionError(f"workflow_run {key} is not same-repository")

    pull_requests = run.get("pull_requests")
    if not isinstance(pull_requests, list) or len(pull_requests) != 1:
        count = len(pull_requests) if isinstance(pull_requests, list) else "non-list"
        raise WorkflowRunResolutionError(
            f"workflow_run must have exactly one associated PR; got {count}"
        )
    pr = _object(pull_requests[0], "workflow_run.pull_requests[0]")
    pr_number = _positive_int(pr.get("number"), "pull_request.number")
    pr_head = _object(pr.get("head"), "pull_request.head")
    pr_base = _object(pr.get("base"), "pull_request.base")

    pr_head_sha = _sha(pr_head.get("sha"), "pull_request.head.sha")
    pr_base_sha = _sha(pr_base.get("sha"), "pull_request.base.sha")
    pr_head_ref = _string(pr_head.get("ref"), "pull_request.head.ref")
    pr_base_ref = _string(pr_base.get("ref"), "pull_request.base.ref")
    pr_head_repo = _string(
        _object(pr_head.get("repo"), "pull_request.head.repo").get("full_name"),
        "pull_request.head.repo.full_name",
    )
    pr_base_repo = _string(
        _object(pr_base.get("repo"), "pull_request.base.repo").get("full_name"),
        "pull_request.base.repo.full_name",
    )

    if pr_head_repo != expected_repo or pr_base_repo != expected_repo:
        raise WorkflowRunResolutionError("fork/cross-repository pull requests are not supported")
    if pr_base_ref != "main":
        raise WorkflowRunResolutionError(f"pull request base is not main: {pr_base_ref!r}")
    if pr_head_sha != head_sha:
        raise WorkflowRunResolutionError(
            f"workflow_run head SHA differs from associated PR head: {head_sha} != {pr_head_sha}"
        )
    if head_branch != pr_head_ref:
        raise WorkflowRunResolutionError(
            f"workflow_run head branch differs from associated PR head ref: "
            f"{head_branch!r} != {pr_head_ref!r}"
        )

    return {
        "schema_version": 1,
        "source_event": "workflow_run",
        "repository": {"full_name": expected_repo},
        "trusted_controller": {
            "commit_sha": trusted_commit,
            "trust_boundary_sha256": trusted["boundary_sha256"],
        },
        "upstream": {
            "workflow_id": workflow_id,
            "workflow_name": workflow_name,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "event": upstream_event,
            "status": status,
            "conclusion": conclusion,
            "conclusion_is_authoritative": False,
        },
        "pull_request": {
            "number": pr_number,
            "head_sha": pr_head_sha,
            "head_ref": pr_head_ref,
            "head_repository": pr_head_repo,
            "base_sha": pr_base_sha,
            "base_ref": pr_base_ref,
            "base_repository": pr_base_repo,
            "source_scope": "same-repository-pull-request-only",
        },
        "authority": {
            "candidate_workflow_artifacts_are_authority": False,
            "upstream_ci_conclusion_is_phase2_verdict": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--trusted-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = resolve(repo=args.repo, event_path=args.event, trusted_commit=args.trusted_commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
