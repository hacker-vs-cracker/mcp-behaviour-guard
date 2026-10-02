from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from resolve_workflow_run import WorkflowRunResolutionError, resolve

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BOUNDARY = Path("assurance/phase2/ci/trust-boundary.json")
_MAX_LOOKUP_BYTES = 1_048_576
FetchJson = Callable[[str, str], Any]


class WorkflowRunCollectionError(RuntimeError):
    pass


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkflowRunCollectionError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkflowRunCollectionError(f"{label} must be a JSON object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorkflowRunCollectionError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WorkflowRunCollectionError(f"{label} must be a positive integer")
    return value


def _preflight_lookup_identity(
    *,
    repo: Path,
    event_path: Path,
    expected_repository: str,
) -> tuple[str, str]:
    boundary = _load_object(repo / _BOUNDARY, "trusted trust-boundary")
    controller = boundary.get("controller")
    if not isinstance(controller, dict):
        raise WorkflowRunCollectionError("trusted controller policy is missing")

    frozen_repository = _string(controller.get("expected_repository"), "expected_repository")
    if expected_repository != frozen_repository:
        raise WorkflowRunCollectionError(
            f"workflow repository differs from frozen repository: "
            f"{expected_repository!r} != {frozen_repository!r}"
        )

    event = _load_object(event_path, "workflow_run event")
    if event.get("action") != controller.get("require_workflow_run_action"):
        raise WorkflowRunCollectionError("workflow_run action differs from frozen policy")

    repository = event.get("repository")
    if not isinstance(repository, dict) or repository.get("full_name") != frozen_repository:
        raise WorkflowRunCollectionError("event repository differs from frozen repository")

    run = event.get("workflow_run")
    if not isinstance(run, dict):
        raise WorkflowRunCollectionError("workflow_run mapping is missing")

    if _positive_int(run.get("workflow_id"), "workflow_run.workflow_id") != _positive_int(
        controller.get("expected_upstream_workflow_id"),
        "expected_upstream_workflow_id",
    ):
        raise WorkflowRunCollectionError("workflow_run id differs from frozen policy")
    if run.get("name") != controller.get("expected_upstream_workflow_name"):
        raise WorkflowRunCollectionError("workflow_run name differs from frozen policy")
    if run.get("event") != controller.get("expected_upstream_event"):
        raise WorkflowRunCollectionError("workflow_run event differs from frozen policy")
    if run.get("status") != controller.get("require_workflow_run_status"):
        raise WorkflowRunCollectionError("workflow_run status differs from frozen policy")

    head_sha = _string(run.get("head_sha"), "workflow_run.head_sha")
    if not _SHA_RE.fullmatch(head_sha):
        raise WorkflowRunCollectionError("workflow_run.head_sha is not an exact 40-hex SHA")
    head_branch = _string(run.get("head_branch"), "workflow_run.head_branch")

    for key in ("repository", "head_repository"):
        nested = run.get(key)
        if nested is not None and (
            not isinstance(nested, dict) or nested.get("full_name") != frozen_repository
        ):
            raise WorkflowRunCollectionError(f"workflow_run.{key} is not same-repository")

    return head_sha, head_branch


def _fetch_json(url: str, token: str) -> Any:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "mcp-behaviour-guard-phase2c",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise WorkflowRunCollectionError(
                    f"trusted PR lookup returned HTTP {response.status}"
                )
            link = response.headers.get("Link", "")
            if 'rel="next"' in link:
                raise WorkflowRunCollectionError(
                    "trusted PR lookup is paginated beyond the bounded first page"
                )
            raw = response.read(_MAX_LOOKUP_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise WorkflowRunCollectionError(f"trusted PR lookup returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise WorkflowRunCollectionError(f"trusted PR lookup failed: {exc.reason}") from exc

    if len(raw) > _MAX_LOOKUP_BYTES:
        raise WorkflowRunCollectionError("trusted PR lookup response exceeds size limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkflowRunCollectionError("trusted PR lookup response is not valid JSON") from exc


def collect(
    *,
    repo: Path,
    event_path: Path,
    trusted_commit: str,
    expected_repository: str,
    api_url: str,
    token: str,
    output: Path,
    lookup_output: Path,
    fetch_json: FetchJson = _fetch_json,
) -> dict[str, Any]:
    if not token:
        raise WorkflowRunCollectionError("GitHub token is empty")
    if api_url.rstrip("/") != "https://api.github.com":
        raise WorkflowRunCollectionError("GitHub API URL is not the expected public API")

    repo = repo.resolve()
    head_sha, _head_branch = _preflight_lookup_identity(
        repo=repo,
        event_path=event_path,
        expected_repository=expected_repository,
    )

    owner, name = expected_repository.split("/", 1)
    endpoint = (
        f"{api_url.rstrip('/')}/repos/"
        f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}/"
        f"commits/{head_sha}/pulls?per_page=100"
    )
    lookup = fetch_json(endpoint, token)
    if not isinstance(lookup, list):
        raise WorkflowRunCollectionError("trusted PR lookup response must be a JSON array")

    lookup_output.parent.mkdir(parents=True, exist_ok=True)
    lookup_output.write_text(
        json.dumps(lookup, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        intake = resolve(
            repo=repo,
            event_path=event_path,
            pull_request_lookup_path=lookup_output,
            trusted_commit=trusted_commit,
        )
    except WorkflowRunResolutionError as exc:
        raise WorkflowRunCollectionError(f"trusted intake resolution failed: {exc}") from exc

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(intake, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return intake


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--trusted-commit", required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lookup-output", type=Path, required=True)
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "")
    collect(
        repo=args.repo,
        event_path=args.event,
        trusted_commit=args.trusted_commit,
        expected_repository=args.expected_repository,
        api_url=args.api_url,
        token=token,
        output=args.output,
        lookup_output=args.lookup_output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
