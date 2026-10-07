from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import extract_candidate_context as extractor
import p4_controller_plan as controller_plan
import p4_resource_enforcement as enforcement


class P4CandidateMaterializationError(RuntimeError):
    pass


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\r\n]*$")

TRUST_REL = "assurance/phase2/ci/trust-boundary.json"
POLICY_REL = "assurance/phase2/ci/p4-resource-policy.json"
MODULE_REL = "assurance/phase2/ci/p4_candidate_materialization.py"
WORKFLOW_REL = ".github/workflows/phase2-trusted-intake.yml"

FetchJson = Callable[[str, str, dict[str, Any]], dict[str, Any]]


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise P4CandidateMaterializationError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise P4CandidateMaterializationError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise P4CandidateMaterializationError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise P4CandidateMaterializationError(f"{label} must be a non-negative integer")
    return value


def _sha(value: Any, label: str) -> str:
    raw = _string(value, label)
    if not _SHA_RE.fullmatch(raw):
        raise P4CandidateMaterializationError(f"{label} must be an exact 40-hex SHA")
    return raw


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _regular_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise P4CandidateMaterializationError(f"{label} must be a regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise P4CandidateMaterializationError(f"cannot read {label}: {exc}") from exc


def _external_object(raw: bytes, policy: dict[str, Any], label: str) -> dict[str, Any]:
    json_policy = _mapping(policy.get("json_intake"), "json_intake")
    max_bytes = _positive_int(json_policy.get("max_bytes"), "json.max_bytes")
    try:
        value = enforcement._load_object_bytes(raw, max_bytes=max_bytes, label=label)
        enforcement._validate_json_shape(value, json_policy)
    except enforcement.P4ResourceEnforcementError as exc:
        raise P4CandidateMaterializationError(str(exc)) from exc
    return value


def _fetch_json(url: str, token: str, policy: dict[str, Any]) -> dict[str, Any]:
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
    max_bytes = _positive_int(
        _mapping(policy.get("json_intake"), "json_intake").get("max_bytes"),
        "json.max_bytes",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise P4CandidateMaterializationError(
                    f"trusted GitHub lookup returned HTTP {response.status}"
                )
            raw = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise P4CandidateMaterializationError(
            f"trusted GitHub lookup returned HTTP {exc.code}"
        ) from exc
    except urllib.error.URLError as exc:
        raise P4CandidateMaterializationError(
            f"trusted GitHub lookup failed: {exc.reason}"
        ) from exc
    if len(raw) > max_bytes:
        raise P4CandidateMaterializationError("trusted GitHub lookup exceeds JSON byte limit")
    return _external_object(raw, policy, "trusted GitHub lookup")


def _api(api_url: str, repository: str, suffix: str) -> str:
    if api_url.rstrip("/") != "https://api.github.com":
        raise P4CandidateMaterializationError("GitHub API URL is not the expected public API")
    try:
        owner, name = repository.split("/", 1)
    except ValueError as exc:
        raise P4CandidateMaterializationError("repository must be owner/name") from exc
    return (
        f"{api_url.rstrip('/')}/repos/"
        f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}/{suffix}"
    )


def _single_tree_entry(
    payload: dict[str, Any],
    *,
    name: str,
    expected_type: str,
    expected_mode: str,
    label: str,
) -> dict[str, Any]:
    if payload.get("truncated") is not False:
        raise P4CandidateMaterializationError(f"{label} tree response is truncated or ambiguous")
    entries = payload.get("tree")
    if not isinstance(entries, list):
        raise P4CandidateMaterializationError(f"{label} tree entries are missing")
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("path") == name]
    if len(matches) != 1:
        raise P4CandidateMaterializationError(f"{label} tree entry count mismatch for {name!r}")
    entry = matches[0]
    if entry.get("type") != expected_type or entry.get("mode") != expected_mode:
        raise P4CandidateMaterializationError(
            f"{label} tree entry has unexpected type/mode for {name!r}"
        )
    _sha(entry.get("sha"), f"{label}.{name}.sha")
    return entry


def _decode_blob(payload: dict[str, Any], *, expected_sha: str, expected_size: int) -> bytes:
    if payload.get("sha") != expected_sha:
        raise P4CandidateMaterializationError("candidate blob SHA differs from tree entry")
    size = _nonnegative_int(payload.get("size"), "candidate blob size")
    if size != expected_size:
        raise P4CandidateMaterializationError("candidate blob size differs from tree entry")
    if payload.get("encoding") != "base64":
        raise P4CandidateMaterializationError("candidate blob encoding is not base64")
    content = _string(payload.get("content"), "candidate blob content")
    if not _BASE64_RE.fullmatch(content):
        raise P4CandidateMaterializationError("candidate blob contains invalid base64 characters")
    compact = "".join(content.split())
    try:
        raw = base64.b64decode(compact, validate=True)
    except ValueError as exc:
        raise P4CandidateMaterializationError("candidate blob base64 decode failed") from exc
    if len(raw) != expected_size:
        raise P4CandidateMaterializationError("decoded candidate blob size differs from tree entry")
    return raw


def validate_static_binding(repo: Path, trusted_commit: str) -> dict[str, Any]:
    repo = repo.resolve()
    static = controller_plan.validate_static_binding(repo, trusted_commit)
    trust = _mapping(static.get("trust"), "controller static trust")
    workflow_raw = _regular_bytes(repo / WORKFLOW_REL, "trusted intake workflow")
    module_raw = _regular_bytes(repo / MODULE_REL, "candidate materialization module")

    binding = _mapping(
        trust.get("p4_candidate_materialization"),
        "trust.p4_candidate_materialization",
    )
    expected = {
        "status": "WIRED_NOT_LIVE_PROVEN",
        "stage": "CANDIDATE_MATERIALIZATION_WIRING_ONLY",
        "module_path": MODULE_REL,
        "module_sha256": _sha256(module_raw),
        "workflow_path": WORKFLOW_REL,
        "workflow_sha256": _sha256(workflow_raw),
        "source_transport": "trusted_github_git_data_api_exact_blob",
        "current_pr_recheck_required": True,
        "candidate_context_outside_trusted_checkout": True,
        "candidate_context_destroyed_before_artifact_upload": True,
        "candidate_workflow_artifacts_are_authority": False,
        "candidate_execution_enabled": False,
        "hostile_execution_authorized": False,
        "runtime_enforcement_proven": False,
        "verdict_publication_enabled": False,
    }
    if binding != expected:
        raise P4CandidateMaterializationError(
            "trust-boundary candidate materialization binding mismatch"
        )
    consumed = trust.get("consumed_trusted_inputs")
    if not isinstance(consumed, list) or consumed.count(MODULE_REL) != 1:
        raise P4CandidateMaterializationError(
            "candidate materialization module must be listed exactly once as trusted input"
        )
    controller = _mapping(trust.get("controller"), "trust.controller")
    if (
        controller.get("controller_stage") != "INTAKE_ONLY"
        or controller.get("candidate_execution_enabled") is not False
        or controller.get("verdict_publication_enabled") is not False
    ):
        raise P4CandidateMaterializationError(
            "controller must remain non-executing and non-publishing"
        )
    publisher = _mapping(trust.get("publisher"), "trust.publisher")
    if (
        publisher.get("bootstrap_status") != "UNBOOTSTRAPPED"
        or publisher.get("integration_id") is not None
    ):
        raise P4CandidateMaterializationError("publisher must remain unbootstrapped")
    return static


def materialize_proof(
    *,
    repo: Path,
    plan_path: Path,
    trusted_commit: str,
    expected_repository: str,
    api_url: str,
    token: str,
    context_dir: Path,
    manifest_path: Path,
    fetch_json: FetchJson = _fetch_json,
) -> dict[str, Any]:
    if not token:
        raise P4CandidateMaterializationError("GitHub token is empty")

    repo = repo.resolve()
    context_dir = context_dir.resolve()
    manifest_path = manifest_path.resolve()

    try:
        context_dir.relative_to(repo)
    except ValueError:
        pass
    else:
        raise P4CandidateMaterializationError(
            "candidate materialization context must be outside trusted checkout"
        )
    if context_dir.exists():
        raise P4CandidateMaterializationError("candidate materialization context already exists")
    try:
        manifest_path.relative_to(context_dir)
    except ValueError:
        pass
    else:
        raise P4CandidateMaterializationError(
            "candidate materialization manifest must be outside candidate context"
        )
    if manifest_path.exists():
        raise P4CandidateMaterializationError("candidate materialization manifest already exists")

    static = validate_static_binding(repo, trusted_commit)
    trust = _mapping(static.get("trust"), "controller static trust")
    policy = _mapping(static.get("policy"), "controller static policy")

    plan_raw = _regular_bytes(plan_path, "P4 controller plan")
    try:
        plan = enforcement.load_bounded_json(plan_raw, policy, expected_schema_version=1)
    except enforcement.P4ResourceEnforcementError as exc:
        raise P4CandidateMaterializationError(f"invalid P4 controller plan: {exc}") from exc

    if plan.get("stage") != "P4_CONTROLLER_PLAN_ONLY":
        raise P4CandidateMaterializationError("controller plan stage mismatch")
    trusted = _mapping(plan.get("trusted_controller"), "plan.trusted_controller")
    if _sha(trusted.get("commit_sha"), "plan trusted commit") != trusted_commit:
        raise P4CandidateMaterializationError("controller plan trusted commit mismatch")
    if trusted.get("trust_boundary_sha256") != static.get("trust_boundary_sha256"):
        raise P4CandidateMaterializationError("controller plan trust-boundary digest mismatch")
    if trusted.get("workflow_sha256") != static.get("workflow_sha256"):
        raise P4CandidateMaterializationError("controller plan workflow digest mismatch")

    controller = _mapping(trust.get("controller"), "trust.controller")
    frozen_repo = _string(controller.get("expected_repository"), "expected repository")
    if expected_repository != frozen_repo:
        raise P4CandidateMaterializationError("workflow repository differs from frozen repository")

    eligible = _mapping(plan.get("eligible_workflow"), "plan.eligible_workflow")
    if eligible.get("workflow_id") != controller.get("expected_upstream_workflow_id"):
        raise P4CandidateMaterializationError("controller plan workflow id mismatch")
    if eligible.get("workflow_name") != controller.get("expected_upstream_workflow_name"):
        raise P4CandidateMaterializationError("controller plan workflow name mismatch")
    if eligible.get("event") != controller.get("expected_upstream_event"):
        raise P4CandidateMaterializationError("controller plan workflow event mismatch")
    if eligible.get("status") != controller.get("require_workflow_run_status"):
        raise P4CandidateMaterializationError("controller plan workflow status mismatch")
    _positive_int(eligible.get("run_id"), "plan.eligible_workflow.run_id")
    _positive_int(eligible.get("run_attempt"), "plan.eligible_workflow.run_attempt")
    if eligible.get("conclusion_is_authoritative") is not False:
        raise P4CandidateMaterializationError(
            "controller plan upstream conclusion must remain non-authoritative"
        )

    current_pr = _mapping(plan.get("pull_request"), "plan.pull_request")
    pr_number = _positive_int(current_pr.get("number"), "plan.pull_request.number")
    head_sha = _sha(current_pr.get("head_sha"), "plan.pull_request.head_sha")
    base_sha = _sha(current_pr.get("base_sha"), "plan.pull_request.base_sha")
    if current_pr.get("state") != "open" or current_pr.get("base_ref") != "main":
        raise P4CandidateMaterializationError("controller plan PR state/base mismatch")
    if current_pr.get("repository") != frozen_repo:
        raise P4CandidateMaterializationError("controller plan repository mismatch")

    candidate_plan = _mapping(plan.get("candidate"), "plan.candidate")
    if (
        candidate_plan.get("materialization_performed") is not False
        or candidate_plan.get("execution_enabled") is not False
        or candidate_plan.get("hostile_execution_authorized") is not False
        or candidate_plan.get("execution_time_current_pr_recheck_required") is not True
    ):
        raise P4CandidateMaterializationError("controller plan unexpectedly authorizes candidate")
    source_path = _string(candidate_plan.get("source_path"), "candidate source path")

    candidate_policy = _mapping(trust.get("candidate"), "trust.candidate")
    if candidate_plan.get("trusted_dockerfile_path") != candidate_policy.get(
        "trusted_dockerfile_path"
    ):
        raise P4CandidateMaterializationError("controller plan trusted Dockerfile path mismatch")
    if candidate_plan.get("source_scope") != candidate_policy.get("source_scope"):
        raise P4CandidateMaterializationError("controller plan candidate source scope mismatch")
    if candidate_policy.get("allowed_paths") != [source_path]:
        raise P4CandidateMaterializationError("candidate source path differs from frozen allowlist")
    if candidate_policy.get("allowed_git_modes") != ["100644"]:
        raise P4CandidateMaterializationError("candidate git-mode allowlist differs from frozen v1")
    max_source_bytes = _positive_int(
        candidate_policy.get("max_source_bytes"), "candidate.max_source_bytes"
    )

    promoted = _mapping(plan.get("promoted_authority"), "plan.promoted_authority")
    promotion = _mapping(trust.get("p3_promotion"), "trust.p3_promotion")
    authority = _mapping(static.get("authority"), "controller static authority")
    authority_reference = _mapping(authority.get("reference"), "authority.reference")
    if promoted.get("generation") != promotion.get("authority_generation"):
        raise P4CandidateMaterializationError("controller plan authority generation mismatch")
    if promoted.get("authority_sha256") != static.get("authority_sha256"):
        raise P4CandidateMaterializationError("controller plan authority digest mismatch")
    if promoted.get("approval_bundle_digest") != authority_reference.get("approval_bundle_digest"):
        raise P4CandidateMaterializationError("controller plan approval digest mismatch")
    if promoted.get("platform") != authority.get("platform"):
        raise P4CandidateMaterializationError("controller plan authority platform mismatch")

    publisher_plan = _mapping(plan.get("publisher"), "plan.publisher")
    if (
        publisher_plan.get("enabled") is not False
        or publisher_plan.get("bootstrap_status") != "UNBOOTSTRAPPED"
        or publisher_plan.get("integration_id") is not None
    ):
        raise P4CandidateMaterializationError("controller plan publisher unexpectedly enabled")

    resource_controls = _mapping(plan.get("resource_controls"), "plan.resource_controls")
    resource_policy = _mapping(trust.get("p4_resource_policy"), "trust.p4_resource_policy")
    resource_enforcement = _mapping(
        trust.get("p4_resource_enforcement"), "trust.p4_resource_enforcement"
    )
    if resource_controls.get("policy_sha256") != resource_policy.get("policy_sha256"):
        raise P4CandidateMaterializationError("controller plan resource-policy digest mismatch")
    if resource_controls.get("enforcement_module_sha256") != resource_enforcement.get(
        "module_sha256"
    ):
        raise P4CandidateMaterializationError(
            "controller plan resource-enforcement digest mismatch"
        )
    if resource_controls.get("runtime_enforcement_proven") is not False:
        raise P4CandidateMaterializationError("controller plan falsely claims runtime proof")

    pr_payload = fetch_json(
        _api(api_url, frozen_repo, f"pulls/{pr_number}"),
        token,
        policy,
    )
    head = _mapping(pr_payload.get("head"), "live pull_request.head")
    base = _mapping(pr_payload.get("base"), "live pull_request.base")
    head_repo = _mapping(head.get("repo"), "live pull_request.head.repo")
    base_repo = _mapping(base.get("repo"), "live pull_request.base.repo")
    if (
        _positive_int(pr_payload.get("number"), "live pull_request.number") != pr_number
        or pr_payload.get("state") != "open"
        or _sha(head.get("sha"), "live pull_request.head.sha") != head_sha
        or _sha(base.get("sha"), "live pull_request.base.sha") != base_sha
        or head.get("ref") != current_pr.get("head_ref")
        or base.get("ref") != "main"
        or head_repo.get("full_name") != frozen_repo
        or base_repo.get("full_name") != frozen_repo
    ):
        raise P4CandidateMaterializationError("current PR identity changed since controller plan")

    commit_payload = fetch_json(
        _api(api_url, frozen_repo, f"git/commits/{head_sha}"),
        token,
        policy,
    )
    tree_sha = _sha(
        _mapping(commit_payload.get("tree"), "candidate commit tree").get("sha"),
        "candidate commit tree sha",
    )

    parts = source_path.split("/")
    if any(not part or part in (".", "..") for part in parts):
        raise P4CandidateMaterializationError("candidate source path is invalid")
    for part in parts[:-1]:
        tree_payload = fetch_json(
            _api(api_url, frozen_repo, f"git/trees/{tree_sha}"),
            token,
            policy,
        )
        entry = _single_tree_entry(
            tree_payload,
            name=part,
            expected_type="tree",
            expected_mode="040000",
            label="candidate",
        )
        tree_sha = _sha(entry.get("sha"), f"candidate tree {part} sha")

    final_tree = fetch_json(
        _api(api_url, frozen_repo, f"git/trees/{tree_sha}"),
        token,
        policy,
    )
    blob_entry = _single_tree_entry(
        final_tree,
        name=parts[-1],
        expected_type="blob",
        expected_mode="100644",
        label="candidate",
    )
    blob_sha = _sha(blob_entry.get("sha"), "candidate blob sha")
    blob_size = _nonnegative_int(blob_entry.get("size"), "candidate blob size")
    if blob_size > max_source_bytes:
        raise P4CandidateMaterializationError(
            f"candidate source exceeds max_source_bytes: {blob_size} > {max_source_bytes}"
        )

    blob_payload = fetch_json(
        _api(api_url, frozen_repo, f"git/blobs/{blob_sha}"),
        token,
        policy,
    )
    candidate_raw = _decode_blob(
        blob_payload,
        expected_sha=blob_sha,
        expected_size=blob_size,
    )
    if b"\0" in candidate_raw:
        raise P4CandidateMaterializationError("candidate source contains a NUL byte")
    try:
        candidate_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise P4CandidateMaterializationError("candidate source is not UTF-8") from exc

    dockerfile_path = _string(
        candidate_policy.get("trusted_dockerfile_path"),
        "trusted candidate Dockerfile path",
    )
    dockerfile_entry = extractor._tree_entry(repo, trusted_commit, dockerfile_path)
    if dockerfile_entry.mode != "100644" or dockerfile_entry.kind != "blob":
        raise P4CandidateMaterializationError(
            "trusted candidate Dockerfile is not a regular 100644 blob"
        )
    dockerfile_raw = extractor._blob(repo, dockerfile_entry.oid)

    context_budget: dict[str, int]
    docker_args: list[str]
    build_limits: dict[str, int]
    subprocess_limits: dict[str, int]
    context_created = False
    try:
        context_dir.mkdir(parents=True, mode=0o700)
        context_created = True
        candidate_name = _string(
            candidate_policy.get("materialized_name"),
            "candidate materialized_name",
        )
        candidate_target = context_dir / candidate_name
        dockerfile_target = context_dir / "Dockerfile"
        candidate_target.write_bytes(candidate_raw)
        dockerfile_target.write_bytes(dockerfile_raw)
        candidate_target.chmod(0o444)
        dockerfile_target.chmod(0o444)

        if sorted(path.name for path in context_dir.iterdir()) != ["Dockerfile", candidate_name]:
            raise P4CandidateMaterializationError(
                "candidate build context contains unexpected files"
            )
        try:
            context_budget = enforcement.validate_build_context(context_dir, policy)
            docker_args = enforcement.docker_resource_args(policy)
            build_limits = enforcement.build_command_limits(policy)
            subprocess_limits = enforcement.subprocess_limits(policy)
        except enforcement.P4ResourceEnforcementError as exc:
            raise P4CandidateMaterializationError(
                f"resource enforcement rejected materialized context: {exc}"
            ) from exc
    finally:
        if context_created:
            shutil.rmtree(context_dir, ignore_errors=False)

    if context_dir.exists():
        raise P4CandidateMaterializationError("candidate materialization context was not destroyed")

    manifest = {
        "schema_version": 1,
        "stage": "P4_CANDIDATE_MATERIALIZATION_PROOF_ONLY",
        "repository": frozen_repo,
        "pull_request": {
            "number": pr_number,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "current_identity_rechecked": True,
        },
        "candidate": {
            "source_path": source_path,
            "blob_oid": blob_sha,
            "sha256": _sha256(candidate_raw),
            "bytes": len(candidate_raw),
            "git_mode": "100644",
            "source_transport": "trusted_github_git_data_api_exact_blob",
            "workflow_artifacts_are_authority": False,
            "source_retained_after_proof": False,
        },
        "trusted_dockerfile": {
            "path": dockerfile_path,
            "blob_oid": dockerfile_entry.oid,
            "sha256": _sha256(dockerfile_raw),
        },
        "resource_controls": {
            "policy_sha256": resource_policy["policy_sha256"],
            "enforcement_module_sha256": resource_enforcement["module_sha256"],
            "context_budget": context_budget,
            "docker_resource_args": docker_args,
            "build_command_limits": build_limits,
            "subprocess_limits": subprocess_limits,
            "runtime_enforcement_proven": False,
        },
        "lifecycle": {
            "context_outside_trusted_checkout": True,
            "context_destroyed_before_manifest_write": True,
            "candidate_execution_performed": False,
            "hostile_execution_authorized": False,
            "verdict_publication_performed": False,
        },
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--trusted-commit")
    parser.add_argument("--expected-repository")
    parser.add_argument("--api-url")
    parser.add_argument("--context-dir", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--validate-binding-only", action="store_true")
    args = parser.parse_args()

    if args.trusted_commit is None:
        parser.error("--trusted-commit is required")
    if args.validate_binding_only:
        value = validate_static_binding(args.repo, args.trusted_commit)
        print(
            json.dumps(
                {
                    "status": "P4_CANDIDATE_MATERIALIZATION_WIRING_VALID",
                    "candidate_execution_enabled": False,
                    "hostile_execution_authorized": False,
                    "runtime_enforcement_proven": False,
                    "authority_generation": value["trust"]["p3_promotion"]["authority_generation"],
                },
                sort_keys=True,
            )
        )
        return 0

    for name, value in (
        ("--plan", args.plan),
        ("--expected-repository", args.expected_repository),
        ("--api-url", args.api_url),
        ("--context-dir", args.context_dir),
        ("--manifest", args.manifest),
    ):
        if value is None:
            parser.error(f"{name} is required unless --validate-binding-only is used")

    materialize_proof(
        repo=args.repo,
        plan_path=args.plan,
        trusted_commit=args.trusted_commit,
        expected_repository=args.expected_repository,
        api_url=args.api_url,
        token=os.environ.get("GITHUB_TOKEN", ""),
        context_dir=args.context_dir,
        manifest_path=args.manifest,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
