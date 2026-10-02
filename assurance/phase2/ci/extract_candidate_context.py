from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TRUST_BOUNDARY_PATH = "assurance/phase2/ci/trust-boundary.json"


class CandidateContextError(RuntimeError):
    pass


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    kind: str
    oid: str
    path: str


def _git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise CandidateContextError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def _validate_commit(repo: Path, commit: str, label: str) -> None:
    if not _SHA_RE.fullmatch(commit):
        raise CandidateContextError(f"{label} is not an exact 40-hex commit SHA")
    kind = _git(repo, "cat-file", "-t", commit).decode("ascii").strip()
    if kind != "commit":
        raise CandidateContextError(f"{label} does not identify a commit")


def _tree_entry(repo: Path, commit: str, path: str) -> TreeEntry:
    raw = _git(repo, "ls-tree", "-z", commit, "--", path)
    records = [record for record in raw.split(b"\0") if record]
    if len(records) != 1:
        raise CandidateContextError(f"expected exactly one tree entry for {path!r}")
    try:
        metadata, raw_path = records[0].split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split(" ", 2)
        decoded_path = raw_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise CandidateContextError(f"could not parse tree entry for {path!r}") from exc
    if decoded_path != path:
        raise CandidateContextError(f"tree entry path mismatch for {path!r}")
    return TreeEntry(mode=mode, kind=kind, oid=oid, path=decoded_path)


def _blob(repo: Path, oid: str) -> bytes:
    kind = _git(repo, "cat-file", "-t", oid).decode("ascii").strip()
    if kind != "blob":
        raise CandidateContextError(f"object {oid} is not a blob")
    return _git(repo, "cat-file", "blob", oid)


def _blob_size(repo: Path, oid: str) -> int:
    raw = _git(repo, "cat-file", "-s", oid).decode("ascii").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise CandidateContextError(f"object {oid} reported invalid size: {raw!r}") from exc
    if value < 0:
        raise CandidateContextError(f"object {oid} reported negative size")
    return value


def _json_blob(repo: Path, commit: str, path: str, label: str) -> tuple[dict[str, Any], bytes]:
    entry = _tree_entry(repo, commit, path)
    if entry.mode != "100644" or entry.kind != "blob":
        raise CandidateContextError(f"{label} must be a regular 100644 blob")
    raw = _blob(repo, entry.oid)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateContextError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CandidateContextError(f"{label} must be a JSON object")
    return value, raw


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def materialize(
    *,
    repo: Path,
    candidate_commit: str,
    trusted_commit: str,
    output_dir: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    repo = repo.resolve()
    output_dir = output_dir.resolve()
    manifest_path = manifest_path.resolve()

    _validate_commit(repo, candidate_commit, "candidate_commit")
    _validate_commit(repo, trusted_commit, "trusted_commit")

    boundary, boundary_raw = _json_blob(
        repo,
        trusted_commit,
        _TRUST_BOUNDARY_PATH,
        "trusted trust-boundary",
    )
    candidate_policy = boundary.get("candidate")
    platform = boundary.get("platform")
    if not isinstance(candidate_policy, dict) or not isinstance(platform, dict):
        raise CandidateContextError("trusted trust-boundary is missing candidate/platform mappings")

    allowed_paths = candidate_policy.get("allowed_paths")
    allowed_modes = candidate_policy.get("allowed_git_modes")
    if allowed_paths != ["assurance/phase2/vertical/candidate_server.py"]:
        raise CandidateContextError(
            "candidate allowlist is broader or different than the frozen v1 path"
        )
    if allowed_modes != ["100644"]:
        raise CandidateContextError("candidate git-mode allowlist differs from frozen v1")
    source_path = allowed_paths[0]

    materialized_name = candidate_policy.get("materialized_name")
    if materialized_name != "candidate_server.py":
        raise CandidateContextError("materialized candidate filename differs from frozen v1")

    max_bytes = candidate_policy.get("max_source_bytes")
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise CandidateContextError("candidate max_source_bytes is invalid")

    dockerfile_path = candidate_policy.get("trusted_dockerfile_path")
    if dockerfile_path != "assurance/phase2/vertical/Dockerfile":
        raise CandidateContextError("trusted candidate Dockerfile path differs from frozen v1")

    candidate_entry = _tree_entry(repo, candidate_commit, source_path)
    if candidate_entry.mode not in allowed_modes or candidate_entry.kind != "blob":
        raise CandidateContextError(
            f"candidate source must be a regular {allowed_modes[0]} blob; "
            f"got mode={candidate_entry.mode} kind={candidate_entry.kind}"
        )
    candidate_size = _blob_size(repo, candidate_entry.oid)
    if candidate_size > max_bytes:
        raise CandidateContextError(
            f"candidate source exceeds max_source_bytes: {candidate_size} > {max_bytes}"
        )
    candidate_raw = _blob(repo, candidate_entry.oid)
    if len(candidate_raw) != candidate_size:
        raise CandidateContextError(
            f"candidate blob size changed while reading: {len(candidate_raw)} != {candidate_size}"
        )
    if b"\0" in candidate_raw:
        raise CandidateContextError("candidate source contains a NUL byte")
    try:
        candidate_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateContextError("candidate source is not UTF-8") from exc

    trusted_dockerfile_entry = _tree_entry(repo, trusted_commit, dockerfile_path)
    if trusted_dockerfile_entry.mode != "100644" or trusted_dockerfile_entry.kind != "blob":
        raise CandidateContextError("trusted candidate Dockerfile is not a regular 100644 blob")
    trusted_dockerfile_raw = _blob(repo, trusted_dockerfile_entry.oid)

    try:
        manifest_path.relative_to(output_dir)
    except ValueError:
        pass
    else:
        raise CandidateContextError("manifest must not be written inside candidate build context")

    if output_dir.exists():
        raise CandidateContextError("candidate output directory already exists")
    output_dir.mkdir(parents=True, mode=0o700)

    candidate_path = output_dir / materialized_name
    candidate_path.write_bytes(candidate_raw)
    candidate_path.chmod(0o444)

    context_files = sorted(path.name for path in output_dir.iterdir())
    if context_files != [materialized_name]:
        raise CandidateContextError(
            f"candidate build context contains unexpected files: {context_files}"
        )

    manifest = {
        "schema_version": 1,
        "candidate_commit_sha": candidate_commit,
        "candidate_source_path": source_path,
        "candidate_blob_oid": candidate_entry.oid,
        "candidate_sha256": _sha256(candidate_raw),
        "candidate_bytes": len(candidate_raw),
        "materialized_name": materialized_name,
        "context_files": context_files,
        "trusted_commit_sha": trusted_commit,
        "trust_boundary_sha256": _sha256(boundary_raw),
        "trusted_dockerfile_path": dockerfile_path,
        "trusted_dockerfile_sha256": _sha256(trusted_dockerfile_raw),
        "platform": f"{platform.get('os')}/{platform.get('architecture')}",
        "candidate_dockerfile_ignored": True,
        "candidate_workflow_ignored_as_authority": True,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--trusted-commit", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    manifest = materialize(
        repo=args.repo,
        candidate_commit=args.candidate_commit,
        trusted_commit=args.trusted_commit,
        output_dir=args.output_dir,
        manifest_path=args.manifest,
    )
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
