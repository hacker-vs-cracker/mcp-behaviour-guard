from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

PLATFORM = "linux/amd64"
DECISION_SCOPE = "phase2c_trusted_ci_gate_only"
PROFILE_ID = "phase2c-ci-amd64-v1"
AMD64_LOCK_SHA256 = "a18436b0d48f7eacf5b8f4142685a12b11eed3105039e4d3a0eab2b42a3ec22b"
ARM64_LOCK_SHA256 = "7f135a827bad87dc89e5a359824d0abe727f376f213865330b4da8c14cead267"
ARM64_RUNTIME_SHA256 = "1d5ed99b583ad85a1465a7fa8a84a2bb41515410371a94870a18a8066e03933e"
AMD64_BASE_MANIFEST = "sha256:fa7a862d74b4decf68fb7d3a85147efc14dbcd3779c0abd56c071d27a1ffee04"
DEFAULT_SPEC = Path("assurance/phase2/ci/build-adapter.json")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GHCR_DIGEST_RE = re.compile(
    r"^ghcr\.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-[a-z0-9][a-z0-9_.-]*@sha256:[0-9a-f]{64}$"
)


class BuildAdapterError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise BuildAdapterError(f"cannot hash trusted input {path}: {exc}") from exc
    return digest.hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BuildAdapterError(
            f"{label} is unreadable/invalid: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise BuildAdapterError(f"{label} must be a JSON object")
    return value


def _trusted_file(repo: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise BuildAdapterError(f"trusted input path is unsafe: {relative}")
    candidate = repo / rel
    try:
        resolved_repo = repo.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise BuildAdapterError(
            f"trusted input is missing/unresolvable: {relative}: {exc}"
        ) from exc
    try:
        resolved.relative_to(resolved_repo)
    except ValueError as exc:
        raise BuildAdapterError(f"trusted input escapes repository: {relative}") from exc
    if candidate.is_symlink() or not resolved.is_file():
        raise BuildAdapterError(f"trusted input must be a regular non-symlink file: {relative}")
    return resolved


def validate_ghcr_digest_reference(value: str) -> str:
    if not _GHCR_DIGEST_RE.fullmatch(value):
        raise BuildAdapterError("image execution reference must be ghcr.io/...@sha256:<64 hex>")
    return value


def validate_spec(repo: Path, spec_path: Path | None = None) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    path = spec_path or (repo / DEFAULT_SPEC)
    spec = _load_json(path, "P1B build adapter specification")

    if spec.get("schema_version") != 1:
        raise BuildAdapterError("build adapter schema_version must be 1")
    if spec.get("profile_id") != PROFILE_ID:
        raise BuildAdapterError("build adapter profile_id mismatch")
    if spec.get("status") != "P2_PROOF_PREP_FROZEN":
        raise BuildAdapterError("build adapter status is not P2_PROOF_PREP_FROZEN")
    if spec.get("platform") != PLATFORM:
        raise BuildAdapterError("build adapter platform must be linux/amd64")
    if spec.get("decision_scope") != DECISION_SCOPE:
        raise BuildAdapterError("build adapter decision_scope mismatch")
    if spec.get("runtime_execution_enabled") is not True:
        raise BuildAdapterError("P2 proof preparation must enable bounded runtime execution")
    if spec.get("promotion_enabled") is not False:
        raise BuildAdapterError("P1B must not enable promotion")

    evaluator = spec.get("evaluator_build_context")
    if not isinstance(evaluator, dict):
        raise BuildAdapterError("evaluator_build_context mapping missing")
    if evaluator.get("dockerfile_source") != "assurance/phase2/evaluator/Dockerfile":
        raise BuildAdapterError("evaluator Dockerfile source mismatch")
    if evaluator.get("dockerfile_output_name") != "Dockerfile":
        raise BuildAdapterError("evaluator Dockerfile output name must be Dockerfile")
    if evaluator.get("dependency_lock_source") != (
        "assurance/phase2/ci/evaluator-requirements-amd64.lock"
    ):
        raise BuildAdapterError("AMD64 dependency lock source mismatch")
    if evaluator.get("dependency_lock_output_name") != "requirements.lock":
        raise BuildAdapterError("evaluator dependency lock must stage as requirements.lock")
    if evaluator.get("dependency_lock_sha256") != AMD64_LOCK_SHA256:
        raise BuildAdapterError("AMD64 dependency lock expected SHA256 mismatch")
    if evaluator.get("named_wheelhouse_context") != "wheelhouse":
        raise BuildAdapterError("evaluator named wheelhouse context mismatch")
    if evaluator.get("live_dependency_resolution_fallback") is not False:
        raise BuildAdapterError("live dependency-resolution fallback must be disabled")
    if evaluator.get("required_pip_flags") != [
        "--no-index",
        "--find-links=/wheelhouse",
        "--only-binary=:all:",
        "--require-hashes",
    ]:
        raise BuildAdapterError("evaluator required pip flags mismatch")

    lock = _trusted_file(repo, str(evaluator["dependency_lock_source"]))
    if _sha256(lock) != AMD64_LOCK_SHA256:
        raise BuildAdapterError("AMD64 dependency lock bytes do not match frozen SHA256")

    historical = spec.get("historical_evidence")
    if not isinstance(historical, dict):
        raise BuildAdapterError("historical_evidence mapping missing")
    if historical.get("arm64_dependency_lock_sha256") != ARM64_LOCK_SHA256:
        raise BuildAdapterError("historical ARM64 dependency lock expected SHA256 mismatch")
    if historical.get("arm64_lock_reuse_allowed") is not False:
        raise BuildAdapterError("historical ARM64 dependency lock reuse must be disabled")
    arm64_profile = _trusted_file(repo, str(historical.get("arm64_runtime_profile")))
    if historical.get("arm64_runtime_profile_sha256") != ARM64_RUNTIME_SHA256:
        raise BuildAdapterError("historical ARM64 runtime profile expected SHA256 mismatch")
    if _sha256(arm64_profile) != ARM64_RUNTIME_SHA256:
        raise BuildAdapterError("historical ARM64 runtime profile bytes changed")
    arm64_lock = _trusted_file(repo, str(historical.get("arm64_dependency_lock")))
    if _sha256(arm64_lock) != ARM64_LOCK_SHA256:
        raise BuildAdapterError("historical ARM64 dependency lock bytes changed")

    dockerfile = _trusted_file(repo, str(evaluator.get("dockerfile_source")))
    docker_text = dockerfile.read_text(encoding="utf-8")
    for token in (
        "COPY requirements.lock /tmp/requirements.lock",
        "COPY --from=wheelhouse / /wheelhouse/",
        "--no-index",
        "--find-links=/wheelhouse",
        "--only-binary=:all:",
        "--require-hashes",
    ):
        if token not in docker_text:
            raise BuildAdapterError(f"evaluator Dockerfile missing required invariant: {token}")

    base_image = spec.get("base_image")
    if not isinstance(base_image, dict):
        raise BuildAdapterError("base_image mapping missing")
    if base_image.get("reference") != "python:3.11.14-slim":
        raise BuildAdapterError("base image reference mismatch")
    if base_image.get("platform") != PLATFORM:
        raise BuildAdapterError("base image platform mismatch")
    if base_image.get("characterized_platform_manifest_digest") != AMD64_BASE_MANIFEST:
        raise BuildAdapterError("characterized AMD64 base platform manifest mismatch")
    if base_image.get("runtime_profile_binding_status") != "UNPROMOTED_UNTIL_P2_P3_EVIDENCE":
        raise BuildAdapterError("base runtime-profile binding status mismatch")
    if base_image.get("immutable_platform_manifest_required_before_build") is not True:
        raise BuildAdapterError("immutable AMD64 base manifest must be required before build")
    if base_image.get("moving_tag_execution_allowed") is not False:
        raise BuildAdapterError("moving-tag base-image execution must be disabled")

    distribution = spec.get("image_distribution")
    if not isinstance(distribution, dict):
        raise BuildAdapterError("image_distribution mapping missing")
    if distribution.get("decision_status") != "P2_FROZEN":
        raise BuildAdapterError("image distribution decision status mismatch")
    if distribution.get("primary") != "ghcr_immutable_digest":
        raise BuildAdapterError("P2 primary image distribution must be GHCR immutable digest")
    if distribution.get("alternatives_reviewed") != [
        "ghcr_immutable_digest",
        "retained_oci_layout",
    ]:
        raise BuildAdapterError("image distribution alternatives mismatch")
    if distribution.get("registry") != "ghcr.io":
        raise BuildAdapterError("image registry must be ghcr.io")
    if distribution.get("namespace") != "hacker-vs-cracker":
        raise BuildAdapterError("GHCR namespace mismatch")
    if distribution.get("repository_prefix") != "mcp-behaviour-guard-phase2-":
        raise BuildAdapterError("GHCR repository prefix mismatch")
    if distribution.get("execution_reference_requires_digest") is not True:
        raise BuildAdapterError("image execution references must require a digest")
    if distribution.get("moving_tag_fallback_allowed") is not False:
        raise BuildAdapterError("moving-tag fallback must be disabled")
    if distribution.get("publication_credentials_available_to_candidate_execution") is not False:
        raise BuildAdapterError("candidate execution must not receive publication credentials")
    if distribution.get("retrieval_credentials_available_to_candidate_execution") is not False:
        raise BuildAdapterError("candidate execution must not receive image retrieval credentials")
    if distribution.get("package_visibility") != "repository_inherited":
        raise BuildAdapterError("GHCR package visibility policy mismatch")
    if distribution.get("trusted_image_publication_auth") != (
        "github_token_packages_write_build_job_only"
    ):
        raise BuildAdapterError("trusted image-publication auth policy mismatch")
    if distribution.get("trusted_controller_pull_auth") != (
        "github_token_packages_read_pull_step_only"
    ):
        raise BuildAdapterError("trusted controller pull-auth policy mismatch")
    if distribution.get("credentials_removed_before_candidate_runtime") is not True:
        raise BuildAdapterError("registry credentials must be removed before candidate runtime")
    if distribution.get("digest_retrievable_through_promoted_authority_lifetime") is not True:
        raise BuildAdapterError("promoted digest retention requirement missing")
    if distribution.get("retained_oci_layout_role") != "reviewed_alternative_not_selected":
        raise BuildAdapterError("retained OCI layout role mismatch")
    if distribution.get("retained_oci_layout_generated") is not False:
        raise BuildAdapterError("P2 must not claim an OCI layout that was not generated")
    if distribution.get("retained_oci_layout_recovery_available") is not False:
        raise BuildAdapterError("P2 must not claim OCI recovery availability")
    if distribution.get("retained_oci_layout_recovery_requires_digest_match") is not True:
        raise BuildAdapterError("OCI recovery must require exact digest identity if later used")

    wheelhouse = spec.get("wheelhouse")
    if not isinstance(wheelhouse, dict):
        raise BuildAdapterError("wheelhouse mapping missing")
    if wheelhouse.get("status") != "SEALED_AT_PROOF_RUNTIME":
        raise BuildAdapterError("wheelhouse must be sealed during the P2 proof")
    if wheelhouse.get("manifest_required_before_build") is not True:
        raise BuildAdapterError("wheelhouse manifest must be required before build")
    if wheelhouse.get("exact_file_set_required") is not True:
        raise BuildAdapterError("wheelhouse exact file set must be required")
    if wheelhouse.get("hash_each_wheel") is not True:
        raise BuildAdapterError("wheelhouse per-wheel hashing must be required")
    if wheelhouse.get("live_download_fallback") is not False:
        raise BuildAdapterError("wheelhouse live-download fallback must be disabled")

    return spec


def materialize_evaluator_context(
    repo: Path,
    output_dir: Path,
    *,
    spec_path: Path | None = None,
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    spec = validate_spec(repo, spec_path)
    evaluator = spec["evaluator_build_context"]

    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise BuildAdapterError("evaluator context output directory must be empty")

    docker_source = _trusted_file(repo, str(evaluator["dockerfile_source"]))
    lock_source = _trusted_file(repo, str(evaluator["dependency_lock_source"]))

    docker_dest = output_dir / str(evaluator["dockerfile_output_name"])
    lock_dest = output_dir / str(evaluator["dependency_lock_output_name"])
    shutil.copyfile(docker_source, docker_dest)
    shutil.copyfile(lock_source, lock_dest)

    manifest = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "platform": PLATFORM,
        "decision_scope": DECISION_SCOPE,
        "files": {
            docker_dest.name: {
                "source": str(evaluator["dockerfile_source"]),
                "sha256": _sha256(docker_dest),
            },
            lock_dest.name: {
                "source": str(evaluator["dependency_lock_source"]),
                "sha256": _sha256(lock_dest),
            },
        },
        "named_contexts": {"wheelhouse": {"required": True, "manifest_required": True}},
        "runtime_execution_enabled": bool(spec["runtime_execution_enabled"]),
        "promotion_enabled": bool(spec["promotion_enabled"]),
    }
    (output_dir / "context-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def validate_wheelhouse_manifest(
    manifest_path: Path,
    wheelhouse_dir: Path,
) -> dict[str, Any]:
    manifest = _load_json(manifest_path, "AMD64 wheelhouse manifest")
    if manifest.get("schema_version") != 1:
        raise BuildAdapterError("wheelhouse manifest schema_version must be 1")
    if manifest.get("platform") != PLATFORM:
        raise BuildAdapterError("wheelhouse manifest platform must be linux/amd64")
    if manifest.get("decision_scope") != DECISION_SCOPE:
        raise BuildAdapterError("wheelhouse manifest decision_scope mismatch")

    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise BuildAdapterError("wheelhouse manifest files must be a non-empty list")

    expected: dict[str, tuple[int, str]] = {}
    for item in raw_files:
        if not isinstance(item, dict):
            raise BuildAdapterError("wheelhouse manifest contains a non-object file record")
        name = item.get("name")
        size = item.get("size")
        digest = item.get("sha256")
        if (
            not isinstance(name, str)
            or not name.endswith(".whl")
            or Path(name).name != name
            or name in {".", ".."}
        ):
            raise BuildAdapterError(f"wheelhouse filename is unsafe/invalid: {name!r}")
        if name in expected:
            raise BuildAdapterError(f"duplicate wheelhouse filename: {name}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BuildAdapterError(f"wheelhouse size is invalid: {name}")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise BuildAdapterError(f"wheelhouse SHA256 is invalid: {name}")
        expected[name] = (size, digest)

    try:
        entries = sorted(wheelhouse_dir.iterdir())
    except OSError as exc:
        raise BuildAdapterError(f"wheelhouse directory is unreadable: {exc}") from exc
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise BuildAdapterError("wheelhouse must contain regular non-symlink wheel files only")
    actual_paths = entries

    actual_names = {path.name for path in actual_paths}
    if actual_names != set(expected):
        missing = sorted(set(expected) - actual_names)
        extra = sorted(actual_names - set(expected))
        raise BuildAdapterError(f"wheelhouse file-set mismatch; missing={missing}, extra={extra}")

    for path in actual_paths:
        size, digest = expected[path.name]
        if path.stat().st_size != size:
            raise BuildAdapterError(f"wheelhouse size mismatch: {path.name}")
        if _sha256(path) != digest:
            raise BuildAdapterError(f"wheelhouse SHA256 mismatch: {path.name}")
    return manifest


def _main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-spec")
    validate.add_argument("--repo", type=Path, required=True)
    validate.add_argument("--spec", type=Path)

    materialize = sub.add_parser("materialize-evaluator-context")
    materialize.add_argument("--repo", type=Path, required=True)
    materialize.add_argument("--output", type=Path, required=True)
    materialize.add_argument("--spec", type=Path)

    wheelhouse = sub.add_parser("validate-wheelhouse")
    wheelhouse.add_argument("--manifest", type=Path, required=True)
    wheelhouse.add_argument("--wheelhouse", type=Path, required=True)

    image = sub.add_parser("validate-image-ref")
    image.add_argument("reference")

    args = parser.parse_args()
    try:
        if args.command == "validate-spec":
            validate_spec(args.repo, args.spec)
        elif args.command == "materialize-evaluator-context":
            manifest = materialize_evaluator_context(args.repo, args.output, spec_path=args.spec)
            print(json.dumps(manifest, sort_keys=True))
        elif args.command == "validate-wheelhouse":
            validate_wheelhouse_manifest(args.manifest, args.wheelhouse)
        elif args.command == "validate-image-ref":
            print(validate_ghcr_digest_reference(args.reference))
        else:
            raise BuildAdapterError(f"unsupported command: {args.command}")
    except BuildAdapterError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
