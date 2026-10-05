from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

CI_DIR = Path(__file__).resolve().parent
PHASE2 = CI_DIR.parent
sys.path.insert(0, str(CI_DIR))
sys.path.insert(0, str(PHASE2))

import build_adapter  # type: ignore  # noqa: E402
from run_isolation_check import (  # type: ignore  # noqa: E402
    IsolationError,
    _assert_security,
    _resource_args,
    _run,
    _wait_exec,
)

EXPECTED_PLATFORM = "linux/amd64"
EXPECTED_SCOPE = "phase2c_trusted_ci_gate_only"
EXPECTED_BASE_MANIFEST = "sha256:fa7a862d74b4decf68fb7d3a85147efc14dbcd3779c0abd56c071d27a1ffee04"
EXPECTED_IMAGES = ("evaluator", "fixture", "candidate_probe", "vertical_candidate", "gate")
_LOCK_LINE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})$")


class P2ProofError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise P2ProofError(f"invalid JSON {path}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise P2ProofError(f"JSON must be an object: {path}")
    return value


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise P2ProofError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _normalize_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _lock_entries(lock_path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for raw in lock_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _LOCK_LINE.fullmatch(line)
        if not match:
            raise P2ProofError(f"unexpected AMD64 lock line: {line!r}")
        rows.append((_normalize_distribution(match.group(1)), match.group(2)))
    if not rows:
        raise P2ProofError("AMD64 lock is empty")
    if len(rows) != len(set(rows)):
        raise P2ProofError("AMD64 lock contains duplicate package/version entries")
    return rows


def _wheel_identity(path: Path) -> tuple[str, str]:
    if path.suffix != ".whl":
        raise P2ProofError(f"wheelhouse contains a non-wheel file: {path.name}")
    parts = path.name[:-4].split("-")
    if len(parts) < 5:
        raise P2ProofError(f"invalid wheel filename: {path.name}")
    return _normalize_distribution(parts[0]), parts[1]


def _validate_wheelhouse_coverage(lock_path: Path, entries: list[Path]) -> None:
    expected = sorted(_lock_entries(lock_path))
    actual = sorted(_wheel_identity(path) for path in entries)
    if expected != actual:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise P2ProofError(
            f"wheelhouse package coverage mismatch; missing={missing}, extra={extra}"
        )


def assert_native(output: Path) -> dict[str, Any]:
    uname = platform.machine().lower()
    docker = _run("docker", "info", "--format", "{{.Architecture}}").stdout.strip().lower()
    if uname not in {"x86_64", "amd64"}:
        raise P2ProofError(f"native host is not AMD64: {uname}")
    if docker not in {"x86_64", "amd64"}:
        raise P2ProofError(f"Docker server is not AMD64: {docker}")
    data: dict[str, Any] = {
        "schema_version": 1,
        "platform": EXPECTED_PLATFORM,
        "uname_m": uname,
        "docker_architecture": docker,
        "docker_server_version": _run(
            "docker", "version", "--format", "{{.Server.Version}}"
        ).stdout.strip(),
    }
    _write(output, data)
    return data


def seal_wheelhouse(repo: Path, wheelhouse: Path, output: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    spec = build_adapter.validate_spec(repo)
    lock_rel = str(spec["evaluator_build_context"]["dependency_lock_source"])
    lock_path = repo / lock_rel

    entries = sorted(wheelhouse.iterdir())
    if not entries:
        raise P2ProofError("wheelhouse is empty")
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise P2ProofError("wheelhouse must contain regular non-symlink files only")
    _validate_wheelhouse_coverage(lock_path, entries)

    manifest = {
        "schema_version": 1,
        "platform": EXPECTED_PLATFORM,
        "decision_scope": EXPECTED_SCOPE,
        "requirements_path": lock_rel,
        "requirements_sha256": _sha256(lock_path),
        "files": [
            {
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in entries
        ],
    }
    _write(output, manifest)
    build_adapter.validate_wheelhouse_manifest(output, wheelhouse)
    return manifest


def consumed_inputs(repo: Path, output: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    boundary = _json(repo / "assurance/phase2/ci/trust-boundary.json")
    paths = boundary.get("consumed_trusted_inputs")
    if not isinstance(paths, list) or not paths or not all(isinstance(x, str) for x in paths):
        raise P2ProofError("consumed_trusted_inputs must be a non-empty string list")
    if len(paths) != len(set(paths)):
        raise P2ProofError("consumed_trusted_inputs contains duplicates")

    rows: list[dict[str, Any]] = []
    for rel in paths:
        candidate = repo / rel
        if candidate.is_symlink() or not candidate.is_file():
            raise P2ProofError(f"consumed input is not a regular file: {rel}")
        stage = _git(repo, "ls-files", "--stage", "--", rel)
        fields = stage.split(maxsplit=3)
        if len(fields) != 4 or fields[0] != "100644":
            raise P2ProofError(f"consumed input is not tracked 100644: {rel}: {stage!r}")
        rows.append(
            {
                "path": rel,
                "git_mode": fields[0],
                "blob_oid": fields[1],
                "sha256": _sha256(candidate),
                "bytes": candidate.stat().st_size,
            }
        )

    manifest = {
        "schema_version": 1,
        "source_commit": _git(repo, "rev-parse", "HEAD"),
        "source_tree": _git(repo, "rev-parse", "HEAD^{tree}"),
        "platform": EXPECTED_PLATFORM,
        "decision_scope": EXPECTED_SCOPE,
        "files": rows,
    }
    _write(output, manifest)
    return manifest


def _registry_digest(reference: str) -> str:
    if "@" not in reference:
        raise P2ProofError("registry reference must be digest-pinned")
    digest = reference.rsplit("@", 1)[1]
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise P2ProofError(f"invalid registry digest: {digest!r}")
    return digest


def _json_run_image(ref: str) -> dict[str, Any]:
    value = json.loads(_run("docker", "image", "inspect", ref).stdout)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise P2ProofError(f"unexpected docker image inspect result for {ref}")
    return value[0]


def _json_run_container(name: str) -> dict[str, Any]:
    value = json.loads(_run("docker", "container", "inspect", name).stdout)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise P2ProofError(f"unexpected container inspect result for {name}")
    return value[0]


def image_identity(name: str, local_ref: str, registry_ref: str, output: Path) -> dict[str, Any]:
    if name not in EXPECTED_IMAGES:
        raise P2ProofError(f"unsupported image name: {name}")
    build_adapter.validate_ghcr_digest_reference(registry_ref)
    registry_digest = _registry_digest(registry_ref)

    raw = json.loads(
        _run("docker", "buildx", "imagetools", "inspect", "--raw", registry_ref).stdout
    )
    if not isinstance(raw, dict):
        raise P2ProofError("registry manifest document must be an object")
    media_type = str(raw.get("mediaType") or "")

    index_digest: str | None
    if isinstance(raw.get("manifests"), list):
        matches = [
            item
            for item in raw["manifests"]
            if isinstance(item, dict)
            and (item.get("platform") or {}).get("os") == "linux"
            and (item.get("platform") or {}).get("architecture") == "amd64"
            and not (item.get("annotations") or {}).get("vnd.docker.reference.type")
        ]
        if len(matches) != 1:
            raise P2ProofError(f"expected exactly one linux/amd64 manifest for {name}")
        platform_digest = str(matches[0].get("digest"))
        index_digest = registry_digest
        child_ref = registry_ref.rsplit("@", 1)[0] + "@" + platform_digest
        child = json.loads(
            _run("docker", "buildx", "imagetools", "inspect", "--raw", child_ref).stdout
        )
    else:
        platform_digest = registry_digest
        index_digest = None
        child = raw

    config = child.get("config")
    if not isinstance(config, dict) or not isinstance(config.get("digest"), str):
        raise P2ProofError(f"image {name} manifest has no config digest")
    config_digest = str(config["digest"])

    local = _json_run_image(local_ref)
    architecture = str(local.get("Architecture") or "").lower()
    os_name = str(local.get("Os") or "").lower()
    local_id = str(local.get("Id") or "")
    if architecture != "amd64" or os_name != "linux":
        raise P2ProofError(f"image {name} is not linux/amd64: {os_name}/{architecture}")
    if local_id != config_digest:
        raise P2ProofError(
            f"image {name} local config does not match registry config: "
            f"{local_id} != {config_digest}"
        )

    identity = {
        "name": name,
        "os": os_name,
        "architecture": architecture,
        "execution_ref": registry_ref,
        "registry_digest": registry_digest,
        "registry_media_type": media_type,
        "oci_index_digest": index_digest,
        "platform_manifest_digest": platform_digest,
        "config_digest": config_digest,
        "local_build_ref": local_ref,
    }
    _write(output, identity)
    return identity


def compose_profile(
    repo: Path,
    identities_dir: Path,
    wheelhouse_manifest: Path,
    consumed_manifest: Path,
    output: Path,
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    template = _json(repo / "assurance/phase2/ci/runtime-profile-template.json")
    spec = build_adapter.validate_spec(repo)
    wheelhouse = _json(wheelhouse_manifest)
    consumed = _json(consumed_manifest)

    images: dict[str, Any] = {}
    for name in EXPECTED_IMAGES:
        identity = _json(identities_dir / f"{name}.json")
        if identity.get("name") != name:
            raise P2ProofError(f"image identity name mismatch: {name}")
        if identity.get("os") != "linux" or identity.get("architecture") != "amd64":
            raise P2ProofError(f"image identity platform mismatch: {name}")
        build_adapter.validate_ghcr_digest_reference(str(identity.get("execution_ref")))
        images[name] = identity

    profile = template
    profile["status"] = "P2_PROOF_ONLY"
    profile["consumable"] = False
    profile["base_image"]["platform_manifest_digest"] = EXPECTED_BASE_MANIFEST
    profile["base_image"]["selection_rule"] = "accepted-characterized-linux-amd64-manifest"
    profile["images"] = images
    profile["reference"] = {
        "status": "UNPROMOTED",
        "approval_bundle_digest": None,
        "origin_attempt_id": None,
    }
    profile["proof"] = {
        "source_commit": _git(repo, "rev-parse", "HEAD"),
        "source_tree": _git(repo, "rev-parse", "HEAD^{tree}"),
        "wheelhouse_manifest_sha256": _sha256(wheelhouse_manifest),
        "consumed_inputs_manifest_sha256": _sha256(consumed_manifest),
        "wheel_count": len(wheelhouse.get("files") or []),
        "consumed_input_count": len(consumed.get("files") or []),
        "image_distribution": spec["image_distribution"],
        "promotion_enabled": False,
    }

    fixture_profile = repo / "assurance/phase2/fixture-profile.json"
    profile["fixture_profile"] = {
        "profile_id": _json(fixture_profile)["profile_id"],
        "sha256": _sha256(fixture_profile),
    }
    _write(output, profile)
    validate_profile(output)
    return profile


def validate_profile(path: Path) -> dict[str, Any]:
    profile = _json(path)
    if profile.get("status") != "P2_PROOF_ONLY" or profile.get("consumable") is not False:
        raise P2ProofError("P2 proof profile must remain non-consumable")
    if profile.get("platform") != EXPECTED_PLATFORM:
        raise P2ProofError("P2 proof profile platform mismatch")
    if profile.get("decision_scope") != EXPECTED_SCOPE:
        raise P2ProofError("P2 proof profile decision scope mismatch")
    if profile.get("base_image", {}).get("platform_manifest_digest") != EXPECTED_BASE_MANIFEST:
        raise P2ProofError("P2 proof base manifest mismatch")
    if profile.get("reference", {}).get("status") != "UNPROMOTED":
        raise P2ProofError("P2 must not promote a reference")

    images = profile.get("images")
    if not isinstance(images, dict) or set(images) != set(EXPECTED_IMAGES):
        raise P2ProofError("P2 proof image set mismatch")
    for name, identity in images.items():
        if not isinstance(identity, dict):
            raise P2ProofError(f"invalid image identity: {name}")
        build_adapter.validate_ghcr_digest_reference(str(identity.get("execution_ref")))
        if identity.get("os") != "linux" or identity.get("architecture") != "amd64":
            raise P2ProofError(f"wrong image platform: {name}")
        for field in ("registry_digest", "platform_manifest_digest", "config_digest"):
            value = identity.get(field)
            if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
                raise P2ProofError(f"invalid {field} for {name}")
    return profile


def execution_refs(profile_path: Path) -> list[str]:
    profile = validate_profile(profile_path)
    refs = [str(profile["images"][name]["execution_ref"]) for name in EXPECTED_IMAGES]
    for ref in refs:
        print(ref)
    return refs


def _cleanup_container(name: str, errors: list[str]) -> None:
    result = _run("docker", "rm", "-f", name, check=False)
    if result.returncode not in {0, 1}:
        errors.append(f"container {name} removal failed: {result.stderr.strip()}")
    if _run("docker", "container", "inspect", name, check=False).returncode == 0:
        errors.append(f"container {name} still exists")


def _cleanup_network(name: str, errors: list[str]) -> None:
    result = _run("docker", "network", "rm", name, check=False)
    if result.returncode not in {0, 1}:
        errors.append(f"network {name} removal failed: {result.stderr.strip()}")
    if _run("docker", "network", "inspect", name, check=False).returncode == 0:
        errors.append(f"network {name} still exists")


def candidate_smoke(profile_path: Path, output: Path) -> dict[str, Any]:
    profile = validate_profile(profile_path)
    ref = str(profile["images"]["vertical_candidate"]["execution_ref"])
    suffix = uuid.uuid4().hex[:10]
    network = f"p2-native-candidate-{suffix}"
    container = f"p2-native-candidate-{suffix}"
    created_network = False
    created_container = False
    result: dict[str, Any] = {"cleanup_complete": False}
    errors: list[str] = []

    try:
        _run(
            "docker",
            "network",
            "create",
            "--internal",
            "--opt",
            "com.docker.network.bridge.gateway_mode_ipv4=isolated",
            network,
        )
        created_network = True
        _run(
            "docker",
            "run",
            "-d",
            "--name",
            container,
            "--network",
            network,
            *_resource_args(),
            "-e",
            "PHASE2_ATTEMPT_TOKEN=synthetic-p2-proof-token",
            ref,
        )
        created_container = True
        _wait_exec(
            container,
            "import urllib.request;"
            "urllib.request.urlopen('http://127.0.0.1:7000/healthz',timeout=1).read()",
        )
        security = _assert_security(container, [network], expected_uid=10002, candidate=True)
        inspected = _json_run_container(container)
        env_names = sorted(
            item.split("=", 1)[0]
            for item in (inspected.get("Config", {}).get("Env") or [])
            if isinstance(item, str) and "=" in item
        )
        forbidden = {
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "ACTIONS_RUNTIME_TOKEN",
            "DOCKER_AUTH_CONFIG",
            "CR_PAT",
        }
        if forbidden.intersection(env_names):
            raise P2ProofError(
                "candidate environment contains forbidden credential names: "
                f"{sorted(forbidden.intersection(env_names))}"
            )
        result.update(
            {
                "status": "passed",
                "runtime_uid": security["runtime_uid"],
                "security": security,
                "environment_variable_names": env_names,
                "publisher_or_repository_credentials_present": False,
            }
        )
    finally:
        if created_container:
            _cleanup_container(container, errors)
        if created_network:
            _cleanup_network(network, errors)
        result["cleanup_errors"] = errors
        result["cleanup_complete"] = not errors
        _write(output, result)
        if errors:
            raise P2ProofError("candidate smoke cleanup failed: " + "; ".join(errors))
    return result


def negative_controls(profile_path: Path, output: Path) -> dict[str, Any]:
    profile = validate_profile(profile_path)
    evaluator = str(profile["images"]["evaluator"]["execution_ref"])
    probe = str(profile["images"]["candidate_probe"]["execution_ref"])
    suffix = uuid.uuid4().hex[:10]
    hang = f"p2-negative-hang-{suffix}"
    startup = f"p2-negative-startup-{suffix}"
    memory = f"p2-negative-memory-{suffix}"
    cleanup_errors: list[str] = []
    created: list[str] = []
    results: dict[str, Any] = {"cleanup_complete": False}

    try:
        output_result = _run(
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "python",
            evaluator,
            "-c",
            "print('x' * 200000)",
            capture_limit=1024,
        )
        if "[truncated after 1024 bytes]" not in output_result.stdout:
            raise P2ProofError("output exhaustion control was not bounded")
        results["output_exhaustion"] = {"capture_bounded": True}

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            hang,
            "--network",
            "none",
            *_resource_args(),
            "--entrypoint",
            "python",
            evaluator,
            "-c",
            "import time; time.sleep(300)",
        )
        created.append(hang)
        try:
            _run(
                "docker",
                "exec",
                hang,
                "python",
                "-c",
                "import time; time.sleep(300)",
                timeout=1.0,
            )
        except IsolationError as exc:
            if "timed out" not in str(exc):
                raise
            results["hang_timeout"] = {"bounded_timeout_observed": True}
        else:
            raise P2ProofError("hang control unexpectedly completed")

        startup_result = _run(
            "docker",
            "run",
            "--name",
            startup,
            "--network",
            "none",
            *_resource_args(),
            probe,
            "not-a-command",
            check=False,
        )
        created.append(startup)
        if startup_result.returncode == 0:
            raise P2ProofError("startup-failure control unexpectedly succeeded")
        startup_inspect = _json_run_container(startup)
        results["startup_failure"] = {
            "nonzero_exit": True,
            "exit_code": startup_inspect.get("State", {}).get("ExitCode"),
        }

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            memory,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--memory",
            "64m",
            "--memory-swap",
            "64m",
            "--cpus",
            "0.50",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--entrypoint",
            "python",
            evaluator,
            "-c",
            "x=bytearray(512*1024*1024); print(len(x))",
        )
        created.append(memory)
        _run("docker", "wait", memory, timeout=30.0)
        memory_inspect = _json_run_container(memory)
        state = memory_inspect.get("State") or {}
        exit_code = state.get("ExitCode")
        if exit_code == 0:
            raise P2ProofError("memory-exhaustion control unexpectedly succeeded")
        results["memory_exhaustion"] = {
            "nonzero_exit": True,
            "exit_code": exit_code,
            "oom_killed": bool(state.get("OOMKilled")),
            "configured_memory_bytes": 64 * 1024 * 1024,
        }
    finally:
        for name in reversed(created):
            _cleanup_container(name, cleanup_errors)
        results["cleanup_errors"] = cleanup_errors
        results["cleanup_complete"] = not cleanup_errors
        _write(output, results)
        if cleanup_errors:
            raise P2ProofError("negative-control cleanup failed: " + "; ".join(cleanup_errors))
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    native = sub.add_parser("assert-native")
    native.add_argument("--output", type=Path, required=True)

    wheel = sub.add_parser("seal-wheelhouse")
    wheel.add_argument("--repo", type=Path, required=True)
    wheel.add_argument("--wheelhouse", type=Path, required=True)
    wheel.add_argument("--output", type=Path, required=True)

    consumed = sub.add_parser("consumed-inputs")
    consumed.add_argument("--repo", type=Path, required=True)
    consumed.add_argument("--output", type=Path, required=True)

    identity = sub.add_parser("image-identity")
    identity.add_argument("--name", required=True)
    identity.add_argument("--local-ref", required=True)
    identity.add_argument("--registry-ref", required=True)
    identity.add_argument("--output", type=Path, required=True)

    profile_cmd = sub.add_parser("compose-profile")
    profile_cmd.add_argument("--repo", type=Path, required=True)
    profile_cmd.add_argument("--identities-dir", type=Path, required=True)
    profile_cmd.add_argument("--wheelhouse-manifest", type=Path, required=True)
    profile_cmd.add_argument("--consumed-inputs", type=Path, required=True)
    profile_cmd.add_argument("--output", type=Path, required=True)

    validate_cmd = sub.add_parser("validate-profile")
    validate_cmd.add_argument("--profile", type=Path, required=True)

    refs = sub.add_parser("execution-refs")
    refs.add_argument("--profile", type=Path, required=True)

    smoke = sub.add_parser("candidate-smoke")
    smoke.add_argument("--profile", type=Path, required=True)
    smoke.add_argument("--output", type=Path, required=True)

    negatives = sub.add_parser("negative-controls")
    negatives.add_argument("--profile", type=Path, required=True)
    negatives.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "assert-native":
            assert_native(args.output)
        elif args.command == "seal-wheelhouse":
            seal_wheelhouse(args.repo, args.wheelhouse, args.output)
        elif args.command == "consumed-inputs":
            consumed_inputs(args.repo, args.output)
        elif args.command == "image-identity":
            image_identity(args.name, args.local_ref, args.registry_ref, args.output)
        elif args.command == "compose-profile":
            compose_profile(
                args.repo,
                args.identities_dir,
                args.wheelhouse_manifest,
                args.consumed_inputs,
                args.output,
            )
        elif args.command == "validate-profile":
            validate_profile(args.profile)
        elif args.command == "execution-refs":
            execution_refs(args.profile)
        elif args.command == "candidate-smoke":
            candidate_smoke(args.profile, args.output)
        elif args.command == "negative-controls":
            negative_controls(args.profile, args.output)
        else:
            raise P2ProofError(f"unsupported command: {args.command}")
    except (P2ProofError, build_adapter.BuildAdapterError, IsolationError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
