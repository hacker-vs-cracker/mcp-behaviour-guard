from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import stat
import tarfile
import time
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


class P4ResourceEnforcementError(RuntimeError):
    pass


POLICY_REL = "assurance/phase2/ci/p4-resource-policy.json"
MODULE_REL = "assurance/phase2/ci/p4_resource_enforcement.py"
IMPLEMENTED_PRIMITIVES = [
    "docker_log_options_builder",
    "build_command_limits",
    "artifact_tree_budget",
    "safe_archive_extraction",
    "bounded_json_parser",
    "fixture_traffic_budget",
    "attempt_deadline_and_single_attempt_lock",
    "owned_docker_resource_budget",
    "fail_closed_cleanup_classification",
]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise P4ResourceEnforcementError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_object_bytes(raw: bytes, *, max_bytes: int, label: str) -> dict[str, Any]:
    if len(raw) > max_bytes:
        raise P4ResourceEnforcementError(f"{label} exceeds {max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise P4ResourceEnforcementError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except P4ResourceEnforcementError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise P4ResourceEnforcementError(f"{label} is not valid bounded JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise P4ResourceEnforcementError(f"{label} must be a JSON object")
    return value


def load_policy(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise P4ResourceEnforcementError(f"cannot read policy {path}: {exc}") from exc
    return _load_object_bytes(raw, max_bytes=131_072, label="resource policy")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise P4ResourceEnforcementError(f"{label} must be an object")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise P4ResourceEnforcementError(f"{label} must be a positive integer")
    return value


def _limits(policy: dict[str, Any], key: str) -> dict[str, Any]:
    return _mapping(_mapping(policy.get("limits"), "limits").get(key), f"limits.{key}")


def _validate_json_shape(value: Any, policy: dict[str, Any]) -> None:
    max_depth = _positive_int(policy.get("max_depth"), "json.max_depth")
    max_string = _positive_int(policy.get("max_string_bytes"), "json.max_string_bytes")
    max_array = _positive_int(policy.get("max_array_items"), "json.max_array_items")
    max_members = _positive_int(policy.get("max_object_members"), "json.max_object_members")

    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise P4ResourceEnforcementError("JSON nesting depth exceeds policy")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > max_string:
                raise P4ResourceEnforcementError("JSON string exceeds policy")
        elif isinstance(current, list):
            if len(current) > max_array:
                raise P4ResourceEnforcementError("JSON array length exceeds policy")
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, dict):
            if len(current) > max_members:
                raise P4ResourceEnforcementError("JSON object member count exceeds policy")
            for key, item in current.items():
                if len(key.encode("utf-8")) > max_string:
                    raise P4ResourceEnforcementError("JSON key exceeds policy")
                stack.append((item, depth + 1))


def load_bounded_json(
    raw: bytes,
    policy: dict[str, Any],
    *,
    expected_schema_version: int,
    field_types: Mapping[str, type | tuple[type, ...]] | None = None,
) -> dict[str, Any]:
    json_policy = _mapping(policy.get("json_intake"), "json_intake")
    max_bytes = _positive_int(json_policy.get("max_bytes"), "json.max_bytes")
    value = _load_object_bytes(raw, max_bytes=max_bytes, label="JSON intake")
    _validate_json_shape(value, json_policy)
    if json_policy.get("schema_version_required") is not True:
        raise P4ResourceEnforcementError("JSON policy must require schema_version")
    schema_version = value.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != expected_schema_version:
        raise P4ResourceEnforcementError("JSON schema_version mismatch")
    if json_policy.get("field_types") != "strict":
        raise P4ResourceEnforcementError("JSON policy must require strict field types")
    for key, expected in (field_types or {}).items():
        if key not in value:
            raise P4ResourceEnforcementError(f"JSON field type mismatch: {key}")
        item = value[key]
        expected_types = expected if isinstance(expected, tuple) else (expected,)
        if isinstance(item, bool) and int in expected_types and bool not in expected_types:
            raise P4ResourceEnforcementError(f"JSON field type mismatch: {key}")
        if not isinstance(item, expected_types):
            raise P4ResourceEnforcementError(f"JSON field type mismatch: {key}")
    return value


def _directory_depth(root: Path, path: Path) -> int:
    rel = path.relative_to(root)
    return len(rel.parts)


def validate_directory_budget(
    root: Path,
    *,
    total_bytes: int,
    per_file_bytes: int,
    max_files: int,
    max_depth: int,
) -> dict[str, int]:
    root = root.resolve(strict=True)
    total = 0
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in list(dirnames):
            path = base / name
            if path.is_symlink():
                raise P4ResourceEnforcementError(f"symlink directory rejected: {path}")
            if _directory_depth(root, path) > max_depth:
                raise P4ResourceEnforcementError("directory depth exceeds policy")
        for name in filenames:
            path = base / name
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode):
                raise P4ResourceEnforcementError(f"non-regular artifact rejected: {path}")
            if _directory_depth(root, path) > max_depth:
                raise P4ResourceEnforcementError("artifact depth exceeds policy")
            if st.st_size > per_file_bytes:
                raise P4ResourceEnforcementError("artifact file exceeds policy")
            count += 1
            total += st.st_size
            if count > max_files:
                raise P4ResourceEnforcementError("artifact file count exceeds policy")
            if total > total_bytes:
                raise P4ResourceEnforcementError("artifact total bytes exceeds policy")
    return {"files": count, "bytes": total}


def validate_artifact_tree(root: Path, policy: dict[str, Any]) -> dict[str, int]:
    limits = _limits(policy, "artifacts")
    return validate_directory_budget(
        root,
        total_bytes=_positive_int(limits.get("total_bytes"), "artifacts.total_bytes"),
        per_file_bytes=_positive_int(limits.get("per_file_bytes"), "artifacts.per_file_bytes"),
        max_files=_positive_int(limits.get("max_files"), "artifacts.max_files"),
        max_depth=_positive_int(limits.get("max_depth"), "artifacts.max_depth"),
    )


def validate_build_context(root: Path, policy: dict[str, Any]) -> dict[str, int]:
    build = _limits(policy, "build")
    candidate = _limits(policy, "candidate_source")
    return validate_directory_budget(
        root,
        total_bytes=_positive_int(build.get("context_bytes"), "build.context_bytes"),
        per_file_bytes=_positive_int(build.get("context_bytes"), "build.context_bytes"),
        max_files=_positive_int(candidate.get("allowed_files"), "candidate.allowed_files") + 1,
        max_depth=2,
    )


def _archive_name(raw_name: str, *, max_depth: int) -> tuple[str, bool]:
    if not raw_name or "\x00" in raw_name or "\\" in raw_name:
        raise P4ResourceEnforcementError("archive member name is invalid")
    if raw_name.startswith("/"):
        raise P4ResourceEnforcementError("absolute archive path rejected")
    path = PurePosixPath(raw_name)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise P4ResourceEnforcementError("archive path traversal rejected")
    clean_parts = tuple(part for part in path.parts if part not in ("", "."))
    if not clean_parts:
        raise P4ResourceEnforcementError("empty archive path rejected")
    if len(clean_parts) > max_depth:
        raise P4ResourceEnforcementError("archive depth exceeds policy")
    clean = "/".join(clean_parts)
    return clean, raw_name.endswith("/")


def _register_archive_path(
    name: str,
    *,
    is_dir: bool,
    seen: dict[str, str],
) -> None:
    if name in seen:
        raise P4ResourceEnforcementError("duplicate archive name rejected")
    parts = name.split("/")
    for idx in range(1, len(parts)):
        parent = "/".join(parts[:idx])
        if seen.get(parent) == "file":
            raise P4ResourceEnforcementError("archive file/directory collision rejected")
    prefix = name + "/"
    if not is_dir and any(existing.startswith(prefix) for existing in seen):
        raise P4ResourceEnforcementError("archive file/directory collision rejected")
    seen[name] = "dir" if is_dir else "file"


def _copy_limited(source: Any, target: Any, *, expected: int) -> None:
    remaining = expected
    while remaining:
        chunk = source.read(min(65_536, remaining))
        if not chunk:
            raise P4ResourceEnforcementError("archive member ended before declared size")
        target.write(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise P4ResourceEnforcementError("archive member exceeds declared size")


def _prepare_destination(destination: Path) -> Path:
    if destination.is_symlink():
        raise P4ResourceEnforcementError("archive destination symlink rejected")
    destination = destination.resolve()
    if destination.exists():
        if not destination.is_dir():
            raise P4ResourceEnforcementError("archive destination must be a directory")
        if any(destination.iterdir()):
            raise P4ResourceEnforcementError("archive destination must be absent or empty")
    else:
        destination.mkdir(parents=True, mode=0o700)
    return destination


def _safe_target(destination: Path, name: str) -> Path:
    target = (destination / name).resolve()
    try:
        target.relative_to(destination)
    except ValueError as exc:
        raise P4ResourceEnforcementError("archive target escapes destination") from exc
    return target


def _archive_limits(policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    archive = _mapping(policy.get("archive_extraction"), "archive_extraction")
    artifacts = _limits(policy, "artifacts")
    for key in (
        "reject_absolute_paths",
        "reject_parent_traversal",
        "reject_symlinks",
        "reject_hardlinks",
        "reject_device_entries",
        "reject_duplicate_names",
        "reject_type_collisions",
    ):
        if archive.get(key) is not True:
            raise P4ResourceEnforcementError(f"archive hardening flag is not enabled: {key}")
    return archive, artifacts


def _check_archive_totals(
    *,
    compressed_size: int,
    expanded_size: int,
    file_count: int,
    archive: dict[str, Any],
    artifacts: dict[str, Any],
) -> None:
    compressed_limit = _positive_int(archive.get("compressed_bytes"), "archive.compressed_bytes")
    expanded_limit = _positive_int(archive.get("expanded_bytes"), "archive.expanded_bytes")
    ratio = _positive_int(archive.get("max_expansion_ratio"), "archive.max_expansion_ratio")
    max_files = min(
        _positive_int(archive.get("max_files"), "archive.max_files"),
        _positive_int(artifacts.get("max_files"), "artifacts.max_files"),
    )
    artifact_total = _positive_int(artifacts.get("total_bytes"), "artifacts.total_bytes")
    if compressed_size > compressed_limit:
        raise P4ResourceEnforcementError("archive compressed bytes exceed policy")
    if expanded_size > expanded_limit or expanded_size > artifact_total:
        raise P4ResourceEnforcementError("archive expanded bytes exceed policy")
    if file_count > max_files:
        raise P4ResourceEnforcementError("archive file count exceeds policy")
    if compressed_size == 0:
        if expanded_size:
            raise P4ResourceEnforcementError("archive expansion ratio exceeds policy")
    elif expanded_size > compressed_size * ratio:
        raise P4ResourceEnforcementError("archive expansion ratio exceeds policy")


def _extract_zip(archive_path: Path, destination: Path, policy: dict[str, Any]) -> dict[str, int]:
    archive, artifacts = _archive_limits(policy)
    max_depth = min(
        _positive_int(archive.get("max_depth"), "archive.max_depth"),
        _positive_int(artifacts.get("max_depth"), "artifacts.max_depth"),
    )
    per_file = _positive_int(artifacts.get("per_file_bytes"), "artifacts.per_file_bytes")
    seen: dict[str, str] = {}
    files: list[tuple[zipfile.ZipInfo, str]] = []
    expanded = 0
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            name, trailing_dir = _archive_name(info.filename, max_depth=max_depth)
            mode = (info.external_attr >> 16) & 0o170000
            is_dir = info.is_dir() or trailing_dir
            if mode == stat.S_IFLNK:
                raise P4ResourceEnforcementError("archive symlink rejected")
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise P4ResourceEnforcementError("archive special entry rejected")
            _register_archive_path(name, is_dir=is_dir, seen=seen)
            if is_dir:
                continue
            if info.file_size > per_file:
                raise P4ResourceEnforcementError("archive member exceeds per-file policy")
            expanded += info.file_size
            files.append((info, name))
        _check_archive_totals(
            compressed_size=archive_path.stat().st_size,
            expanded_size=expanded,
            file_count=len(files),
            archive=archive,
            artifacts=artifacts,
        )
        destination = _prepare_destination(destination)
        for name, kind in seen.items():
            if kind == "dir":
                _safe_target(destination, name).mkdir(parents=True, exist_ok=True)
        for info, name in files:
            target = _safe_target(destination, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as source, target.open("xb") as output:
                _copy_limited(source, output, expected=info.file_size)
    return validate_artifact_tree(destination, policy)


def _extract_tar(archive_path: Path, destination: Path, policy: dict[str, Any]) -> dict[str, int]:
    archive, artifacts = _archive_limits(policy)
    max_depth = min(
        _positive_int(archive.get("max_depth"), "archive.max_depth"),
        _positive_int(artifacts.get("max_depth"), "artifacts.max_depth"),
    )
    per_file = _positive_int(artifacts.get("per_file_bytes"), "artifacts.per_file_bytes")
    seen: dict[str, str] = {}
    files: list[tuple[tarfile.TarInfo, str]] = []
    expanded = 0
    with tarfile.open(archive_path, mode="r:*") as tf:
        for member in tf.getmembers():
            name, trailing_dir = _archive_name(member.name, max_depth=max_depth)
            is_dir = member.isdir() or trailing_dir
            if member.issym():
                raise P4ResourceEnforcementError("archive symlink rejected")
            if member.islnk():
                raise P4ResourceEnforcementError("archive hardlink rejected")
            if member.isdev() or member.isfifo():
                raise P4ResourceEnforcementError("archive device/fifo rejected")
            if not (member.isfile() or is_dir):
                raise P4ResourceEnforcementError("archive special entry rejected")
            _register_archive_path(name, is_dir=is_dir, seen=seen)
            if is_dir:
                continue
            if member.size > per_file:
                raise P4ResourceEnforcementError("archive member exceeds per-file policy")
            expanded += member.size
            files.append((member, name))
        _check_archive_totals(
            compressed_size=archive_path.stat().st_size,
            expanded_size=expanded,
            file_count=len(files),
            archive=archive,
            artifacts=artifacts,
        )
        destination = _prepare_destination(destination)
        for name, kind in seen.items():
            if kind == "dir":
                _safe_target(destination, name).mkdir(parents=True, exist_ok=True)
        for member, name in files:
            source = tf.extractfile(member)
            if source is None:
                raise P4ResourceEnforcementError("archive regular file has no data stream")
            target = _safe_target(destination, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("xb") as output:
                _copy_limited(source, output, expected=member.size)
    return validate_artifact_tree(destination, policy)


def safe_extract_archive(
    archive_path: Path, destination: Path, policy: dict[str, Any]
) -> dict[str, int]:
    archive_path = archive_path.resolve(strict=True)
    compressed_limit = _positive_int(
        _mapping(policy.get("archive_extraction"), "archive_extraction").get("compressed_bytes"),
        "archive.compressed_bytes",
    )
    if archive_path.stat().st_size > compressed_limit:
        raise P4ResourceEnforcementError("archive compressed bytes exceed policy")
    if zipfile.is_zipfile(archive_path):
        return _extract_zip(archive_path, destination, policy)
    if tarfile.is_tarfile(archive_path):
        return _extract_tar(archive_path, destination, policy)
    raise P4ResourceEnforcementError("unsupported archive format")


def _docker_size(value: int) -> str:
    for unit, divisor in (("g", 1024**3), ("m", 1024**2), ("k", 1024)):
        if value % divisor == 0:
            return f"{value // divisor}{unit}"
    return str(value)


def docker_resource_args(policy: dict[str, Any]) -> list[str]:
    docker = _limits(policy, "docker_runtime")
    if docker.get("log_driver") != "local":
        raise P4ResourceEnforcementError("docker log driver must be local")
    return [
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(_positive_int(docker.get("pids_limit"), "docker.pids_limit")),
        "--memory",
        str(_positive_int(docker.get("memory_bytes"), "docker.memory_bytes")),
        "--cpus",
        f"{_positive_int(docker.get('nano_cpus'), 'docker.nano_cpus') / 1_000_000_000:.2f}",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={_docker_size(_positive_int(docker.get('tmpfs_bytes'), 'docker.tmpfs_bytes'))}",
        "--log-driver",
        "local",
        "--log-opt",
        f"max-size={_docker_size(_positive_int(docker.get('log_max_size_bytes'), 'docker.log_max_size_bytes'))}",
        "--log-opt",
        f"max-file={_positive_int(docker.get('log_max_files'), 'docker.log_max_files')}",
    ]


def build_command_limits(policy: dict[str, Any]) -> dict[str, int]:
    build = _limits(policy, "build")
    return {
        "timeout_seconds": _positive_int(build.get("timeout_seconds"), "build.timeout_seconds"),
        "output_budget_bytes": _positive_int(
            build.get("log_output_bytes"), "build.log_output_bytes"
        ),
        "context_bytes": _positive_int(build.get("context_bytes"), "build.context_bytes"),
    }


def subprocess_limits(policy: dict[str, Any]) -> dict[str, int]:
    subprocess_policy = _limits(policy, "subprocess")
    return {
        "timeout_seconds": _positive_int(
            subprocess_policy.get("command_timeout_seconds"), "subprocess.command_timeout_seconds"
        ),
        "output_budget_bytes": _positive_int(
            subprocess_policy.get("aggregate_output_bytes"), "subprocess.aggregate_output_bytes"
        ),
        "capture_limit_bytes": _positive_int(
            subprocess_policy.get("retained_bytes_per_stream"),
            "subprocess.retained_bytes_per_stream",
        ),
    }


@dataclass
class TrafficBudget:
    request_bytes: int
    response_bytes: int
    max_requests: int
    aggregate_bytes: int
    requests: int = 0
    total_bytes: int = 0

    @classmethod
    def from_policy(cls, policy: dict[str, Any]) -> TrafficBudget:
        value = _limits(policy, "fixture_traffic")
        return cls(
            request_bytes=_positive_int(value.get("request_bytes"), "fixture.request_bytes"),
            response_bytes=_positive_int(value.get("response_bytes"), "fixture.response_bytes"),
            max_requests=_positive_int(value.get("max_requests"), "fixture.max_requests"),
            aggregate_bytes=_positive_int(value.get("aggregate_bytes"), "fixture.aggregate_bytes"),
        )

    def record(self, *, request_bytes: int, response_bytes: int) -> None:
        if request_bytes < 0 or response_bytes < 0:
            raise P4ResourceEnforcementError("fixture byte counts must be non-negative")
        if request_bytes > self.request_bytes:
            raise P4ResourceEnforcementError("fixture request exceeds policy")
        if response_bytes > self.response_bytes:
            raise P4ResourceEnforcementError("fixture response exceeds policy")
        self.requests += 1
        self.total_bytes += request_bytes + response_bytes
        if self.requests > self.max_requests:
            raise P4ResourceEnforcementError("fixture request count exceeds policy")
        if self.total_bytes > self.aggregate_bytes:
            raise P4ResourceEnforcementError("fixture aggregate bytes exceed policy")


@dataclass
class OwnedResourceBudget:
    max_containers: int
    max_networks: int
    max_volumes: int
    containers: int = 0
    networks: int = 0
    volumes: int = 0

    @classmethod
    def from_policy(cls, policy: dict[str, Any]) -> OwnedResourceBudget:
        value = _limits(policy, "docker_runtime")
        return cls(
            max_containers=_positive_int(
                value.get("max_owned_containers_per_attempt"),
                "docker.max_owned_containers_per_attempt",
            ),
            max_networks=_positive_int(
                value.get("max_owned_networks_per_attempt"),
                "docker.max_owned_networks_per_attempt",
            ),
            max_volumes=_positive_int(
                value.get("max_owned_volumes_per_attempt"),
                "docker.max_owned_volumes_per_attempt",
            ),
        )

    def record_container(self) -> None:
        self.containers += 1
        if self.containers > self.max_containers:
            raise P4ResourceEnforcementError("owned container count exceeds policy")

    def record_network(self) -> None:
        self.networks += 1
        if self.networks > self.max_networks:
            raise P4ResourceEnforcementError("owned network count exceeds policy")

    def record_volume(self) -> None:
        self.volumes += 1
        if self.volumes > self.max_volumes:
            raise P4ResourceEnforcementError("owned volume count exceeds policy")


@dataclass(frozen=True)
class AttemptDeadline:
    deadline: float
    cleanup_timeout_seconds: int

    @classmethod
    def from_policy(cls, policy: dict[str, Any], *, now: float | None = None) -> AttemptDeadline:
        value = _limits(policy, "execution")
        attempt = _positive_int(
            value.get("attempt_timeout_seconds"), "execution.attempt_timeout_seconds"
        )
        cleanup = _positive_int(
            value.get("cleanup_timeout_seconds"), "execution.cleanup_timeout_seconds"
        )
        current = time.monotonic() if now is None else now
        return cls(deadline=current + attempt, cleanup_timeout_seconds=cleanup)

    def remaining(self, *, now: float | None = None) -> float:
        current = time.monotonic() if now is None else now
        remaining = self.deadline - current
        if remaining <= 0:
            raise P4ResourceEnforcementError("attempt timeout exceeded")
        return remaining


class AttemptLease:
    def __init__(self, path: Path, policy: dict[str, Any]) -> None:
        execution = _limits(policy, "execution")
        if (
            _positive_int(
                execution.get("max_concurrent_attempts"), "execution.max_concurrent_attempts"
            )
            != 1
        ):
            raise P4ResourceEnforcementError("only max_concurrent_attempts=1 is supported")
        self.path = path
        self._file: Any = None

    def __enter__(self) -> AttemptLease:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a+b")
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._file.close()
            self._file = None
            raise P4ResourceEnforcementError("concurrent attempt rejected") from exc
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        if self._file is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            self._file.close()
            self._file = None


def classify_cleanup_evidence(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    cleanup = _mapping(policy.get("cleanup_semantics"), "cleanup_semantics")
    unknown = {
        "outcome": cleanup.get("malformed_or_missing_evidence_outcome"),
        "recovery_required": cleanup.get("recovery_required"),
    }
    if unknown != {"outcome": "UNKNOWN", "recovery_required": True}:
        raise P4ResourceEnforcementError("cleanup policy must fail closed")
    if not isinstance(value, dict):
        return unknown
    if set(value) != {"cleanup_complete", "owned_resources_remaining"}:
        return unknown
    if not isinstance(value.get("cleanup_complete"), bool):
        return unknown
    remaining = value.get("owned_resources_remaining")
    if isinstance(remaining, bool) or not isinstance(remaining, int) or remaining < 0:
        return unknown
    if value["cleanup_complete"] is True and remaining == 0:
        return {"outcome": "CLEAN", "recovery_required": False}
    return unknown


def policy_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_trust_binding(repo: Path, trust_path: Path, policy_path: Path) -> dict[str, Any]:
    policy = load_policy(policy_path)
    trust = _load_object_bytes(trust_path.read_bytes(), max_bytes=131_072, label="trust boundary")
    binding = _mapping(trust.get("p4_resource_enforcement"), "trust.p4_resource_enforcement")
    expected = {
        "status": "IMPLEMENTED_NOT_RUNTIME_PROVEN",
        "stage": "PRE_HOSTILE_ENFORCEMENT_IMPLEMENTATION",
        "module_path": MODULE_REL,
        "module_sha256": hashlib.sha256((repo / MODULE_REL).read_bytes()).hexdigest(),
        "policy_path": POLICY_REL,
        "policy_sha256": policy_sha256(policy_path),
        "candidate_execution_enabled": False,
        "hostile_execution_authorized": False,
        "runtime_enforcement_proven": False,
        "implemented_primitives": IMPLEMENTED_PRIMITIVES,
    }
    if binding != expected:
        raise P4ResourceEnforcementError("trust-boundary enforcement binding mismatch")
    controller = _mapping(trust.get("controller"), "trust.controller")
    if (
        controller.get("controller_stage") != "INTAKE_ONLY"
        or controller.get("candidate_execution_enabled") is not False
    ):
        raise P4ResourceEnforcementError(
            "controller must remain intake-only with candidate execution disabled"
        )
    publisher = _mapping(trust.get("publisher"), "trust.publisher")
    if (
        publisher.get("bootstrap_status") != "UNBOOTSTRAPPED"
        or publisher.get("integration_id") is not None
    ):
        raise P4ResourceEnforcementError("publisher must remain unbootstrapped")
    consumed = trust.get("consumed_trusted_inputs")
    if not isinstance(consumed, list) or consumed.count(MODULE_REL) != 1:
        raise P4ResourceEnforcementError(
            "enforcement module must be listed exactly once as trusted input"
        )
    if (
        policy.get("runtime_enforcement_proven") is not False
        or policy.get("candidate_execution_enabled") is not False
    ):
        raise P4ResourceEnforcementError("frozen policy must remain unproven and non-executing")
    return binding


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--trust-boundary", type=Path, required=True)
    args = parser.parse_args()
    binding = validate_trust_binding(
        args.repo.resolve(), args.trust_boundary.resolve(), args.policy.resolve()
    )
    print(
        json.dumps(
            {
                "status": "P4_RESOURCE_ENFORCEMENT_IMPLEMENTED_NOT_RUNTIME_PROVEN",
                "candidate_execution_enabled": binding["candidate_execution_enabled"],
                "hostile_execution_authorized": binding["hostile_execution_authorized"],
                "runtime_enforcement_proven": binding["runtime_enforcement_proven"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
