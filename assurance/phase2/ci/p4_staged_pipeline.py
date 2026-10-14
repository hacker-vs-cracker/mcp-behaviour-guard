"""Source contracts for a separately attested native P4 build and metered runtime.

This module never launches a Docker daemon, builds candidates or grants P3 authority.
A build-stage report is a handover claim, not runtime or proof acceptance.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class P4StageError(ValueError):
    pass


SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def hash_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise P4StageError("trusted input must be an ordinary file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_build_profile(path: Path, policy: dict[str, Any]) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise P4StageError("untrusted native-build stage profile")
    try:
        profile = json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as exc:
        raise P4StageError("invalid build profile") from exc
    build = policy.get("limits", {}).get("build", {})
    execution = policy.get("limits", {}).get("execution", {})
    expected = {
        "name": "p4-native-isolated-build-v1",
        "status": "SOURCE_PROFILE_REQUIRES_NATIVE_ADMISSION",
        "platform": "linux/amd64",
        "driver": "dedicated-daemon-docker-buildkit",
        "builder_backend": "engine-bundled-buildkit-only",
        "buildx_container_driver_forbidden": True,
        "builder_has_no_separate_oci_identity": True,
        "private_engine_source_identity_required": True,
        "build_cli_must_bind_private_daemon_socket": True,
        "hard_daemon_data_root_bytes": 1073741824,
        "quota_applies_to": "entire-private-daemon-data-root-including-build-cache-and-loaded-images",
        "private_daemon_socket_required": True,
        "privileged_build_only_inside_disposable_native_worker": True,
        "default_shared_builder_forbidden": True,
        "unbounded_host_daemon_forbidden": True,
        "candidate_dockerfile_forbidden": True,
        "trusted_dockerfile": "assurance/phase2/vertical/Dockerfile",
        "candidate_source_allowlist": ["assurance/phase2/vertical/candidate_server.py"],
        "no_keep_state": True,
        "build_execution_authorized": False,
        "native_storage_proof_completed": False,
        "require_actual_daemon_and_filesystem_attestation": True,
        "require_postbuild_image_and_cleanup_inventory": True,
    }
    if (
        not isinstance(profile, dict)
        or profile.get("schema_version") != 1
        or any(profile.get(key) != value for key, value in expected.items())
    ):
        raise P4StageError("build isolation profile differs from reviewed source")
    for name, limit in (
        ("max_context_bytes", build.get("context_bytes")),
        ("build_timeout_seconds", build.get("timeout_seconds")),
        ("build_output_bytes", build.get("log_output_bytes")),
        ("outer_pipeline_timeout_seconds", execution.get("attempt_timeout_seconds")),
        ("cleanup_timeout_seconds", execution.get("cleanup_timeout_seconds")),
    ):
        if type(limit) is not int or profile.get(name) != limit:
            raise P4StageError("build profile cannot raise or reinterpret frozen policy limits")
    return profile


def verify_native_data_root(
    *,
    daemon_data_root: Path,
    docker_info: dict[str, Any],
    admission: NativeBuildAdmission,
) -> dict[str, int | str]:
    """Read the actual native filesystem and daemon identity before admission.

    The dedicated worker must still attest disk ownership and daemon lifecycle.
    A capacity check is not a substitute for physical write/cleanup proof.
    """
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise P4StageError("build requires native AMD64 Linux")
    if (
        not daemon_data_root.is_absolute()
        or daemon_data_root.is_symlink()
        or not daemon_data_root.is_dir()
        or daemon_data_root.resolve(strict=True) != daemon_data_root
        or not os.path.ismount(daemon_data_root)
        or str(daemon_data_root) != admission.daemon_data_root
    ):
        raise P4StageError("Docker data root must be a dedicated non-aliased filesystem")
    info = daemon_data_root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise P4StageError("native Docker data root is not private/root-owned")
    size = os.statvfs(daemon_data_root)
    capacity = size.f_frsize * size.f_blocks
    if not 0 < capacity <= 1073741824:
        raise P4StageError("Docker data-root filesystem lacks a physical 1GiB bound")
    if (
        docker_info.get("OSType") != "linux"
        or docker_info.get("Architecture") not in {"x86_64", "amd64"}
        or docker_info.get("DockerRootDir") != str(daemon_data_root)
        or not isinstance(docker_info.get("ID"), str)
        or hashlib.sha256(docker_info["ID"].encode()).hexdigest() != admission.daemon_id
    ):
        raise P4StageError("Docker info does not attest the requested private native daemon")
    return {
        "verified_data_root": str(daemon_data_root),
        "filesystem_bytes": capacity,
        "daemon_id_sha256": admission.daemon_id,
    }


@dataclass(frozen=True)
class NativeBuildAdmission:
    """External trusted native worker evidence. These fields alone are not proof."""

    worker_source: str
    platform: str
    daemon_endpoint: str
    daemon_id: str
    daemon_data_root: str
    dedicated_block_device_bytes: int
    disk_hard_limited: bool
    all_docker_writes_contained: bool
    owner_lease_scope: str

    def require_bound_stage(self, *, expected_worker_source: str, lease_scope: str) -> None:
        if (
            not COMMIT.fullmatch(self.worker_source)
            or self.worker_source != expected_worker_source
            or self.platform != "linux/amd64"
            or re.fullmatch(
                r"unix:///run/mcpbg-p4-[a-z0-9]{1,32}/engine\.sock", self.daemon_endpoint
            )
            is None
            or not SHA.fullmatch(self.daemon_id)
            or re.fullmatch(r"/mnt/mcpbg-p4-[a-z0-9]{1,32}/docker", self.daemon_data_root) is None
            or type(self.dedicated_block_device_bytes) is not int
            or not 0 < self.dedicated_block_device_bytes <= 1073741824
            or self.disk_hard_limited is not True
            or self.all_docker_writes_contained is not True
            or not SHA.fullmatch(self.owner_lease_scope)
            or self.owner_lease_scope != lease_scope
        ):
            raise P4StageError("native build-stage admission incomplete or out of scope")


def bind_stage_handoff(
    *,
    source_commit: str,
    source_tree: str,
    source_sha256: str,
    trusted_dockerfile_sha256: str,
    image_identity: str,
    producer_code_sha256: str,
    native_admission_sha256: str,
    reference_authority_sha256: str,
    policy_sha256: str,
    build_stage_clean: bool,
    image_transfer_identity_verified: bool,
) -> dict[str, Any]:
    """Bind build and runtime subjects without inventing P3 image equivalence.

    The image may persist as a tracked pipeline dependency when the build
    stage has been independently cleaned; do not count that as pipeline cleanup.
    """
    if not (COMMIT.fullmatch(source_commit) and COMMIT.fullmatch(source_tree)):
        raise P4StageError("build source commit and tree must be exact")
    if any(
        not SHA.fullmatch(value)
        for value in (
            source_sha256,
            trusted_dockerfile_sha256,
            producer_code_sha256,
            native_admission_sha256,
            reference_authority_sha256,
            policy_sha256,
        )
    ) or not IMAGE.fullmatch(image_identity):
        raise P4StageError("build handoff requires exact immutable identities")
    if build_stage_clean is not True or image_transfer_identity_verified is not True:
        raise P4StageError("build cleanup and image handover remain UNKNOWN")
    return {
        "schema_version": 1,
        "kind": "p4_stage_handoff_source_only",
        "source_commit": source_commit,
        "source_tree": source_tree,
        "candidate_source_sha256": source_sha256,
        "trusted_dockerfile_sha256": trusted_dockerfile_sha256,
        "build_producer_sha256": producer_code_sha256,
        "native_admission_sha256": native_admission_sha256,
        "candidate_image": image_identity,
        "reference_authority_sha256": reference_authority_sha256,
        "p4_policy_sha256": policy_sha256,
        "build_stage_clean": True,
        "pipeline_image_dependency_retained": True,
        "runtime_enforcement_proven": False,
        "candidate_execution_authorized": False,
        "p3_equivalence_claimed": False,
    }


def plan_private_native_build(
    *,
    admission: NativeBuildAdmission,
    expected_worker_source: str,
    lease_scope: str,
    context: Path,
    trusted_dockerfile_sha256: str,
    candidate_source_sha256: str,
    base_image: str,
    owned_tag: str,
    policy: dict[str, Any],
) -> list[str]:
    """Plan an isolated daemon-bundled BuildKit command, without executing it.

    This avoids Buildx's separate privileged container/cache volume. The Engine
    itself remains confined to the admitted disposable native worker and bounded
    private data-root. Source tests cannot establish that OS-level isolation.
    """
    admission.require_bound_stage(
        expected_worker_source=expected_worker_source, lease_scope=lease_scope
    )
    if (
        not context.is_absolute()
        or context.is_symlink()
        or not context.is_dir()
        or context.resolve(strict=True) != context
        or not SHA.fullmatch(trusted_dockerfile_sha256)
        or not SHA.fullmatch(candidate_source_sha256)
        or not re.fullmatch(r"[a-z0-9.-]+(?:/[a-z0-9._-]+)*@sha256:[0-9a-f]{64}", base_image)
        or not re.fullmatch(r"mcpbg-p4-[a-z0-9-]{1,40}:stage", owned_tag)
    ):
        raise P4StageError("native build input identity or private context invalid")
    files = {item.name for item in context.iterdir()}
    if files != {"Dockerfile", "candidate_server.py"}:
        raise P4StageError("candidate build context contains undeclared files")
    total = 0
    for name, expected in (
        ("Dockerfile", trusted_dockerfile_sha256),
        ("candidate_server.py", candidate_source_sha256),
    ):
        path = context / name
        if path.is_symlink() or not path.is_file():
            raise P4StageError("candidate build input is not regular")
        total += path.stat().st_size
        if hash_file(path) != expected:
            raise P4StageError("candidate or trusted Dockerfile changed")
    build = policy.get("limits", {}).get("build", {})
    if type(build.get("context_bytes")) is not int or total > build["context_bytes"]:
        raise P4StageError("candidate context exceeds frozen byte budget")
    return [
        "docker",
        "--host",
        admission.daemon_endpoint,
        "build",
        "--platform",
        "linux/amd64",
        "--pull=false",
        "--no-cache",
        "--network=none",
        "--progress=plain",
        "--build-arg",
        "BASE_IMAGE=" + base_image,
        "--tag",
        owned_tag,
        "--file",
        str(context / "Dockerfile"),
        str(context),
    ]
