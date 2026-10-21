"""Fail-closed whole-worker storage admission for the disposable native P4 daemon.

This is a source admission gate, not a substitute for an authorized physical
write/crash test. All daemon, containerd, BuildKit and transfer writes must be
under ONE measured filesystem; a DockerRootDir check alone is insufficient.
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


class StorageUncertain(RuntimeError):
    """The native worker's complete write boundary has not been proven."""


_COMPONENTS = (
    "containerd_content",
    "containerd_snapshots",
    "containerd_state",
    "buildkit",
    "image_transfer",
    "temporary",
    "daemon_logs",
)


@dataclass(frozen=True)
class WorkerStorageLayout:
    """Trusted-worker supplied *locations*, independently inspected before use."""

    docker_root: Path
    containerd_content: Path
    containerd_snapshots: Path
    containerd_state: Path
    buildkit: Path
    image_transfer: Path
    temporary: Path
    daemon_logs: Path
    backend: str
    daemon_identity: str


def _mount_for(path: Path, mounts: set[str]) -> str | None:
    candidates = [m for m in mounts if str(path) == m or str(path).startswith(m + "/")]
    return max(candidates, key=len) if candidates else None


def _mount_points() -> set[str]:
    """Read actual Linux mount namespace, including same-device bind mounts."""
    try:
        rows = Path("/proc/self/mountinfo").read_text().splitlines()
        mounts = set()
        for row in rows:
            fields = row.split(" ")
            if len(fields) < 6 or " - " not in row:
                raise StorageUncertain("malformed worker mountinfo")
            # Mountinfo encodes whitespace and backslashes as octal escapes.
            mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), fields[4])
            mounts.add(mount)
        return mounts
    except (OSError, UnicodeError) as exc:
        raise StorageUncertain("cannot independently inspect worker mounts") from exc


def verify_worker_storage(
    layout: WorkerStorageLayout,
    *,
    docker_info: dict[str, Any],
    expected_daemon_sha256: str,
) -> dict[str, str | int]:
    """Verify a single at-most-1GiB root and every enumerated writable backend.

    No missing location can be treated as safely inside DockerRootDir. Docker
    config/snapshotter process and write-load proof remain separate conditions.
    """
    if (
        platform.system() != "Linux"
        or platform.machine() not in {"amd64", "x86_64"}
        or type(layout) is not WorkerStorageLayout
        or not isinstance(docker_info, dict)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_daemon_sha256)
        or layout.daemon_identity != expected_daemon_sha256
        or layout.backend not in {"classic-overlay2", "containerd-overlayfs"}
    ):
        raise StorageUncertain("worker platform, backend or daemon identity unsupported")
    root = layout.docker_root
    if not isinstance(root, Path) or not re.fullmatch(
        r"/mnt/mcpbg-p4-[a-z0-9]{1,32}/docker", str(root)
    ):
        raise StorageUncertain("whole-worker root not in dedicated private scope")
    if (
        docker_info.get("DockerRootDir") != str(root)
        or docker_info.get("OSType") != "linux"
        or docker_info.get("Architecture") not in ("x86_64", "amd64")
        or not isinstance(docker_info.get("ID"), str)
        or hashlib.sha256(docker_info["ID"].encode()).hexdigest() != expected_daemon_sha256
    ):
        raise StorageUncertain("whole-worker daemon identity differs")
    paths = [root] + [getattr(layout, key) for key in _COMPONENTS]
    mount_before = _mount_points()
    if str(root) not in mount_before or not os.path.ismount(root):
        raise StorageUncertain("private storage root is not an independent mount")
    unique: set[str] = set()
    for idx, path in enumerate(paths):
        if not isinstance(path, Path) or not path.is_absolute():
            raise StorageUncertain("incomplete writable-backend path inventory")
        name = str(path)
        if name in unique or (idx and not name.startswith(str(root) + "/")):
            raise StorageUncertain("duplicate, escaped or external writable-backend path")
        unique.add(name)
        try:
            if path.is_symlink() or path.resolve(strict=True) != path:
                raise StorageUncertain("aliased worker write path")
            info = path.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                raise StorageUncertain("worker write path not exclusively root-owned")
            if _mount_for(path, mount_before) != str(root):
                raise StorageUncertain("backend write path crosses mount/volume boundary")
        except OSError as exc:
            raise StorageUncertain("worker write path cannot be inspected") from exc
    filesystem = os.statvfs(root)
    capacity = filesystem.f_frsize * filesystem.f_blocks
    if not 0 < capacity <= 1_073_741_824:
        raise StorageUncertain("entire worker write filesystem exceeds 1GiB cap")
    if _mount_points() != mount_before:
        raise StorageUncertain("worker mounts changed during admission")
    material = json.dumps(
        {
            "backend": layout.backend,
            "daemon": expected_daemon_sha256,
            "paths": [str(p) for p in paths],
            "capacity": capacity,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "schema_version": 1,
        "whole_worker_storage_sha256": hashlib.sha256(material).hexdigest(),
        "verified_root": str(root),
        "filesystem_bytes": capacity,
        "backend": layout.backend,
    }
