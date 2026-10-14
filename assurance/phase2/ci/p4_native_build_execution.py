"""Bounded private-Engine build stage. Importing this module has no side effects.

The worker supplies a physically bounded, disposable native daemon. Successful
Docker CLI completion does not attest image transfer, daemon disposal or cleanup.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import p4_staged_pipeline as stage


class P4BuildUnknown(RuntimeError):
    """The worker may have produced an image or retained daemon state."""


@dataclass(frozen=True)
class BuildCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    bytes_seen: int


def bounded_native_command(
    argv: Sequence[str], *, endpoint: str, remaining: float, byte_budget: int
) -> BuildCommandResult:
    """Meter real stdout and stderr and stop the local process group on breach.

    A killed CLI is not evidence that daemon-side build work has stopped.
    """
    if (
        not isinstance(argv, (tuple, list))
        or len(argv) < 4
        or list(argv[:3]) != ["docker", "--host", endpoint]
        or not re.fullmatch(r"unix:///run/mcpbg-p4-[a-z0-9]{1,32}/engine\.sock", endpoint)
        or any(type(x) is not str or not x or "\0" in x for x in argv)
        or not isinstance(remaining, (int, float))
        or not 0 < remaining <= 300
        or type(byte_budget) is not int
        or not 0 < byte_budget <= 1048576
    ):
        raise P4BuildUnknown("invalid private Engine subprocess specification")
    # Do not inherit a DOCKER_HOST, Docker context override, registry credential or
    # user-provided BuildKit settings. The daemon must already hold approved bases.
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/nonexistent",
        "DOCKER_BUILDKIT": "1",
        "DOCKER_CONFIG": "/nonexistent",
        "LANG": "C",
    }
    start = time.monotonic()
    proc: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    complete = False
    seen = 0
    kept: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            env=env,
        )
        assert proc.stdout is not None and proc.stderr is not None
        for label, handle in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            os.set_blocking(handle.fileno(), False)
            selector.register(handle, selectors.EVENT_READ, label)
        while selector.get_map() or proc.poll() is None:
            left = remaining - (time.monotonic() - start)
            if left <= 0:
                raise P4BuildUnknown("private Engine command deadline")
            for key, _ in selector.select(min(left, 0.15)):
                chunk = os.read(key.fd, min(32768, byte_budget - seen + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                seen += len(chunk)
                if seen > byte_budget:
                    raise P4BuildUnknown("private Engine output budget")
                current = kept[key.data]
                if len(current) < 32768:
                    current.extend(chunk[: 32768 - len(current)])
        code = proc.wait(timeout=max(0.01, remaining - (time.monotonic() - start)))
        complete = True
        return BuildCommandResult(code, bytes(kept["stdout"]), bytes(kept["stderr"]), seen)
    except (OSError, subprocess.SubprocessError) as exc:
        raise P4BuildUnknown("private Engine subprocess uncertain") from exc
    finally:
        selector.close()
        if proc is not None:
            if not complete:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2)
            if proc.stdout is not None:
                proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()


class DurableBuildJournal:
    """One private append-only intent record, never reopened for truncation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> DurableBuildJournal:
        parent = self.path.parent
        if (
            parent.is_symlink()
            or not parent.is_dir()
            or parent.stat().st_uid != os.getuid()
            or parent.stat().st_mode & 0o077
            or self.path.is_symlink()
        ):
            raise P4BuildUnknown("build journal is not in private owned state")
        self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(pfd)
        finally:
            os.close(pfd)
        return self

    def append(self, event: str, **details: str | int | bool) -> None:
        if self.fd is None or not re.fullmatch(r"[A-Z_]{3,48}", event):
            raise P4BuildUnknown("build journal not available")
        row = json.dumps({"event": event, **details}, sort_keys=True, separators=(",", ":"))
        if len(row.encode()) > 2048:
            raise P4BuildUnknown("build journal entry oversized")
        try:
            written = os.write(self.fd, (row + "\n").encode())
            if written != len(row.encode()) + 1:
                raise OSError("short journal write")
            os.fsync(self.fd)
        except OSError as exc:
            raise P4BuildUnknown("build journal durability UNKNOWN") from exc

    def __exit__(self, *_args: object) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def prepare_private_build_command(
    *,
    admission: stage.NativeBuildAdmission,
    expected_worker_source: str,
    lease_scope: str,
    data_root: Path,
    docker_info: dict[str, Any],
    context: Path,
    trusted_dockerfile_sha256: str,
    candidate_source_sha256: str,
    base_image: str,
    owned_tag: str,
    policy: dict[str, Any],
) -> list[str]:
    """Do not use user claims in place of a filesystem and daemon admission check."""
    admission.require_bound_stage(
        expected_worker_source=expected_worker_source, lease_scope=lease_scope
    )
    stage.verify_native_data_root(
        daemon_data_root=data_root, docker_info=docker_info, admission=admission
    )
    return stage.plan_private_native_build(
        admission=admission,
        expected_worker_source=expected_worker_source,
        lease_scope=lease_scope,
        context=context,
        trusted_dockerfile_sha256=trusted_dockerfile_sha256,
        candidate_source_sha256=candidate_source_sha256,
        base_image=base_image,
        owned_tag=owned_tag,
        policy=policy,
    )


def run_reviewed_private_build(
    *,
    command: list[str],
    admission: stage.NativeBuildAdmission,
    journal: DurableBuildJournal,
    policy: dict[str, Any],
    deadline: float,
    run: Callable[..., BuildCommandResult] = bounded_native_command,
) -> dict[str, str | bool | int]:
    """Execute only a pre-admitted, preplanned private build.

    The controller must independently verify image identity, transfer and native
    worker destruction before invoking bind_stage_handoff. No success flag here
    implies global cleanup, P3 equivalence or a candidate approval.
    """
    if journal.fd is None or type(deadline) is not float or not deadline > time.monotonic():
        raise P4BuildUnknown("build lease, journal or shared deadline unavailable")
    policy_build = policy.get("limits", {}).get("build", {})
    cap = policy_build.get("log_output_bytes")
    timeout = policy_build.get("timeout_seconds")
    if type(cap) is not int or cap != 1048576 or type(timeout) is not int or timeout != 300:
        raise P4BuildUnknown("build command limits differ from frozen policy")
    # No privileged Buildx sidecar, default builder or endpoint substitution.
    if (
        len(command) < 5
        or command[:3] != ["docker", "--host", admission.daemon_endpoint]
        or command[3:5] != ["build", "--platform"]
        or any("buildx" in arg or "--allow" in arg for arg in command)
        or "--network=none" not in command
        or "--pull=false" not in command
    ):
        raise P4BuildUnknown("build command differs from private reviewed route")
    remaining = min(float(timeout), deadline - time.monotonic())
    if remaining <= 0:
        raise P4BuildUnknown("shared pipeline deadline expired before build")
    journal.append(
        "BUILD_SUBMITTED",
        endpoint_sha256=hashlib.sha256(admission.daemon_endpoint.encode()).hexdigest(),
    )
    try:
        result = run(
            command, endpoint=admission.daemon_endpoint, remaining=remaining, byte_budget=cap
        )
    except BaseException as exc:
        journal.append("BUILD_UNKNOWN")
        raise P4BuildUnknown("daemon-side build completion UNKNOWN") from exc
    if (
        not isinstance(result, BuildCommandResult)
        or type(result.bytes_seen) is not int
        or not 0 <= result.bytes_seen <= cap
        or result.returncode != 0
    ):
        journal.append("BUILD_UNKNOWN")
        raise P4BuildUnknown("build return or output UNKNOWN")
    journal.append("BUILD_CLI_RETURNED", observed_output_bytes=result.bytes_seen)
    return {
        "status": "IMAGE_INSPECTION_AND_WORKER_DISPOSAL_REQUIRED",
        "cli_exit": result.returncode,
        "observed_output_bytes": result.bytes_seen,
        "image_transfer_verified": False,
        "worker_cleanup_verified": False,
        "runtime_enforcement_proven": False,
    }
