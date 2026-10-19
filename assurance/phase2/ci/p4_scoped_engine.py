"""Explicit, fail-closed native Engine endpoint for P4 controller operations.

No daemon is contacted on import or construction. The caller still owns durable
operation intents, resource accounting and replay. This adapter binds all
runtime Docker CLI calls to the *same* private daemon as the build stage.
A CLI exit is not a daemon-side cleanup attestation.
"""

from __future__ import annotations

import hashlib
import re
import stat
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from p4_native_build_execution import BuildCommandResult, bounded_native_command
from p4_trusted_runtime_adapter import CommandResult


class EngineUncertain(RuntimeError):
    """A daemon action might have occurred; readback is required, never retry blindly."""


_ENDPOINT = re.compile(r"unix:///run/mcpbg-p4-[a-z0-9]{1,32}/engine\.sock\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED = frozenset(
    {
        "container",
        "network",
        "volume",
        "image",
        "create",
        "start",
        "stop",
        "rm",
        "exec",
        "cp",
        "inspect",
        "info",
        "pause",
        "unpause",
        "connect",
        "disconnect",
    }
)


@dataclass(frozen=True)
class EngineBinding:
    endpoint: str
    daemon_id_sha256: str
    socket_dev: int
    socket_ino: int

    def __post_init__(self) -> None:
        if (
            type(self.endpoint) is not str
            or not _ENDPOINT.fullmatch(self.endpoint)
            or type(self.daemon_id_sha256) is not str
            or not _SHA256.fullmatch(self.daemon_id_sha256)
            or type(self.socket_dev) is not int
            or type(self.socket_ino) is not int
            or self.socket_dev <= 0
            or self.socket_ino <= 0
        ):
            raise EngineUncertain("incomplete private Engine binding")


def socket_binding(endpoint: str, daemon_id_sha256: str) -> EngineBinding:
    """Capture a real UNIX socket inode under the canonical worker socket path."""
    if not isinstance(endpoint, str) or not _ENDPOINT.fullmatch(endpoint):
        raise EngineUncertain("nonprivate Engine endpoint")
    path = Path(endpoint.removeprefix("unix://"))
    if path.is_symlink() or path.parent.is_symlink() or not path.parent.is_dir():
        raise EngineUncertain("private socket path is aliased")
    if path.parent.resolve(strict=True) != path.parent:
        raise EngineUncertain("private socket directory is aliased")
    try:
        info = path.lstat()
    except OSError as exc:
        raise EngineUncertain("private Engine socket missing") from exc
    if not stat.S_ISSOCK(info.st_mode):
        raise EngineUncertain("Engine endpoint is not a UNIX socket")
    parent_info = path.parent.stat()
    if (
        info.st_uid != 0
        or info.st_mode & 0o077
        or parent_info.st_uid != 0
        or parent_info.st_mode & 0o022
    ):
        raise EngineUncertain("private Engine socket not exclusively owned")
    # Socket ownership and inode checks do not attest the daemon's configuration.
    return EngineBinding(endpoint, daemon_id_sha256, info.st_dev, info.st_ino)


class ScopedEngineRunner:
    """Adapter for OwnedDockerAttempt.run and fixed-control execute.

    The caller supplies the expected admitted daemon ID and socket inode.
    Every read/mutation performs an independent exact-endpoint ID readback.
    All subprocesses share the sanitized bounded native CLI runner. Timeouts,
    unexpected commands, endpoint drift or uncertain post-action readback retain
    UNKNOWN. This adapter cannot itself claim a durable intent was recorded.
    """

    requires_outer_deadline = True

    def __init__(
        self,
        binding: EngineBinding,
        *,
        invoke: Callable[..., BuildCommandResult] = bounded_native_command,
    ) -> None:
        self.binding = binding
        self.invoke = invoke

    def _socket_check(self) -> None:
        path = Path(self.binding.endpoint.removeprefix("unix://"))
        try:
            info = path.lstat()
        except OSError as exc:
            raise EngineUncertain("Engine socket disappeared") from exc
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o077
            or (info.st_dev, info.st_ino) != (self.binding.socket_dev, self.binding.socket_ino)
        ):
            raise EngineUncertain("Engine socket identity changed")

    def _invoke(self, args: Sequence[str], seconds: float, budget: int) -> BuildCommandResult:
        if type(seconds) not in (int, float) or not 0 < seconds <= 300:
            raise EngineUncertain("invalid shared deadline")
        if type(budget) is not int or not 0 < budget <= 1048576:
            raise EngineUncertain("invalid bounded output allowance")
        self._socket_check()
        try:
            result = self.invoke(
                ("docker", "--host", self.binding.endpoint, *args),
                endpoint=self.binding.endpoint,
                remaining=float(seconds),
                byte_budget=budget,
            )
        except BaseException as exc:
            raise EngineUncertain("private Engine CLI outcome UNKNOWN") from exc
        if (
            not isinstance(result, BuildCommandResult)
            or type(result.returncode) is not int
            or type(result.bytes_seen) is not int
            or not 0 <= result.bytes_seen <= budget
            or not isinstance(result.stdout, bytes)
            or not isinstance(result.stderr, bytes)
            or len(result.stdout) + len(result.stderr) > result.bytes_seen
        ):
            raise EngineUncertain("private Engine process result invalid")
        self._socket_check()
        return result

    def _check_daemon(self, remaining: float, budget: int) -> int:
        result = self._invoke(("info", "--format", "{{.ID}}"), min(remaining, 5), budget)
        raw = result.stdout.strip()
        if (
            result.returncode != 0
            or not raw
            or b"\n" in raw
            or hashlib.sha256(raw).hexdigest() != self.binding.daemon_id_sha256
        ):
            raise EngineUncertain("private Engine daemon identity UNKNOWN")
        return result.bytes_seen

    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        output_budget: int,
        retained_per_stream: int,
    ) -> CommandResult:
        if (
            type(argv) not in (tuple, list)
            or len(argv) < 2
            or argv[0] != "docker"
            or argv[1] not in _ALLOWED
            or any(type(part) is not str or not part or "\x00" in part for part in argv)
            or type(timeout) not in (int, float)
            or not 0 < timeout <= 300
            or type(output_budget) is not int
            or not 0 < output_budget <= 1048576
            or type(retained_per_stream) is not int
            or not 0 <= retained_per_stream <= output_budget
        ):
            raise EngineUncertain("invalid scoped Engine command")
        # Control command, role command and archive command must be constructed
        # by trusted reviewed callers, never forwarded from candidate source.
        if any(arg in {"--host", "--context", "--config"} for arg in argv[1:]):
            raise EngineUncertain("Docker endpoint/config override forbidden")
        end = time.monotonic() + timeout
        # Meter the identity readbacks against the SAME aggregate command-output
        # budget and deadline. A post-action readback cannot mint new allowance.
        pre = self._check_daemon(
            max(0.0, end - time.monotonic()), min(4096, max(1, output_budget // 3))
        )
        remaining_bytes = output_budget - pre
        if remaining_bytes < 2:
            raise EngineUncertain("insufficient bound for mutation and readback")
        seconds = end - time.monotonic()
        if seconds <= 0:
            raise EngineUncertain("Engine deadline expired before command")
        result = self._invoke(argv[1:], seconds, remaining_bytes - 1)
        remaining_bytes -= result.bytes_seen
        try:
            seconds = end - time.monotonic()
            if seconds <= 0 or remaining_bytes <= 0:
                raise EngineUncertain("Engine deadline/budget expired after command")
            post = self._check_daemon(seconds, min(4096, remaining_bytes))
        except EngineUncertain as exc:
            raise EngineUncertain("post-command daemon identity UNKNOWN") from exc
        return CommandResult(
            result.returncode,
            result.stdout[:retained_per_stream],
            result.stderr[:retained_per_stream],
            pre + result.bytes_seen + post,
        )
