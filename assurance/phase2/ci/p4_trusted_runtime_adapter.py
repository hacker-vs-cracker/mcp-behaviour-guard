"""P4 trusted-fixture resource adapter, source-only until separately authorized proof.

This is new controller code. It does not inherit historical P3 orchestrator authority,
accept PR-controlled commands, run by import, or publish any GitHub verdict. The
only intended execution subject is a separately approved *fixed* synthetic image.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import p4_resource_enforcement as bounds


class P4AdapterError(RuntimeError):
    """A bounded controller operation was rejected or failed."""


class P4RecoveryRequired(P4AdapterError):
    """An owned remote side effect cannot be independently reconciled."""


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


# The accepted P3 promoted-authority *file bytes*, not reserialized JSON fields.
# This digest changes only through a separate reviewed P3 authority process.
PROMOTED_AUTHORITY_SHA256 = "54ddd04418211add290a597b2e775fb05953d7599b4e78014e57b24b105b6f09"


def approved_fixture_image(authority_raw: bytes, *, role: str, image: str) -> str:
    """Only already promoted fixed fixtures. Never authorize a PR image or tag.

    P3 authority is not an adapter identity: it remains immutable. The caller's
    proposed image is checked against the exact accepted authority file bytes.
    This does not attest that the new adapter has historical P3 provenance.
    """
    if (
        type(authority_raw) is not bytes
        or hashlib.sha256(authority_raw).hexdigest() != PROMOTED_AUTHORITY_SHA256
    ):
        raise P4AdapterError("promoted reference authority bytes differ")
    try:
        authority = json.loads(authority_raw)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise P4AdapterError("invalid promoted authority encoding") from exc
    if (
        not isinstance(authority, dict)
        or authority.get("status") != "PROMOTED"
        or authority.get("consumable") is not True
        or authority.get("platform") != "linux/amd64"
        or authority.get("generation")
        != {
            "number": 1,
            "supersedes": None,
            "renewal_rule": "new-reference-requires-new-reviewed-construction-and-promotion",
        }
        or authority.get("publisher") != {"integration_id": None, "status": "UNBOOTSTRAPPED"}
    ):
        raise P4AdapterError("fixture authority is not approved generation 1")
    runtime = authority.get("runtime")
    images = runtime.get("images") if isinstance(runtime, dict) else None
    if not isinstance(images, dict) or role not in {"fixture", "evaluator"}:
        raise P4AdapterError("unapproved fixed fixture image role")
    approved = images.get(role)
    if (
        not isinstance(approved, str)
        or not isinstance(image, str)
        or image != approved
        or "@" not in image
        or _SHA256.fullmatch(image.split("@", 1)[1]) is None
    ):
        raise P4AdapterError("fixture image differs from promoted authority")
    return approved


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    output_bytes: int


class BoundedProcess:
    """No shell, fixed byte budgets, whole process-group cancellation.

    Completion of a Docker CLI is never treated as proof daemon work has stopped;
    callers must separately inventory/remove owned builder resources.
    """

    def __call__(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        output_budget: int,
        retained_per_stream: int,
    ) -> CommandResult:
        if (
            not argv
            or not all(isinstance(x, str) and x and "\x00" not in x for x in argv)
            or timeout <= 0
            or type(output_budget) is not int
            or type(retained_per_stream) is not int
            or output_budget <= 0
            or retained_per_stream <= 0
        ):
            raise P4AdapterError("invalid bounded process specification")
        started = time.monotonic()
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
        buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        seen = 0
        completed_normally = False
        poller = selectors.DefaultSelector()
        try:
            assert process.stdout is not None and process.stderr is not None
            for key, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                poller.register(stream, selectors.EVENT_READ, key)
            while poller.get_map() or process.poll() is None:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise P4AdapterError("bounded process deadline exceeded")
                events = poller.select(min(remaining, 0.2))
                for handle, _ in events:
                    chunk = os.read(handle.fd, min(65_536, output_budget - seen + 1))
                    if not chunk:
                        poller.unregister(handle.fileobj)
                        continue
                    seen += len(chunk)
                    stream_name = handle.data
                    buffer = buffers[stream_name]
                    if len(buffer) < retained_per_stream:
                        buffer.extend(chunk[: retained_per_stream - len(buffer)])
                    if seen > output_budget:
                        raise P4AdapterError("bounded process output budget exceeded")
            code = process.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
            completed_normally = True
            return CommandResult(code, bytes(buffers["stdout"]), bytes(buffers["stderr"]), seen)
        except (OSError, subprocess.SubprocessError) as exc:
            raise P4AdapterError("bounded process failed") from exc
        finally:
            if not completed_normally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=2)
            poller.close()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


@dataclass
class StreamMeter:
    """Account every chunk before the caller forwards it; no buffering needed."""

    budget: bounds.TrafficBudget
    inflight: bool = False
    request: int = 0
    response: int = 0
    aborted: bool = False

    def begin(self) -> None:
        if self.aborted or self.inflight or self.budget.breached:
            raise P4AdapterError("traffic stream unavailable")
        if self.budget.requests >= self.budget.max_requests:
            self.budget.breached = True
            raise P4AdapterError("traffic request count exceeded")
        self.inflight = True
        self.request = 0
        self.response = 0

    def account(self, chunk: bytes, *, response: bool) -> bytes:
        if not self.inflight or self.aborted or type(chunk) is not bytes:
            raise P4AdapterError("traffic stream invalid")
        n = len(chunk)
        if response:
            self.response += n
            too_large = self.response > self.budget.response_bytes
        else:
            self.request += n
            too_large = self.request > self.budget.request_bytes
        if (
            too_large
            or self.budget.total_bytes + self.request + self.response > self.budget.aggregate_bytes
        ):
            self.aborted = True
            self.budget.breached = True
            raise P4AdapterError("streaming fixture traffic budget exceeded")
        return chunk

    def finish(self) -> None:
        if not self.inflight or self.aborted:
            raise P4AdapterError("traffic stream cannot commit")
        self.budget.record(request_bytes=self.request, response_bytes=self.response)
        self.inflight = False

    def abort(self) -> None:
        self.aborted = True
        self.budget.breached = True
        self.inflight = False


@dataclass
class OwnedItem:
    kind: str
    name: str
    state: str = "INTENT"
    object_id: str | None = None


@dataclass
class OwnedDockerAttempt:
    """One fixed-fixture attempt, reserving slots before Docker side effects.

    Every command uses exact owned names/IDs. Failures where Docker could have
    created a resource retain the intent for reconciliation; cleanup never prunes
    unrelated Docker resources. One shared lease path per execution scope is
    required in addition to a *common* hosted workflow concurrency group.
    """

    policy: dict[str, Any]
    attempt_id: str
    lease_path: Path
    ledger_path: Path
    run: Callable[..., CommandResult] = field(default_factory=BoundedProcess)
    items: list[OwnedItem] = field(default_factory=list)
    attempt_deadline: bounds.AttemptDeadline | None = None
    recovery_required: bool = False
    _lease: bounds.AttemptLease | None = None
    _entered: bool = False
    _cleanup_deadline: float | None = None
    _ledger_fd: int | None = None
    _nonce: str = field(default_factory=lambda: secrets.token_hex(5))

    def _record(self, event: str, item: OwnedItem | None = None) -> None:
        """Write/fsync each intent *before* issuing its daemon operation."""
        if self._ledger_fd is None:
            raise P4AdapterError("owned resource ledger is unavailable")
        data: dict[str, Any] = {
            "event": event,
            "attempt": self.attempt_id,
            "nonce": self._nonce,
            "utc_epoch": int(time.time()),
        }
        if item is not None:
            data.update(
                {
                    "kind": item.kind,
                    "name": item.name,
                    "state": item.state,
                    "object_id": item.object_id,
                }
            )
        raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > 1024:
            raise P4AdapterError("resource ledger entry exceeds budget")
        try:
            if os.write(self._ledger_fd, raw) != len(raw):
                raise OSError("short resource ledger write")
            os.fsync(self._ledger_fd)
        except OSError as exc:
            self.recovery_required = True
            raise P4RecoveryRequired("durable resource ledger write failed") from exc

    def __enter__(self) -> OwnedDockerAttempt:
        if not isinstance(self.attempt_id, str) or not _ATTEMPT.fullmatch(self.attempt_id):
            raise P4AdapterError("attempt ID is not a safe owned resource prefix")
        if self._entered or not isinstance(self.ledger_path, Path):
            raise P4AdapterError("attempt identity or ledger path invalid")
        self._lease = bounds.AttemptLease(self.lease_path, self.policy)
        self._lease.__enter__()
        try:
            # Do not reuse a previous run's ledger or follow a link.
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            self._ledger_fd = os.open(self.ledger_path, flags, 0o600)
            self.attempt_deadline = bounds.AttemptDeadline.from_policy(self.policy)
            self._entered = True
            self._record("ATTEMPT_OPEN")
            return self
        except BaseException:
            if self._ledger_fd is not None:
                os.close(self._ledger_fd)
                self._ledger_fd = None
            self._lease.__exit__(None, None, None)
            self._lease = None
            self._entered = False
            raise

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        try:
            cleanup_window = bounds._limits(self.policy, "execution")["cleanup_timeout_seconds"]
            self._cleanup_deadline = time.monotonic() + float(cleanup_window)
            clean = self.cleanup()
            if not clean:
                self.recovery_required = True
            self._record(
                "FINISH_CLEAN" if clean and not self.recovery_required else "FINISH_UNKNOWN"
            )
        finally:
            if self._ledger_fd is not None:
                os.close(self._ledger_fd)
                self._ledger_fd = None
            if self._lease is not None:
                self._lease.__exit__(None, None, None)
            self._entered = False
            self._cleanup_deadline = None
        if _kind is None and self.recovery_required:
            raise P4RecoveryRequired("owned cleanup is UNKNOWN; retain ledger and recover")

    def _checked_call(
        self, argv: Sequence[str], *, build: bool = False, cleanup: bool = False
    ) -> CommandResult:
        if not self._entered:
            raise P4AdapterError("attempt lease must be active")
        if cleanup:
            if self._cleanup_deadline is None:
                raise P4AdapterError("cleanup deadline unavailable")
            timeout = self._cleanup_deadline - time.monotonic()
            if timeout <= 0:
                raise P4AdapterError("shared cleanup deadline exceeded")
        else:
            if self.attempt_deadline is None:
                raise P4AdapterError("attempt deadline missing")
            remaining = self.attempt_deadline.remaining()
            limit = (
                bounds.build_command_limits(self.policy)
                if build
                else bounds.subprocess_limits(self.policy)
            )
            timeout = min(float(limit["timeout_seconds"]), remaining)
        cap = (
            bounds.build_command_limits(self.policy)["output_budget_bytes"]
            if build
            else bounds.subprocess_limits(self.policy)["output_budget_bytes"]
        )
        retained = min(131_072, cap)
        try:
            return self.run(argv, timeout=timeout, output_budget=cap, retained_per_stream=retained)
        except Exception as exc:
            # A transport failure cannot prove that a daemon side effect did not occur.
            if argv[:2] == ["docker", "create"] or (
                len(argv) > 2
                and argv[1:3]
                in (
                    ["network", "create"],
                    ["volume", "create"],
                    ["buildx", "create"],
                    ["buildx", "build"],
                )
            ):
                self.recovery_required = True
            raise P4AdapterError("owned command uncertain or failed") from exc

    def _reserve(self, kind: str) -> OwnedItem:
        if not self._entered:
            raise P4AdapterError("attempt lease must be active before reservation")
        if kind not in {"container", "network", "volume"}:
            raise P4AdapterError("unsupported owned resource kind")
        limits = bounds.OwnedResourceBudget.from_policy(self.policy)
        allowed = {
            "container": limits.max_containers,
            "network": limits.max_networks,
            "volume": limits.max_volumes,
        }
        used = sum(x.kind == kind for x in self.items)
        if used >= allowed[kind]:
            raise P4AdapterError("owned resource slot budget exceeded")
        name = f"mcpbg-p4-{self.attempt_id}-{self._nonce}-{kind}-{sum(x.kind == kind for x in self.items) + 1}"
        item = OwnedItem(kind=kind, name=name)
        self._record("RESERVED", item)
        self.items.append(item)
        return item

    def create_network(self) -> OwnedItem:
        item = self._reserve("network")
        item.state = "REQUESTED"
        self._record("CREATE_REQUESTED", item)
        res = self._checked_call(
            [
                "docker",
                "network",
                "create",
                "--internal",
                "--label",
                "mcpbg.p4.owner=" + self.attempt_id,
                item.name,
            ]
        )
        if res.exit_code != 0:
            self.recovery_required = True
            raise P4RecoveryRequired("network creation requires owned inventory reconciliation")
        item.object_id = res.stdout.decode("ascii", errors="ignore").strip()
        item.state = "CREATED"
        self._record("CREATE_CONFIRMED", item)
        return item

    def create_volume(self) -> OwnedItem:
        item = self._reserve("volume")
        item.state = "REQUESTED"
        self._record("CREATE_REQUESTED", item)
        res = self._checked_call(
            [
                "docker",
                "volume",
                "create",
                "--label",
                "mcpbg.p4.owner=" + self.attempt_id,
                item.name,
            ]
        )
        if res.exit_code != 0:
            self.recovery_required = True
            raise P4RecoveryRequired("volume creation requires owned inventory reconciliation")
        item.object_id = res.stdout.decode("ascii", errors="ignore").strip()
        item.state = "CREATED"
        self._record("CREATE_CONFIRMED", item)
        return item

    def create_fixed_container(self, image: str, authority_raw: bytes, *, role: str) -> OwnedItem:
        approved_fixture_image(authority_raw, role=role, image=image)
        item = self._reserve("container")
        item.state = "REQUESTED"
        self._record("CREATE_REQUESTED", item)
        args = bounds.docker_resource_args(self.policy)
        artifacts = bounds._limits(self.policy, "artifacts")
        # Container writes have an OS-backed tmpfs ceiling before post-run tree checks.
        tmpfs = f"/trusted-output:rw,noexec,nosuid,size={artifacts['total_bytes']}"
        cmd = [
            "docker",
            "create",
            "--platform",
            "linux/amd64",
            "--name",
            item.name,
            "--network",
            "none",
            "--label",
            "mcpbg.p4.owner=" + self.attempt_id,
            *args,
            "--tmpfs",
            tmpfs,
            image,
        ]
        res = self._checked_call(cmd)
        if res.exit_code != 0:
            self.recovery_required = True
            raise P4RecoveryRequired("container creation requires owned inventory reconciliation")
        identity = res.stdout.decode("ascii", errors="ignore").strip()
        if not re.fullmatch(r"[a-f0-9]{64}", identity):
            self.recovery_required = True
            raise P4RecoveryRequired("container ID could not be verified")
        item.object_id = identity
        item.state = "CREATED"
        self._record("CREATE_CONFIRMED", item)
        return item

    # BuildKit execution is deferred until its image is pinned by digest and its
    # extra daemon container, cache volume, loaded image and cleanup are owned.
    # Do not fall back to Docker's shared default builder or a global prune.

    def _owned_before_delete(self, item: OwnedItem) -> bool | None:
        """Return True for exact owner, False for proven absence, None for UNKNOWN."""
        if item.kind == "container":
            argv = [
                "docker",
                "container",
                "inspect",
                "--format",
                '{{index .Config.Labels "mcpbg.p4.owner"}}',
                item.name,
            ]
        elif item.kind == "network":
            argv = [
                "docker",
                "network",
                "inspect",
                "--format",
                '{{index .Labels "mcpbg.p4.owner"}}',
                item.name,
            ]
        elif item.kind == "volume":
            argv = [
                "docker",
                "volume",
                "inspect",
                "--format",
                '{{index .Labels "mcpbg.p4.owner"}}',
                item.name,
            ]
        else:
            raise P4AdapterError("unsupported resource type")
        result = self._checked_call(argv, cleanup=True)
        if result.exit_code == 1 and any(
            token in result.stderr.lower()
            for token in (b"no such object", b"no such network", b"no such volume", b"no builder")
        ):
            return False
        if result.exit_code != 0:
            return None
        if result.stdout.strip() == self.attempt_id.encode("ascii"):
            return True
        return None

    def cleanup(self) -> bool:
        """Remove only exact owned objects, verify absence and never infer clean from errors."""
        if not self._entered or self._cleanup_deadline is None:
            return False
        clean = True
        for item in reversed(self.items):
            if item.state == "INTENT":
                item.state = "NEVER_SUBMITTED"
                self._record("NOT_SUBMITTED", item)
                continue
            if item.kind == "container":
                delete = ["docker", "rm", "-f", item.name]
            elif item.kind == "network":
                delete = ["docker", "network", "rm", item.name]
            elif item.kind == "volume":
                delete = ["docker", "volume", "rm", item.name]
            else:
                item.state = "UNKNOWN"
                clean = False
                continue
            try:
                exists = self._owned_before_delete(item)
                if exists is True:
                    deleted = self._checked_call(delete, cleanup=True)
                    if deleted.exit_code != 0:
                        raise P4AdapterError("owned removal failed")
                    exists = self._owned_before_delete(item)
                if exists is False:
                    item.state = "ABSENT"
                    self._record("ABSENCE_VERIFIED", item)
                else:
                    item.state = "UNKNOWN"
                    self._record("CLEANUP_UNKNOWN", item)
                    clean = False
            except Exception:
                item.state = "UNKNOWN"
                clean = False
                with contextlib.suppress(P4RecoveryRequired):
                    self._record("CLEANUP_UNKNOWN", item)
        if not clean:
            self.recovery_required = True
        return clean

    def cleanup_result(self) -> dict[str, Any]:
        verified_absent = all(item.state in {"ABSENT", "NEVER_SUBMITTED"} for item in self.items)
        if self.recovery_required or not verified_absent:
            return {"outcome": "UNKNOWN", "recovery_required": True}
        return {"outcome": "CLEAN", "recovery_required": False}


def adapter_binding(module_path: Path, trust: dict[str, Any]) -> dict[str, Any]:
    """Reviewable source binding, separate from P3 generation-1 provenance."""
    expected = {
        "status": "SOURCE_WIRED_NOT_RUNTIME_PROVEN",
        "stage": "TRUSTED_NON_HOSTILE_FIXTURE_ADAPTER",
        "module_path": "assurance/phase2/ci/p4_trusted_runtime_adapter.py",
        "module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
        "candidate_execution_enabled": False,
        "hostile_execution_authorized": False,
        "runtime_enforcement_proven": False,
        "verdict_publication_enabled": False,
    }
    if trust.get("p4_trusted_runtime_adapter") != expected:
        raise P4AdapterError("trusted runtime adapter module binding mismatch")
    return expected
