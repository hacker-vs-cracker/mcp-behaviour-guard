"""P4 trusted-fixture resource adapter, source-only until separately authorized proof.

This is new controller code. It does not inherit historical P3 orchestrator authority,
accept PR-controlled commands, run by import, or publish any GitHub verdict. The
only intended execution subject is a separately approved *fixed* synthetic image.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import secrets
import selectors
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Sequence
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

    def forward(self, chunk: bytes, *, response: bool, sink: Callable[[bytes], int]) -> None:
        """Account the chunk *before* sending it to the trusted fixture transport.

        This is a source-only transport seam, not an installed proxy. If the
        output writer fails or writes partially, the stream becomes unusable;
        already forwarded earlier chunks cannot be rolled back.
        """
        try:
            self.account(chunk, response=response)
            written = sink(chunk)
            if type(written) is not int or written != len(chunk):
                raise P4AdapterError("fixture transport incomplete write")
        except BaseException:
            self.abort()
            raise


def receive_bounded_artifact_archive(
    chunks: Iterable[bytes],
    destination: Path,
    policy: dict[str, Any],
    *,
    deadline: float,
) -> dict[str, int | str]:
    """Bound a streamed archive and atomically validate it before publication.

    `chunks` must come from an independently deadline-fenced transport which
    terminates owned processes if blocked on the next chunk. This function
    cannot itself interrupt a blocking iterator or prove the bytes came from
    Docker. It must not be used as P4 runtime proof without that binding.

    The parent is required to be a private, user-owned directory. Never
    expose partial output; never overwrite a previously published result.
    """
    if not isinstance(destination, Path) or destination.name in ("", ".", ".."):
        raise P4AdapterError("artifact destination must be a new named path")
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise P4AdapterError("artifact destination parent is not a real directory")
    state = parent.stat()
    if state.st_uid != os.getuid() or state.st_mode & 0o077:
        raise P4AdapterError("artifact destination parent must be owned and private")
    if destination.exists() or destination.is_symlink():
        raise P4AdapterError("artifact destination already exists")
    if type(deadline) is not float or not math.isfinite(deadline):
        raise P4AdapterError("artifact deadline invalid")
    archive = bounds._mapping(policy.get("archive_extraction"), "archive_extraction")
    ceiling = bounds._positive_int(archive.get("compressed_bytes"), "archive.compressed_bytes")
    if time.monotonic() >= deadline:
        raise P4AdapterError("artifact intake deadline exceeded")
    total = 0
    count = 0
    digest = hashlib.sha256()
    try:
        with tempfile.TemporaryDirectory(prefix=".p4_artifact_", dir=parent) as temp:
            owned = Path(temp)
            spool = owned / "archive.bin"
            with spool.open("xb") as sink:
                for chunk in chunks:
                    if time.monotonic() >= deadline:
                        raise P4AdapterError("artifact intake deadline exceeded")
                    if type(chunk) is not bytes or not chunk or len(chunk) > 65_536:
                        raise P4AdapterError("artifact intake chunk invalid")
                    count += 1
                    if count > 65_536 or total + len(chunk) > ceiling:
                        raise P4AdapterError("artifact intake byte/chunk budget exceeded")
                    sink.write(chunk)
                    total += len(chunk)
                    digest.update(chunk)
                sink.flush()
                os.fsync(sink.fileno())
            if total == 0 or time.monotonic() >= deadline:
                raise P4AdapterError("artifact intake incomplete or expired")
            staged = owned / "unpacked"
            result = bounds.safe_extract_archive(spool, staged, policy)
            if time.monotonic() >= deadline:
                raise P4AdapterError("artifact intake deadline exceeded")
            if destination.exists() or destination.is_symlink():
                raise P4AdapterError("artifact destination appeared during validation")
            # Publication is limited to a private parent controlled by this
            # attempt. The caller must also hold its shared writer lease.
            # Durably flush validated extracted files and directories before rename.
            for directory, _subdirs, files in os.walk(staged):
                for filename in files:
                    if time.monotonic() >= deadline:
                        raise P4AdapterError("artifact fsync deadline exceeded")
                    fd = os.open(Path(directory) / filename, os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            for directory, _subdirs, _files in os.walk(staged, topdown=False):
                fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            staged.rename(destination)
            parent_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            return {
                "files": result["files"],
                "bytes": result["bytes"],
                "archive_bytes": total,
                "archive_sha256": digest.hexdigest(),
            }
    except (OSError, bounds.P4ResourceEnforcementError) as exc:
        raise P4AdapterError("artifact archive intake invalid") from exc


def _bounded_archive_process(
    argv: Sequence[str], *, deadline: float, byte_limit: int, stderr_limit: int = 131_072
) -> Iterable[bytes]:
    """Bound the *actual subprocess pipes*; never rely on a blocking input iterator.

    This runs only when explicitly invoked, and does not execute on import. The
    caller owns and verifies the source container; a nonzero exit rejects the
    archive even when the bytes appear syntactically valid.
    """
    if (
        not argv
        or not all(type(x) is str and x and "\x00" not in x for x in argv)
        or type(deadline) is not float
        or not math.isfinite(deadline)
        or type(byte_limit) is not int
        or not 0 < byte_limit <= 16_777_216
        or type(stderr_limit) is not int
        or not 0 < stderr_limit <= 131_072
        or time.monotonic() >= deadline
    ):
        raise P4AdapterError("bounded artifact subprocess invalid")
    process: subprocess.Popen[bytes] | None = None
    poller = selectors.DefaultSelector()
    succeeded = False
    stdout_bytes = 0
    stderr_bytes = 0
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
        assert process.stdout is not None and process.stderr is not None
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            poller.register(stream, selectors.EVENT_READ, name)
        while poller.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise P4AdapterError("artifact export process deadline exceeded")
            for key, _ in poller.select(min(0.2, remaining)):
                if key.data == "stdout":
                    chunk = os.read(key.fd, min(65_536, byte_limit - stdout_bytes + 1))
                else:
                    chunk = os.read(key.fd, min(65_536, stderr_limit - stderr_bytes + 1))
                if not chunk:
                    poller.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    stderr_bytes += len(chunk)
                    if stderr_bytes > stderr_limit:
                        raise P4AdapterError("artifact export stderr budget exceeded")
                else:
                    stdout_bytes += len(chunk)
                    if stdout_bytes > byte_limit:
                        raise P4AdapterError("artifact export bytes exceeded")
                    yield chunk
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise P4AdapterError("artifact export CLI failed")
        if stdout_bytes == 0:
            raise P4AdapterError("artifact export CLI produced no archive")
        succeeded = True
    except (OSError, subprocess.SubprocessError) as exc:
        raise P4AdapterError("artifact export pipe failed or expired") from exc
    finally:
        poller.close()
        if process is not None:
            if not succeeded:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=2)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


@dataclass
class OwnedItem:
    kind: str
    name: str
    state: str = "INTENT"
    object_id: str | None = None
    prestart_attested: bool = False
    artifact_tmpfs_attested: bool = False
    artifact_owner_uid: int = 10001
    planned_mounts: dict[str, str] | None = None
    mounted_attested: bool = False


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
    command_output_bytes: int = 0
    build_output_bytes: int = 0
    cleanup_output_bytes: int = 0
    command_output_unknown: bool = False
    build_output_unknown: bool = False
    cleanup_output_unknown: bool = False

    def _record(self, event: str, item: OwnedItem | None = None) -> None:
        """Write/fsync each intent *before* issuing its daemon operation."""
        if self._ledger_fd is None:
            raise P4AdapterError("owned resource ledger is unavailable")
        data: dict[str, Any] = {
            "event": event,
            "attempt": self.attempt_id,
            "nonce": self._nonce,
            "lease_scope_sha256": hashlib.sha256(
                str(self.lease_path.absolute()).encode("utf-8")
            ).hexdigest(),
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

    def _assert_previous_attempts_closed(self) -> None:
        """Fail closed on unresolved local scope records before any new daemon call.

        This is a shared-inode/local durability gate, NOT a cross-runner lease or
        proof of Docker absence. UNKNOWN requires external inventory reconciliation.
        """
        directory = self.ledger_path.parent
        scope = hashlib.sha256(str(self.lease_path.absolute()).encode("utf-8")).hexdigest()
        try:
            names = sorted(directory.glob("owned-*.jsonl"))
            if len(names) > 64:
                raise P4RecoveryRequired("prior owned ledger inventory exceeds budget")
            for previous in names:
                if previous == self.ledger_path:
                    raise P4RecoveryRequired("prior owned ledger path reused")
                if previous.is_symlink() or not previous.is_file():
                    raise P4RecoveryRequired("prior owned ledger not regular")
                if previous.stat().st_size > 131_072:
                    raise P4RecoveryRequired("prior owned ledger exceeds byte budget")
                raw = previous.read_bytes()
                if not raw or not raw.endswith(b"\n") or len(raw.splitlines()) > 128:
                    raise P4RecoveryRequired("prior owned ledger incomplete")
                events: list[dict[str, Any]] = []
                for line in raw.splitlines():
                    if len(line) > 1024:
                        raise P4RecoveryRequired("prior owned ledger entry exceeds budget")
                    try:
                        value = json.loads(
                            line,
                            object_pairs_hook=bounds._reject_duplicate_pairs,
                            parse_constant=bounds._reject_constant,
                        )
                    except (ValueError, UnicodeError, bounds.P4ResourceEnforcementError) as exc:
                        raise P4RecoveryRequired("prior owned ledger malformed") from exc
                    if not isinstance(value, dict) or not isinstance(value.get("event"), str):
                        raise P4RecoveryRequired("prior owned ledger event malformed")
                    events.append(value)
                scopes: list[str] = []
                identities: list[tuple[str, str]] = []
                for event in events:
                    prior_scope = event.get("lease_scope_sha256")
                    prior_attempt = event.get("attempt")
                    prior_nonce = event.get("nonce")
                    if not isinstance(prior_scope, str) or not re.fullmatch(
                        r"[0-9a-f]{64}", prior_scope
                    ):
                        raise P4RecoveryRequired("prior owned ledger scope malformed")
                    if (
                        not isinstance(prior_attempt, str)
                        or not prior_attempt
                        or not isinstance(prior_nonce, str)
                        or not prior_nonce
                    ):
                        raise P4RecoveryRequired("prior ledger has inconsistent attempt identity")
                    scopes.append(prior_scope)
                    identities.append((prior_attempt, prior_nonce))
                if len(set(identities)) != 1:
                    raise P4RecoveryRequired("prior ledger has inconsistent attempt identity")
                if len(set(scopes)) != 1:
                    raise P4RecoveryRequired("prior owned ledger scope malformed")
                if scope not in scopes:
                    continue  # Distinct lock path, not the same execution scope.
                if (
                    events[0].get("event") != "ATTEMPT_OPEN"
                    or events[-1].get("event") != "FINISH_CLEAN"
                ):
                    raise P4RecoveryRequired("prior attempt unresolved; cleanup inventory required")
                pending: dict[str, tuple[str, str]] = {}
                export_pending = False
                export_finished = False
                for event in events[1:-1]:
                    name = event.get("name")
                    kind = event.get("kind")
                    state = event.get("event")
                    if (
                        not isinstance(name, str)
                        or not isinstance(kind, str)
                        or kind not in {"container", "network", "volume"}
                    ):
                        raise P4RecoveryRequired("prior owned ledger resource malformed")
                    if state == "ARTIFACT_EXPORT_BEGIN":
                        if (
                            kind != "container"
                            or pending.get(name) != (kind, "CREATED")
                            or export_pending
                        ):
                            raise P4RecoveryRequired("prior export start inconsistent")
                        export_pending = True
                        continue
                    if state == "ARTIFACT_EXPORT_COMPLETE":
                        if kind != "container" or not export_pending or export_finished:
                            raise P4RecoveryRequired("prior export completion inconsistent")
                        export_finished = True
                        continue
                    if state == "RESERVED":
                        if name in pending:
                            raise P4RecoveryRequired("duplicate owned ledger resource")
                        pending[name] = (kind, "RESERVED")
                    elif state == "CREATE_REQUESTED" and pending.get(name) == (kind, "RESERVED"):
                        pending[name] = (kind, "REQUESTED")
                    elif state == "CREATE_CONFIRMED" and pending.get(name) == (kind, "REQUESTED"):
                        pending[name] = (kind, "CREATED")
                    elif state == "NOT_SUBMITTED" and pending.get(name) == (kind, "RESERVED"):
                        pending[name] = (kind, "NEVER_SUBMITTED")
                    elif state == "ABSENCE_VERIFIED" and pending.get(name) in {
                        (kind, "REQUESTED"),
                        (kind, "CREATED"),
                    }:
                        pending[name] = (kind, "ABSENT")
                    else:
                        raise P4RecoveryRequired("inconsistent prior owned ledger transition")
                if export_pending and not export_finished:
                    raise P4RecoveryRequired("prior artifact export unresolved")
                if any(
                    status not in {"ABSENT", "NEVER_SUBMITTED"} for _, status in pending.values()
                ):
                    raise P4RecoveryRequired("prior owned resources not verified absent")
        except P4RecoveryRequired:
            self.recovery_required = True
            raise
        except (OSError, RecursionError) as exc:
            self.recovery_required = True
            raise P4RecoveryRequired("cannot verify previous attempt ledgers") from exc

    def __enter__(self) -> OwnedDockerAttempt:
        if not isinstance(self.attempt_id, str) or not _ATTEMPT.fullmatch(self.attempt_id):
            raise P4AdapterError("attempt ID is not a safe owned resource prefix")
        if self._entered or not isinstance(self.ledger_path, Path):
            raise P4AdapterError("attempt identity or ledger path invalid")
        self._lease = bounds.AttemptLease(self.lease_path, self.policy)
        self._lease.__enter__()
        try:
            if not re.fullmatch(r"owned-[a-zA-Z0-9._-]+\.jsonl", self.ledger_path.name):
                raise P4AdapterError("ledger name must use owned-*.jsonl")
            if self.lease_path.parent.absolute() != self.ledger_path.parent.absolute():
                raise P4AdapterError("ledger and lease scope directories differ")
            self._assert_previous_attempts_closed()
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
        if cleanup and build:
            raise P4AdapterError("build cannot use the cleanup output reserve")
        subprocess_policy = bounds.subprocess_limits(self.policy)
        if cleanup:
            if self._cleanup_deadline is None:
                raise P4AdapterError("cleanup deadline unavailable")
            timeout = self._cleanup_deadline - time.monotonic()
            if timeout <= 0:
                raise P4AdapterError("shared cleanup deadline exceeded")
            cap = subprocess_policy["output_budget_bytes"]
            spent = self.cleanup_output_bytes
            uncertain = self.cleanup_output_unknown
        else:
            if self.attempt_deadline is None:
                raise P4AdapterError("attempt deadline missing")
            remaining_time = self.attempt_deadline.remaining()
            limits = bounds.build_command_limits(self.policy) if build else subprocess_policy
            timeout = min(float(limits["timeout_seconds"]), remaining_time)
            cap = limits["output_budget_bytes"]
            spent = self.build_output_bytes if build else self.command_output_bytes
            uncertain = self.build_output_unknown if build else self.command_output_unknown
        if uncertain or cap - spent <= 0:
            self.recovery_required = True
            raise P4AdapterError("attempt aggregate subprocess output budget exhausted")
        allowance = cap - spent
        retained = min(subprocess_policy["capture_limit_bytes"], allowance)
        try:
            result = self.run(
                argv,
                timeout=timeout,
                output_budget=allowance,
                retained_per_stream=retained,
            )
            if (
                not isinstance(result, CommandResult)
                or type(result.output_bytes) is not int
                or not 0 <= result.output_bytes <= allowance
                or type(result.stdout) is not bytes
                or type(result.stderr) is not bytes
                or len(result.stdout) + len(result.stderr) > result.output_bytes
            ):
                raise P4AdapterError("bounded process returned invalid byte accounting")
            if cleanup:
                self.cleanup_output_bytes += result.output_bytes
            elif build:
                self.build_output_bytes += result.output_bytes
            else:
                self.command_output_bytes += result.output_bytes
            return result
        except Exception as exc:
            # When the subprocess fails, captured bytes might be unknown. Never
            # assume another subprocess can spend the unaccounted remainder.
            if cleanup:
                self.cleanup_output_unknown = True
            elif build:
                self.build_output_unknown = True
            else:
                self.command_output_unknown = True
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
        identity = res.stdout.decode("ascii", errors="ignore").strip()
        if re.fullmatch(r"[a-f0-9]{64}", identity) is None:
            self.recovery_required = True
            raise P4RecoveryRequired("network identity could not be verified")
        item.object_id = identity
        item.state = "CREATED"
        self._record("CREATE_CONFIRMED", item)
        return item

    def _require_new_volume_name(self, item: OwnedItem) -> None:
        """Never adopt an old Docker volume: create silently reuses existing names.

        Absence is a required precondition, not proof against a concurrent
        daemon-side replacement. Keep the lease and separately verify options,
        owner and mounts after creation. Ambiguous daemon results stay UNKNOWN.
        """
        if (
            not self._entered
            or item.kind != "volume"
            or item.state != "INTENT"
            or not any(owned is item for owned in self.items)
        ):
            raise P4AdapterError("unreserved volume pre-create inventory")
        try:
            result = self._checked_call(
                ["docker", "volume", "inspect", "--format", "{{.Name}}", item.name]
            )
            if (
                result.exit_code != 1
                or result.stdout
                or not any(
                    marker in result.stderr.lower()
                    for marker in (b"no such volume", b"no such object")
                )
            ):
                raise P4AdapterError("volume may already exist or inventory is ambiguous")
        except Exception as exc:
            self.recovery_required = True
            raise P4RecoveryRequired("new owned volume name not independently absent") from exc

    def create_volume(self) -> OwnedItem:
        item = self._reserve("volume")
        self._require_new_volume_name(item)
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
        if res.exit_code != 0 or res.stdout.strip() != item.name.encode("ascii"):
            self.recovery_required = True
            raise P4RecoveryRequired("volume creation requires owned inventory reconciliation")
        item.object_id = item.name
        item.state = "CREATED"
        self._record("CREATE_CONFIRMED", item)
        return item

    def create_bounded_artifact_volume(self, *, role: str = "fixture") -> OwnedItem:
        """Request one attempt-owned Linux local-driver tmpfs volume, source-only.

        A volume is not trusted merely because `docker volume create` returned a
        name. Inspect its *effective* driver, options, owner and exact name before
        passing it to a future candidate or read-only exporter. No global prune.
        The physical mounted filesystem and writer fence need separate proof.
        """
        if type(role) is not str or role not in {"fixture", "evaluator"}:
            raise P4AdapterError("unapproved owned volume role")
        owner_uid = 10001 if role == "fixture" else 10003
        item = self._reserve("volume")
        item.artifact_owner_uid = owner_uid
        self._require_new_volume_name(item)
        item.state = "REQUESTED"
        self._record("CREATE_REQUESTED", item)
        artifact_bytes = bounds._positive_int(
            bounds._limits(self.policy, "artifacts").get("total_bytes"),
            "artifacts.total_bytes",
        )
        options = (
            f"size={artifact_bytes},uid={owner_uid},gid={owner_uid},mode=0770,noexec,nosuid,nodev"
        )
        command = [
            "docker",
            "volume",
            "create",
            "--driver",
            "local",
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            f"o={options}",
            "--label",
            "mcpbg.p4.owner=" + self.attempt_id,
            item.name,
        ]
        result = self._checked_call(command)
        if result.exit_code != 0 or result.stdout.strip() != item.name.encode("ascii"):
            self.recovery_required = True
            raise P4RecoveryRequired("artifact volume creation UNKNOWN")
        item.object_id = item.name
        item.state = "CREATED"
        self._record("CREATE_CONFIRMED", item)
        try:
            inspection = self._checked_call(
                ["docker", "volume", "inspect", "--format", "{{json .}}", item.name]
            )
            if inspection.exit_code != 0:
                raise P4AdapterError("artifact volume inspect failed")
            json_rules = bounds._mapping(self.policy.get("json_intake"), "json_intake")
            decoded = bounds._load_object_bytes(
                inspection.stdout,
                max_bytes=bounds._positive_int(json_rules.get("max_bytes"), "json.max_bytes"),
                label="artifact volume inspection",
                shape=json_rules,
            )
            bounds._validate_json_shape(decoded, json_rules)
            if (
                decoded.get("Name") != item.name
                or decoded.get("Driver") != "local"
                or decoded.get("Options") != {"type": "tmpfs", "device": "tmpfs", "o": options}
                or not isinstance(decoded.get("Labels"), dict)
                or decoded["Labels"].get("mcpbg.p4.owner") != self.attempt_id
            ):
                raise P4AdapterError("effective artifact volume identity/options mismatch")
            item.artifact_tmpfs_attested = True
            return item
        except Exception as exc:
            self.recovery_required = True
            raise P4RecoveryRequired("artifact volume verification UNKNOWN") from exc

    def plan_owned_image_mounts(
        self,
        image: str,
        authority_raw: bytes,
        *,
        role: str,
        bindings: dict[str, OwnedItem],
    ) -> list[str]:
        """Bind *all* image-declared volumes to previously attested owned volumes.

        This is a read-only daemon inventory and argument planner, NOT permission
        to create or run a container. A fixture declares /state; Docker otherwise
        creates an unmanaged anonymous volume. No implicit volume is allowed.
        """
        if not self._entered:
            raise P4AdapterError("attempt lease required for mount inventory")
        approved_fixture_image(authority_raw, role=role, image=image)
        if type(bindings) is not dict:
            raise P4AdapterError("owned volume bindings must be an exact mapping")
        try:
            inspection = self._checked_call(
                ["docker", "image", "inspect", "--format", "{{json .}}", image]
            )
            if inspection.exit_code != 0:
                raise P4AdapterError("immutable image inventory failed")
            json_rules = bounds._mapping(self.policy.get("json_intake"), "json_intake")
            decoded = bounds._load_object_bytes(
                inspection.stdout,
                max_bytes=bounds._positive_int(json_rules.get("max_bytes"), "json.max_bytes"),
                label="immutable image inventory",
                shape=json_rules,
            )
            bounds._validate_json_shape(decoded, json_rules)
            config = decoded.get("Config")
            digests = decoded.get("RepoDigests")
            if (
                not isinstance(config, dict)
                or not isinstance(digests, list)
                or image not in digests
            ):
                raise P4AdapterError("immutable image manifest identity unverified")
            declared = config.get("Volumes")
            if declared is None:
                declared = {}
            if not isinstance(declared, dict) or not all(
                isinstance(path, str) and value == {} for path, value in declared.items()
            ):
                raise P4AdapterError("untrusted image-declared volume inventory")
            expected_declarations = {"/state"} if role == "fixture" else set()
            if set(declared) != expected_declarations:
                raise P4AdapterError("unexpected image-declared anonymous volume")
            required = expected_declarations | {"/trusted-output"}
            if set(bindings) != required:
                raise P4AdapterError("every image volume must be explicitly owned")
            names: set[str] = set()
            flags: list[str] = []
            for destination in sorted(required):
                item = bindings[destination]
                if (
                    not isinstance(item, OwnedItem)
                    or not any(existing is item for existing in self.items)
                    or item.kind != "volume"
                    or item.state != "CREATED"
                    or not item.artifact_tmpfs_attested
                    or item.artifact_owner_uid != (10001 if role == "fixture" else 10003)
                    or item.object_id != item.name
                    or item.name in names
                ):
                    raise P4AdapterError("volume binding not attested or owned")
                names.add(item.name)
                flags.extend(
                    ["--mount", f"type=volume,src={item.name},dst={destination},volume-nocopy"]
                )
            return flags
        except (OSError, ValueError, TypeError, bounds.P4ResourceEnforcementError) as exc:
            self.recovery_required = True
            raise P4RecoveryRequired("image mount inventory UNKNOWN") from exc

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
            "--memory-swap",
            str(bounds._limits(self.policy, "docker_runtime")["memory_bytes"]),
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

    def create_mounted_fixed_container(
        self,
        image: str,
        authority_raw: bytes,
        *,
        role: str,
        bindings: dict[str, OwnedItem],
    ) -> OwnedItem:
        """Create a nonexecuting container with *every* declared volume accounted for.

        Unlike the historical, source-only create_fixed_container() test seam,
        this path consumes V11's attested mount plan before any create intent.
        It never starts a container, and is not yet a runtime-proof capability.
        """
        flags = self.plan_owned_image_mounts(image, authority_raw, role=role, bindings=bindings)
        # The plan itself only returns arguments; it cannot create resources.
        # Recheck the same OwnedItem object identities immediately before commit.
        expected_paths = {"/state", "/trusted-output"} if role == "fixture" else {"/trusted-output"}
        if set(bindings) != expected_paths or len(flags) != 2 * len(bindings):
            raise P4AdapterError("owned mount plan changed before create")
        for item in bindings.values():
            if (
                not any(item is owned for owned in self.items)
                or item.kind != "volume"
                or item.state != "CREATED"
                or not item.artifact_tmpfs_attested
                or item.artifact_owner_uid != (10001 if role == "fixture" else 10003)
                or item.object_id != item.name
            ):
                raise P4AdapterError(
                    "owned mount identity changed before create: volume ownership mismatch"
                )
        # Retain the exact name mapping for later effective Docker inspection.
        planned = {path: bindings[path].name for path in sorted(expected_paths)}
        candidate = self._reserve("container")
        candidate.planned_mounts = planned
        candidate.state = "REQUESTED"
        self._record("CREATE_REQUESTED", candidate)
        command = [
            "docker",
            "create",
            "--platform",
            "linux/amd64",
            "--memory-swap",
            str(bounds._limits(self.policy, "docker_runtime")["memory_bytes"]),
            "--name",
            candidate.name,
            "--network",
            "none",
            "--label",
            "mcpbg.p4.owner=" + self.attempt_id,
            *bounds.docker_resource_args(self.policy),
            *flags,
            image,
        ]
        # No --tmpfs for /trusted-output: an owned volume occupies that path.
        # The frozen /tmp OS-backed tmpfs remains in docker_resource_args.
        result = self._checked_call(command)
        if result.exit_code != 0:
            self.recovery_required = True
            raise P4RecoveryRequired("mounted container creation UNKNOWN")
        identity = result.stdout.decode("ascii", errors="ignore").strip()
        if re.fullmatch(r"[a-f0-9]{64}", identity) is None:
            self.recovery_required = True
            raise P4RecoveryRequired("mounted container identity UNKNOWN")
        candidate.object_id = identity
        candidate.state = "CREATED"
        self._record("CREATE_CONFIRMED", candidate)
        return candidate

    def attest_fixed_container(
        self, item: OwnedItem, authority_raw: bytes, *, role: str
    ) -> dict[str, str]:
        """Check effective daemon state before any start; do not start the container.

        Docker create flags are *requests*, not proof. The trusted image is
        separately bound to P3 generation 1. Treat malformed or drifted Docker
        inspection as UNKNOWN so the owned container is not executed.
        """
        if (
            not self._entered
            or not any(existing is item for existing in self.items)
            or item.kind != "container"
            or item.state != "CREATED"
            or not isinstance(item.object_id, str)
            or re.fullmatch(r"[a-f0-9]{64}", item.object_id) is None
        ):
            raise P4AdapterError("owned created container required for pre-start attestation")
        try:
            if (
                type(authority_raw) is not bytes
                or hashlib.sha256(authority_raw).hexdigest() != PROMOTED_AUTHORITY_SHA256
            ):
                raise P4AdapterError("attestation authority bytes differ")
            authority = json.loads(authority_raw)
            image = authority["runtime"]["images"][role]
            approved_fixture_image(authority_raw, role=role, image=image)
            result = self._checked_call(
                ["docker", "container", "inspect", "--format", "{{json .}}", item.object_id]
            )
            if result.exit_code != 0:
                raise P4AdapterError("effective Docker inspection failed")
            json_policy = bounds._mapping(self.policy.get("json_intake"), "json_intake")
            parsed = bounds._load_object_bytes(
                result.stdout,
                max_bytes=bounds._positive_int(json_policy.get("max_bytes"), "json.max_bytes"),
                label="Docker effective inspection",
                shape=json_policy,
            )
            bounds._validate_json_shape(parsed, json_policy)
            config = parsed.get("Config")
            host = parsed.get("HostConfig")
            state = parsed.get("State")
            if not all(isinstance(x, dict) for x in (config, host, state)):
                raise P4AdapterError("Docker effective config missing")
            limit = bounds._limits(self.policy, "docker_runtime")
            artifacts = bounds._limits(self.policy, "artifacts")
            log = host.get("LogConfig")
            tmpfs = host.get("Tmpfs")
            mounts = parsed.get("Mounts")
            expected_tmpfs = {
                "/tmp": f"rw,noexec,nosuid,size={bounds._docker_size(limit['tmpfs_bytes'])}",
            }
            if item.planned_mounts is None:
                # Retained only for source-level backwards-compatibility tests.
                # A legacy tmpfs container is NOT eligible for physical artifact export.
                expected_tmpfs["/trusted-output"] = (
                    f"rw,noexec,nosuid,size={artifacts['total_bytes']}"
                )
            else:
                if (
                    type(item.planned_mounts) is not dict
                    or set(item.planned_mounts)
                    != ({"/state", "/trusted-output"} if role == "fixture" else {"/trusted-output"})
                    or not isinstance(mounts, list)
                    or len(mounts) != len(item.planned_mounts)
                ):
                    raise P4AdapterError("effective owned mount inventory mismatch")
                found: set[str] = set()
                for mount in mounts:
                    if not isinstance(mount, dict):
                        raise P4AdapterError("effective Docker mount malformed")
                    dest = mount.get("Destination")
                    if (
                        dest not in item.planned_mounts
                        or dest in found
                        or mount.get("Type") != "volume"
                        or mount.get("Name") != item.planned_mounts[dest]
                        or mount.get("RW") is not True
                    ):
                        raise P4AdapterError("effective owned mount identity mismatch")
                    found.add(dest)
                if found != set(item.planned_mounts):
                    raise P4AdapterError("effective owned mounts incomplete")
                for volume in item.planned_mounts.values():
                    if not any(
                        owned.kind == "volume"
                        and owned.name == volume
                        and owned.artifact_tmpfs_attested
                        and owned.artifact_owner_uid == (10001 if role == "fixture" else 10003)
                        and owned.state == "CREATED"
                        for owned in self.items
                    ):
                        raise P4AdapterError("effective mount no longer owned")
            labels = config.get("Labels")
            if (
                parsed.get("Id") != item.object_id
                or parsed.get("Name") != "/" + item.name
                or config.get("Image") != image
                or not isinstance(labels, dict)
                or labels.get("mcpbg.p4.owner") != self.attempt_id
                or state.get("Running") is not False
                or state.get("Pid") not in (0, None)
                or host.get("NetworkMode") != "none"
                or host.get("ReadonlyRootfs") is not True
                or host.get("Privileged") is not False
                or host.get("PublishAllPorts") is not False
                or host.get("Memory") != limit["memory_bytes"]
                or host.get("MemorySwap") != limit["memory_bytes"]
                or host.get("PidsLimit") != limit["pids_limit"]
                or host.get("NanoCpus") != limit["nano_cpus"]
                or not isinstance(host.get("CapDrop"), list)
                or "ALL" not in host["CapDrop"]
                or host.get("CapAdd") not in (None, [])
                or not isinstance(host.get("SecurityOpt"), list)
                or "no-new-privileges:true" not in host["SecurityOpt"]
                or host.get("Binds") not in (None, [])
                or host.get("Devices") not in (None, [])
                or host.get("PortBindings") not in (None, {})
                or (item.planned_mounts is None and mounts not in (None, []))
                or tmpfs != expected_tmpfs
                or not isinstance(log, dict)
                or log.get("Type") != "local"
                or log.get("Config") != {"max-size": "1m", "max-file": "2"}
            ):
                raise P4AdapterError("effective Docker containment/identity mismatch")
            item.prestart_attested = True
            item.mounted_attested = item.planned_mounts is not None
            return {
                "status": "PRESTART_CONFIG_ATTESTED_SOURCE_ONLY",
                "container_id": item.object_id,
            }
        except Exception as exc:
            self.recovery_required = True
            raise P4RecoveryRequired("pre-start container attestation UNKNOWN") from exc

    def export_paused_fixed_artifacts(
        self, item: OwnedItem, authority_raw: bytes, *, role: str, destination: Path
    ) -> dict[str, int | str]:
        """Disabled: docker cp cannot export a Docker tmpfs or named mount.

        A future volume-backed exporter must independently prove its own
        immutable identity, writer fence and daemon-side cleanup. This source
        branch does not authorize execution, publishing or proof.
        """
        if (
            not self._entered
            or not any(owned is item for owned in self.items)
            or item.kind != "container"
            or item.state != "CREATED"
            or not item.prestart_attested
            or not isinstance(item.object_id, str)
        ):
            raise P4AdapterError("verified prestart-attested owned container required")
        self.recovery_required = True
        raise P4RecoveryRequired(
            "physical artifact export UNKNOWN; unsupported Docker cp from mounted filesystem"
        )

    # BuildKit execution is deferred until its image is pinned by digest and its
    # extra daemon container, cache volume, loaded image and cleanup are owned.
    # Do not fall back to Docker's shared default builder or a global prune.

    def _owned_before_delete(self, item: OwnedItem) -> bool | None:
        """Verify exact owner and immutable object ID, not an attacker-reused name.

        A CREATE_REQUESTED record with no confirmed ID cannot authorize removal.
        Only an independently verified absence can close that unknown operation.
        """
        if item.kind == "container":
            field = '{{.Id}}|{{index .Config.Labels "mcpbg.p4.owner"}}'
            argv = ["docker", "container", "inspect", "--format", field, item.name]
        elif item.kind in {"network", "volume"}:
            identity = ".Id" if item.kind == "network" else ".Name"
            field = "{{" + identity + '}}|{{index .Labels "mcpbg.p4.owner"}}'
            argv = ["docker", item.kind, "inspect", "--format", field, item.name]
        else:
            raise P4AdapterError("unsupported resource type")
        result = self._checked_call(argv, cleanup=True)
        if result.exit_code == 1 and any(
            token in result.stderr.lower()
            for token in (b"no such object", b"no such network", b"no such volume")
        ):
            return False
        if result.exit_code != 0 or len(result.stdout) > 256:
            return None
        try:
            parsed = result.stdout.decode("ascii").strip().split("|")
        except UnicodeDecodeError:
            return None
        if len(parsed) != 2 or parsed[1] != self.attempt_id:
            return None
        expected = item.object_id
        if not isinstance(expected, str) or not expected or parsed[0] != expected:
            return None
        if item.kind in {"container", "network"}:
            if re.fullmatch(r"[a-f0-9]{64}", parsed[0]) is None:
                return None
        elif parsed[0] != item.name:
            return None
        return True

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
                delete = ["docker", "rm", "-f", item.object_id or item.name]
            elif item.kind == "network":
                delete = ["docker", "network", "rm", item.object_id or item.name]
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
