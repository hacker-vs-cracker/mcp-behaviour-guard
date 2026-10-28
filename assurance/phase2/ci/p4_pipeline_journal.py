"""Durable P4 source-stage ownership and recovery contract.

This journal sequences independently observed controller boundaries. It never
starts Docker, mints physical attestations, approves an outcome or replays a
remote mutation after a lost acknowledgement. A native coordinator must obtain
observations from its pinned Engine and worker, not candidate-supplied JSON.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import p4_resource_enforcement as bounds


class JournalUnknown(RuntimeError):
    """Unresolved operation or invalid durability evidence requires reconciliation."""


_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_STAGES = (
    "BUILD_WORKER_ADMITTED",
    "BUILD_RESULT_OBSERVED",
    "IMAGE_TRANSFER_OBSERVED",
    "BUILD_WORKER_DISPOSED",
    "RUNTIME_WORKER_ADMITTED",
    "CREATED_GRAPH_OBSERVED",
    "ACTIVE_GRAPH_OBSERVED",
    "RELAY_DRAINED",
    "CONTROL_FINALIZED",
    "WRITERS_FENCED",
    "EXPORT_RECONCILED",
    "CLEANUP_RECONCILED",
    "SAVED_RUN_COMPARED",
)
# R33 v1 receipts compared before cleanup. Read them only for historical
# recovery; R34 v2 receipts require verified cleanup before comparison.
_LEGACY_STAGES = _STAGES[:-2] + ("SAVED_RUN_COMPARED", "CLEANUP_RECONCILED")
_JOURNAL_SCHEMA = 2
_BUILD_STAGES = frozenset(_STAGES[:4])
_MAX_JOURNAL_BYTES = 131_072
_MAX_EVENTS = 32
_MAX_RECEIPT_BYTES = 1_048_576
_FROZEN_P3 = "54ddd04418211add290a597b2e775fb05953d7599b4e78014e57b24b105b6f09"
_FROZEN_POLICY = "cd321216217fbc11034e0aeb0a4afaca7ae42607142cd9158e31d094f54a707f"


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_sha(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _expected(stage: str, evidence: dict[str, Any]) -> None:
    """Reject synthetic shortcuts, absent identities and incomplete fence evidence."""
    if stage == "BUILD_WORKER_ADMITTED":
        # The source journal never treats a caller's platform/storage boolean as
        # physical admission. Require the reviewed build spec and the independent
        # whole-worker storage verifier's identities before recording the stage.
        if (
            evidence.get("platform") != "linux/amd64"
            or not _valid_sha(evidence.get("whole_worker_storage_sha256"))
            or not _valid_sha(evidence.get("reviewed_build_spec_sha256"))
            or not _valid_sha(evidence.get("private_engine_endpoint_sha256"))
            or type(evidence.get("whole_worker_storage_bytes")) is not int
            or not 0 < evidence["whole_worker_storage_bytes"] <= 1_073_741_824
            or evidence.get("physical_admission_proven") is not False
        ):
            raise JournalUnknown("native build admission identities or whole-worker bound missing")
    elif stage == "BUILD_RESULT_OBSERVED":
        if (
            evidence.get("platform") != "linux/amd64"
            or not _valid_sha(evidence.get("reviewed_build_spec_sha256"))
            or not _valid_sha(evidence.get("bounded_build_receipt_sha256"))
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(evidence.get("resolved_image_id")))
            or type(evidence.get("build_exit_code")) is not int
            or evidence["build_exit_code"] != 0
            or evidence.get("build_observed_source_only") is not True
            or evidence.get("physical_build_proven") is not False
        ):
            raise JournalUnknown("bounded build output and resolved image readback required")
    elif stage == "RUNTIME_WORKER_ADMITTED":
        if (
            evidence.get("platform") != "linux/amd64"
            or not _valid_sha(evidence.get("private_engine_endpoint_sha256"))
            or not _valid_sha(evidence.get("build_disposal_receipt_sha256"))
            or not _valid_sha(evidence.get("image_transfer_receipt_sha256"))
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(evidence.get("resolved_image_id")))
            or evidence.get("candidate_started") is not False
            or evidence.get("native_runtime_admission_proven") is not False
        ):
            raise JournalUnknown(
                "runtime admission needs bounded handover and fresh daemon identities"
            )
    elif stage == "IMAGE_TRANSFER_OBSERVED":
        if (
            evidence.get("platform") != "linux/amd64"
            or not _valid_sha(evidence.get("source_archive_sha256"))
            or evidence.get("source_archive_sha256") != evidence.get("destination_archive_sha256")
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(evidence.get("source_image_id")))
            or evidence.get("source_image_id") != evidence.get("destination_image_id")
            or type(evidence.get("transfer_bytes")) is not int
            or not 0 < evidence["transfer_bytes"] <= 1_073_741_824
        ):
            raise JournalUnknown("build-image transport identity incomplete")
    elif stage == "BUILD_WORKER_DISPOSED":
        if (
            evidence.get("worker_alive") is not False
            or evidence.get("daemon_alive") is not False
            or type(evidence.get("cache_entries")) is not int
            or evidence["cache_entries"] != 0
            or type(evidence.get("scratch_entries")) is not int
            or evidence["scratch_entries"] != 0
            or evidence.get("remaining_owned_resources") != []
            or not _valid_sha(evidence.get("disposal_readback_sha256"))
            or evidence.get("daemon_socket_present") is not False
            or evidence.get("data_root_mounted") is not False
            or evidence.get("builder_present") is not False
            or evidence.get("disposal_inspected_source_only") is not True
            or evidence.get("physical_disposal_proven") is not False
        ):
            raise JournalUnknown(
                "build worker disposal needs external readbacks, not a cleanup claim"
            )
    elif stage == "CREATED_GRAPH_OBSERVED":
        roles = evidence.get("roles")
        if (
            type(roles) is not dict
            or set(roles) != {"candidate", "evaluator", "relay", "fixture-app", "fixture-control"}
            or not all(_valid_sha(x) for x in roles.values())
            or evidence.get("candidate_started") is not False
            or not _valid_sha(evidence.get("profiles_sha256"))
        ):
            raise JournalUnknown("created five-role graph not independently read back")
    elif stage == "ACTIVE_GRAPH_OBSERVED":
        # This observation is NOT candidate startup authority. A physically
        # enforced pre-execution barrier remains separately required.
        if evidence.get("startup_barrier_proven") is not False:
            raise JournalUnknown("source inventory cannot claim a native startup barrier")
        # R38/R39 source-only active graph must never fall back to the older
        # boolean-only journal receipt. Historical journals remain readable
        # through inspect_recovery(), which does not grant fresh startup.
        helpers = ("fixture-control", "fixture-app", "relay", "evaluator")
        receipts = evidence.get("helper_start_receipts")
        descriptors = evidence.get("helper_descriptors_sha256")
        if (
            type(receipts) is not dict
            or set(receipts) != set(helpers)
            or not all(isinstance(receipts[x], str) and _valid_sha(receipts[x]) for x in helpers)
            or len(set(receipts.values())) != 4
            or type(descriptors) is not dict
            or set(descriptors) != set(helpers)
            or not all(_valid_sha(descriptors[x]) for x in helpers)
            or not _valid_sha(evidence.get("candidate_descriptor_sha256"))
            or evidence.get("candidate_started") is not False
            or evidence.get("active_network_verified") is not False
            or evidence.get("helper_network_membership_verified_source_only") is not True
            or type(evidence.get("helper_network_descriptors_sha256")) is not dict
            or set(evidence["helper_network_descriptors_sha256"])
            != {"subject", "fixture", "control"}
            or not all(
                _valid_sha(x) for x in evidence["helper_network_descriptors_sha256"].values()
            )
        ):
            raise JournalUnknown("helper group source readbacks malformed or overstated")
    elif stage == "RELAY_DRAINED":
        if (
            evidence.get("admission_closed") is not True
            or type(evidence.get("active_requests")) is not int
            or evidence["active_requests"] != 0
            or evidence.get("drain_complete") is not True
        ):
            raise JournalUnknown("relay still admits or owns requests")
    elif stage == "CONTROL_FINALIZED":
        if (
            evidence.get("audit_complete") is not True
            or type(evidence.get("active_requests")) is not int
            or evidence["active_requests"] != 0
        ):
            raise JournalUnknown("final control audit or request drainage incomplete")
    elif stage == "WRITERS_FENCED":
        writers = evidence.get("writers")
        if (
            type(writers) is not dict
            or set(writers) != {"fixture-app", "fixture-control"}
            or not all(
                type(x) is dict
                and x.get("running") is False
                and type(x.get("pid")) is int
                and x["pid"] == 0
                and _valid_sha(x.get("container_id"))
                for x in writers.values()
            )
            or type(evidence.get("active_requests")) is not int
            or evidence["active_requests"] != 0
        ):
            raise JournalUnknown("both fixture writers must be independently fenced")
    elif stage == "EXPORT_RECONCILED":
        if (
            evidence.get("source_export_status") != "MATCHED_FENCED_SOURCE_DIGESTS_SOURCE_ONLY"
            or evidence.get("business_effect_status") != "MATCHED_REVIEWED_PROJECTION_SOURCE_ONLY"
            or evidence.get("runtime_enforcement_proven") is not False
        ):
            raise JournalUnknown("transcript/hash agreement alone is not business proof")
    elif stage == "SAVED_RUN_COMPARED":
        if (
            evidence.get("approval_outcome") != "NOT_EVALUATED"
            or evidence.get("runtime_enforcement_proven") is not False
            or not _valid_sha(evidence.get("comparison_sha256"))
        ):
            raise JournalUnknown("comparison is not an approval verdict")
    elif stage == "CLEANUP_RECONCILED" and evidence.get("owned_resources_remaining") != []:
        raise JournalUnknown("cleanup cannot be inferred from CLI success")


@dataclass(frozen=True)
class PipelineIdentity:
    pipeline_id: str
    attempt_id: str
    source_commit: str
    source_tree: str
    policy_sha256: str
    reference_sha256: str
    build_worker: str
    build_daemon: str
    runtime_worker: str
    runtime_daemon: str

    def __post_init__(self) -> None:
        if (
            not _ID.fullmatch(self.pipeline_id)
            or not _ID.fullmatch(self.attempt_id)
            or self.policy_sha256 != _FROZEN_POLICY
            or self.reference_sha256 != _FROZEN_P3
            or not all(
                _valid_sha(x)
                for x in (
                    self.policy_sha256,
                    self.reference_sha256,
                    self.build_worker,
                    self.build_daemon,
                    self.runtime_worker,
                    self.runtime_daemon,
                )
            )
            or not re.fullmatch(r"[a-f0-9]{40}", self.source_commit)
            or not re.fullmatch(r"[a-f0-9]{40}", self.source_tree)
            or self.build_worker == self.runtime_worker
            or self.build_daemon == self.runtime_daemon
        ):
            raise JournalUnknown("stage identity cannot be reused or is malformed")


def _require_private_journal_scope(path: Path) -> None:
    """Reject writable/aliased parent directories before trusting journal bytes.

    The file's own O_NOFOLLOW and 0600 modes do not make an attacker-writable
    parent safe: a rename could swap the pathname between recovery operations.
    Path resolution is deliberately not a substitute for this permission check.
    """
    parent = path.parent
    try:
        info = parent.lstat()
        canonical = parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise JournalUnknown("private journal scope missing or changed") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or canonical != parent
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise JournalUnknown("journal scope must be private, owned and canonical")


class PipelineJournal:
    """One owner and chain-verified intent/observation log for a single attempt.

    Recovery never sends a remote command. Records are source evidence only,
    not authenticated observations or a completed integrated runtime pipeline.
    """

    def __init__(self, path: Path, identity: PipelineIdentity, *, deadline: float) -> None:
        if (
            not isinstance(path, Path)
            or type(identity) is not PipelineIdentity
            or type(deadline) is not float
            or not time.monotonic() < deadline <= time.monotonic() + 600
        ):
            raise JournalUnknown("invalid original attempt deadline or journal identity")
        self.path = path
        self.identity = identity
        self.deadline = deadline
        self.fd: int | None = None
        self.lease_fd: int | None = None
        self.events: list[dict[str, Any]] = []
        self.stage_index = 0
        self.unknown = False
        self.pending = False
        self.bytes_accounted = 0
        # These anchors come only from observations made in this live, locked
        # attempt. A recovered journal is never resumed as operational authority.
        self.observed_receipts: dict[str, dict[str, Any]] = {}

    def __enter__(self) -> PipelineJournal:
        _require_private_journal_scope(self.path)
        lease = self.path.parent / "p4-pipeline-scope.lock"
        try:
            self.lease_fd = os.open(lease, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            lease_info = os.fstat(self.lease_fd)
            if (
                not stat.S_ISREG(lease_info.st_mode)
                or lease_info.st_mode & 0o077
                or lease_info.st_uid != os.getuid()
                or lease_info.st_nlink != 1
            ):
                raise JournalUnknown("untrusted pipeline lease")
            fcntl.flock(self.lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # A prior attempt's unreviewed recovery state cannot be cleared by
            # a process restart or another entrypoint. No glob-based deletion.
            if any(self.path.parent.glob("owned-p4-*.jsonl")):
                raise JournalUnknown("prior pipeline journal needs owner reconciliation")
            if not re.fullmatch(r"owned-p4-[a-z][a-z0-9-]{0,31}\.jsonl", self.path.name):
                raise JournalUnknown("unexpected pipeline journal filename")
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._append("OPEN", "", "", {})
            dfd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_args: object) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.lease_fd is not None:
            os.close(self.lease_fd)
            self.lease_fd = None

    def _append(self, status: str, stage: str, operation_id: str, details: dict[str, Any]) -> None:
        if self.fd is None or len(self.events) >= _MAX_EVENTS:
            raise JournalUnknown("durable journal unavailable or exceeds event ceiling")
        prior = self.events[-1]["digest"] if self.events else "0" * 64
        body = {
            "schema_version": _JOURNAL_SCHEMA,
            "pipeline_id": self.identity.pipeline_id,
            "attempt_id": self.identity.attempt_id,
            "stage": stage,
            "operation_id": operation_id,
            "status": status,
            "prior_sha256": prior,
            "source_commit": self.identity.source_commit,
            "source_tree": self.identity.source_tree,
            "policy_sha256": self.identity.policy_sha256,
            "reference_sha256": self.identity.reference_sha256,
            "details": details,
        }
        digest = _sha(_canonical(body))
        row = {**body, "digest": digest}
        data = _canonical(row) + b"\n"
        if len(data) > 4096 or os.fstat(self.fd).st_size + len(data) > _MAX_JOURNAL_BYTES:
            raise JournalUnknown("journal size exceeded before append")
        if os.write(self.fd, data) != len(data):
            raise JournalUnknown("short durable journal write")
        os.fsync(self.fd)
        self.events.append(row)

    def _require_stage_continuity(self, stage: str, evidence: dict[str, Any]) -> None:
        """Bind consecutive stage observations, not separately valid claims.

        The journal never treats equality between caller-supplied hashes as
        physical proof. The authoritative observer/supervisor is still required.
        Past journals are read-only recovery records, never sources of new
        execution authority.
        """
        prior = self.observed_receipts
        if stage == "BUILD_RESULT_OBSERVED":
            admitted = prior.get("BUILD_WORKER_ADMITTED")
            if admitted is None or evidence.get("reviewed_build_spec_sha256") != admitted.get(
                "reviewed_build_spec_sha256"
            ):
                raise JournalUnknown("build spec differs from admitted worker source")
        elif stage == "IMAGE_TRANSFER_OBSERVED":
            built = prior.get("BUILD_RESULT_OBSERVED")
            if built is None or evidence.get("source_image_id") != built.get("resolved_image_id"):
                raise JournalUnknown("staged source image differs from observed native build")
        elif stage == "RUNTIME_WORKER_ADMITTED":
            admitted = prior.get("BUILD_WORKER_ADMITTED")
            transferred = prior.get("IMAGE_TRANSFER_OBSERVED")
            disposed = prior.get("BUILD_WORKER_DISPOSED")
            if (
                admitted is None
                or transferred is None
                or disposed is None
                or evidence.get("build_disposal_receipt_sha256")
                != disposed.get("observation_sha256")
                or evidence.get("image_transfer_receipt_sha256")
                != transferred.get("observation_sha256")
                or evidence.get("resolved_image_id") != transferred.get("destination_image_id")
                or evidence.get("private_engine_endpoint_sha256")
                == admitted.get("private_engine_endpoint_sha256")
            ):
                raise JournalUnknown("runtime stage is not bound to prior image and disposal")

    def advance(
        self,
        stage: str,
        *,
        operation_id: str,
        mutate: Callable[[], object],
        observe: Callable[[object], bytes],
        output_bytes: int = 8192,
    ) -> dict[str, Any]:
        """Write intent before mutation; independently read back or retain UNKNOWN.

        Receipt bytes must fit the allowance durably reserved before mutation.
        Historical journal reservations remain recovery-only and never grant
        new execution authority.

        The caller must provide a trusted source-side observer, not a candidate
        path or an unchecked success flag. All outcomes remain source-only.
        """
        if (
            self.fd is None
            or self.unknown
            or self.pending
            or self.stage_index >= len(_STAGES)
            or stage != _STAGES[self.stage_index]
            or type(operation_id) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", operation_id) is None
            or any(x.get("operation_id") == operation_id for x in self.events)
            or not callable(mutate)
            or not callable(observe)
            or type(output_bytes) is not int
            or output_bytes <= 0
            or self.bytes_accounted + output_bytes > 1_048_576
            or time.monotonic() >= self.deadline
        ):
            raise JournalUnknown("stage, original budget, operation or journal unavailable")
        worker = (
            self.identity.build_worker if stage in _BUILD_STAGES else self.identity.runtime_worker
        )
        daemon = (
            self.identity.build_daemon if stage in _BUILD_STAGES else self.identity.runtime_daemon
        )
        # Reserve the *entire* declared allowance before any remote effect.
        # A lost reply must not make the same budget available again.
        self._append(
            "INTENT",
            stage,
            operation_id,
            {"worker": worker, "daemon": daemon, "reserved_output_bytes": output_bytes},
        )
        self.bytes_accounted += output_bytes
        self.pending = True
        try:
            result = mutate()
            raw = observe(result)
            if type(raw) is not bytes or not 0 < len(raw) <= min(output_bytes, _MAX_RECEIPT_BYTES):
                raise JournalUnknown("independent observation exceeded durable reservation")
            evidence = bounds._load_object_bytes(
                raw,
                max_bytes=_MAX_RECEIPT_BYTES,
                label="P4 controller source observation",
                shape={
                    "max_depth": 32,
                    "max_array_items": 1024,
                    "max_object_members": 1024,
                    "max_string_bytes": 65536,
                },
            )
            bounds._validate_json_shape(
                evidence,
                {
                    "max_depth": 32,
                    "max_array_items": 1024,
                    "max_object_members": 1024,
                    "max_string_bytes": 65536,
                },
            )
            if (
                type(evidence.get("schema_version")) is not int
                or evidence["schema_version"] != 1
                or evidence.get("attempt_id") != self.identity.attempt_id
                or evidence.get("operation_id") != operation_id
                or evidence.get("stage") != stage
                or evidence.get("worker") != worker
                or evidence.get("daemon") != daemon
                or evidence.get("runtime_enforcement_proven") is not False
                or evidence.get("approval_outcome") != "NOT_EVALUATED"
            ):
                raise JournalUnknown("source observation identity/context invalid")
            _expected(stage, evidence)
            self._require_stage_continuity(stage, evidence)
            self._append(
                "OBSERVED_SOURCE_ONLY",
                stage,
                operation_id,
                {"observation_sha256": _sha(raw), "output_bytes": output_bytes},
            )
            # Persist only bounded continuity anchors from this observation.
            # A later stage must not infer admission from a raw sidecar alone.
            anchors = {
                "observation_sha256": _sha(raw),
                **{
                    key: evidence[key]
                    for key in (
                        "reviewed_build_spec_sha256",
                        "private_engine_endpoint_sha256",
                        "resolved_image_id",
                        "source_image_id",
                        "destination_image_id",
                    )
                    if key in evidence
                },
            }
            self.observed_receipts[stage] = anchors
            self.stage_index += 1
            self.pending = False
            return {
                "schema_version": 1,
                "status": "SOURCE_STAGE_RECONCILED_ONLY",
                "next_stage": _STAGES[self.stage_index]
                if self.stage_index < len(_STAGES)
                else None,
                "runtime_enforcement_proven": False,
                "complete_integrated_runtime_wiring": False,
                "approval_outcome": "NOT_EVALUATED",
            }
        except BaseException:
            self.unknown = True
            # Even if the local observer fails, mutation may have completed.
            try:
                self._append("UNKNOWN", stage, operation_id, {})
            except Exception as exc:
                # A failed UNKNOWN append cannot be treated as reconciled. The
                # durable INTENT still requires explicit remote readback.
                raise JournalUnknown("cannot durably record uncertain remote operation") from exc
            raise

    def reconcile_build_worker_disposal(
        self,
        *,
        operation_id: str,
        dispose_worker: Callable[[], object],
        independently_inspect: Callable[[], bytes],
    ) -> dict[str, Any]:
        """Bind build-worker teardown to two trusted-supervisor observations.

        The caller must connect ``independently_inspect`` to the *outside*
        supervisor of the disposable native build worker, not the deleted
        worker itself, candidate output or a prewritten JSON sidecar. This
        source boundary cannot attest that supervisor's physical identity.
        The two matching replies remain source-only, never native proof.
        """
        if (
            self.fd is None
            or self.unknown
            or self.pending
            or self.stage_index != _STAGES.index("BUILD_WORKER_DISPOSED")
            or not callable(dispose_worker)
            or not callable(independently_inspect)
            or time.monotonic() >= self.deadline
        ):
            raise JournalUnknown("build worker disposal stage unavailable")

        def readback() -> tuple[dict[str, Any], str]:
            raw = independently_inspect()
            if type(raw) is not bytes or not 0 < len(raw) <= 65_536:
                raise JournalUnknown("bounded external build disposal observation missing")
            try:
                value = bounds._load_object_bytes(
                    raw,
                    max_bytes=65_536,
                    label="external native build worker disposal readback",
                    shape={
                        "max_depth": 16,
                        "max_array_items": 128,
                        "max_object_members": 64,
                        "max_string_bytes": 4096,
                    },
                )
            except bounds.P4ResourceEnforcementError as exc:
                raise JournalUnknown("external worker disposal JSON malformed") from exc
            expected = {
                "schema_version",
                "worker",
                "daemon",
                "worker_alive",
                "daemon_alive",
                "daemon_socket_present",
                "data_root_mounted",
                "builder_present",
                "cache_entries",
                "scratch_entries",
                "remaining_owned_resources",
                "inspection_complete",
            }
            if (
                set(value) != expected
                or type(value.get("schema_version")) is not int
                or value["schema_version"] != 1
                or value.get("worker") != self.identity.build_worker
                or value.get("daemon") != self.identity.build_daemon
                or any(
                    value.get(field) is not False
                    for field in (
                        "worker_alive",
                        "daemon_alive",
                        "daemon_socket_present",
                        "data_root_mounted",
                        "builder_present",
                    )
                )
                or any(
                    type(value.get(field)) is not int or value[field] != 0
                    for field in ("cache_entries", "scratch_entries")
                )
                or value.get("remaining_owned_resources") != []
                or value.get("inspection_complete") is not True
                or time.monotonic() >= self.deadline
            ):
                raise JournalUnknown("build worker or whole-worker storage cleanup UNKNOWN")
            return value, _sha(raw)

        def perform() -> dict[str, Any]:
            # advance() writes and fsyncs one INTENT before any remote teardown.
            dispose_worker()
            first, first_hash = readback()
            second, second_hash = readback()
            if first != second:
                raise JournalUnknown("build worker disposal changed between observations")
            return {"observation": second, "readback_hashes": [first_hash, second_hash]}

        def observe(result: object) -> bytes:
            if type(result) is not dict or set(result) != {"observation", "readback_hashes"}:
                raise JournalUnknown("external disposal observations missing")
            readbacks = result["readback_hashes"]
            if (
                type(readbacks) is not list
                or len(readbacks) != 2
                or not all(_valid_sha(value) for value in readbacks)
            ):
                raise JournalUnknown("two bounded disposal readbacks required")
            value = result["observation"]
            if type(value) is not dict:
                raise JournalUnknown("external disposal observation invalid")
            receipt = {
                "schema_version": 1,
                "attempt_id": self.identity.attempt_id,
                "operation_id": operation_id,
                "stage": "BUILD_WORKER_DISPOSED",
                "worker": self.identity.build_worker,
                "daemon": self.identity.build_daemon,
                "runtime_enforcement_proven": False,
                "complete_integrated_runtime_wiring": False,
                "approval_outcome": "NOT_EVALUATED",
                "worker_alive": False,
                "daemon_alive": False,
                "cache_entries": 0,
                "scratch_entries": 0,
                "remaining_owned_resources": [],
                "daemon_socket_present": False,
                "data_root_mounted": False,
                "builder_present": False,
                "disposal_inspected_source_only": True,
                "physical_disposal_proven": False,
                "disposal_readback_sha256": _sha(
                    _canonical({"first": readbacks[0], "second": readbacks[1]})
                ),
            }
            return _canonical(receipt)

        return self.advance(
            "BUILD_WORKER_DISPOSED",
            operation_id=operation_id,
            mutate=perform,
            observe=observe,
            output_bytes=8192,
        )

    def reconcile_staged_image_archive(
        self,
        *,
        operation_id: str,
        source_archive: Path,
        destination_archive: Path,
        source_image_inspect: dict[str, Any],
        destination_image_inspect: dict[str, Any],
        remaining_transfer_bytes: int,
    ) -> dict[str, Any]:
        """Use the bounded byte verifier, not supplied identity-success booleans.

        Both paths and Engine inspect records must come from the trusted operator.
        Local byte equality remains SOURCE_ONLY, not native handover proof.
        """
        from p4_image_handover import reconcile_staged_image

        if self.stage_index != _STAGES.index("IMAGE_TRANSFER_OBSERVED"):
            raise JournalUnknown("build result must precede image transfer")

        def verify() -> dict[str, Any]:
            return reconcile_staged_image(
                source_archive=source_archive,
                destination_archive=destination_archive,
                source_image_inspect=source_image_inspect,
                destination_image_inspect=destination_image_inspect,
                remaining_transfer_bytes=remaining_transfer_bytes,
                original_deadline_monotonic=self.deadline,
            )

        def observe(result: object) -> bytes:
            if (
                not isinstance(result, dict)
                or result.get("status") != "MATCHED_STAGE_ARCHIVE_BYTES_SOURCE_ONLY"
            ):
                raise JournalUnknown("verified stage image transfer result absent")
            return _canonical(
                {
                    "schema_version": 1,
                    "attempt_id": self.identity.attempt_id,
                    "operation_id": operation_id,
                    "stage": "IMAGE_TRANSFER_OBSERVED",
                    "worker": self.identity.build_worker,
                    "daemon": self.identity.build_daemon,
                    "runtime_enforcement_proven": False,
                    "approval_outcome": "NOT_EVALUATED",
                    "platform": result["platform"],
                    "source_archive_sha256": result["source_archive_sha256"],
                    "destination_archive_sha256": result["destination_archive_sha256"],
                    "source_image_id": result["source_image_id"],
                    "destination_image_id": result["destination_image_id"],
                    "transfer_bytes": result["transfer_bytes"],
                }
            )

        return self.advance(
            "IMAGE_TRANSFER_OBSERVED",
            operation_id=operation_id,
            mutate=verify,
            observe=observe,
        )

    def reconcile_live_writer_fence(
        self,
        *,
        operation_id: str,
        runtime_runner: Any,
        owned_container_ids: dict[str, str],
        active_requests: Callable[[], int],
    ) -> dict[str, Any]:
        """Join durable intent to bounded, exact-Engine two-writer readback.

        This never authorizes new container starts or asserts permanent native
        writer quiescence. The owner must maintain the restart fence until export.
        """
        from p4_live_writer_fence import observe_both_writers_fenced

        if self.stage_index != _STAGES.index("WRITERS_FENCED"):
            raise JournalUnknown("control must be finalized before writer readback")

        def readback() -> dict[str, Any]:
            return observe_both_writers_fenced(
                runtime_runner=runtime_runner,
                runtime_daemon_sha256=self.identity.runtime_daemon,
                attempt_id=self.identity.attempt_id,
                owned_container_ids=owned_container_ids,
                active_requests=active_requests,
                original_deadline_monotonic=self.deadline,
            )

        def observe(result: object) -> bytes:
            if not isinstance(result, dict) or result.get("writer_observation_status") != (
                "BOUND_ENGINE_DOUBLE_READ_SOURCE_ONLY"
            ):
                raise JournalUnknown("no trusted source-side writer fence observation")
            return _canonical(
                {
                    "schema_version": 1,
                    "attempt_id": self.identity.attempt_id,
                    "operation_id": operation_id,
                    "stage": "WRITERS_FENCED",
                    "worker": self.identity.runtime_worker,
                    "daemon": self.identity.runtime_daemon,
                    **result,
                }
            )

        # Reserve four bounded complete Engine command output envelopes before
        # the first daemon inspection; no failed readback refunds that allowance.
        return self.advance(
            "WRITERS_FENCED",
            operation_id=operation_id,
            mutate=readback,
            observe=observe,
            output_bytes=4 * 65_536,
        )

    def reconcile_exported_fixture(
        self,
        *,
        operation_id: str,
        exported_state: Path,
        fenced_snapshot: dict[str, Any],
        finalized_snapshot: dict[str, Any],
        expected_records: list[dict[str, Any]],
        fenced_source_sha256: dict[str, str],
        artifact_ceiling_bytes: int,
    ) -> dict[str, Any]:
        """Call the real bounded SQLite verifier, never a copied transcript digest.

        This cannot authenticate the fixture producer or attest a live writer
        fence. The preceding stage must already record both writer readbacks.
        """
        from p4_fixture_sqlite_export import verify_exported_fixture_sqlite

        if self.stage_index != _STAGES.index("EXPORT_RECONCILED"):
            raise JournalUnknown("export verifier requires both writer fences")

        def verify() -> dict[str, Any]:
            return verify_exported_fixture_sqlite(
                exported_state=exported_state,
                attempt_id=self.identity.attempt_id,
                fenced_snapshot=fenced_snapshot,
                finalized_snapshot=finalized_snapshot,
                artifact_ceiling_bytes=artifact_ceiling_bytes,
                reviewed_expected_records=expected_records,
                observed_fenced_file_sha256=fenced_source_sha256,
                original_deadline_monotonic=self.deadline,
            )

        def observe(result: object) -> bytes:
            if not isinstance(result, dict):
                raise JournalUnknown("real offline SQLite reconciliation missing")
            raw = {
                "schema_version": 1,
                "attempt_id": self.identity.attempt_id,
                "operation_id": operation_id,
                "stage": "EXPORT_RECONCILED",
                "worker": self.identity.runtime_worker,
                "daemon": self.identity.runtime_daemon,
                "runtime_enforcement_proven": False,
                "approval_outcome": "NOT_EVALUATED",
                "source_export_status": result["source_export_status"],
                "business_effect_status": result["business_effect_status"],
                "records_sha256": result["records_sha256"],
            }
            return _canonical(raw)

        return self.advance(
            "EXPORT_RECONCILED", operation_id=operation_id, mutate=verify, observe=observe
        )

    def compare_saved_run_after_cleanup(
        self,
        *,
        operation_id: str,
        authority_raw: bytes,
        policy_raw: bytes,
        reference_dir: Path,
        candidate_dir: Path,
        stage_handoff: dict[str, Any],
        subject: dict[str, Any],
        runtime_evidence: dict[str, Any],
    ) -> dict[str, Any]:
        """Call the shipped comparator only after final owned cleanup readback.

        The comparison is non-approving and cannot substitute for a physically
        proven controller/producer or fresh P4 adjudication.
        """
        if self.stage_index != _STAGES.index("SAVED_RUN_COMPARED"):
            raise JournalUnknown("saved-run comparison requires reconciled cleanup")

        def compare() -> dict[str, Any]:
            from p4_reference_bridge import compare_p4_saved_run

            from mcp_behaviour_guard.baseline import compare_saved_runs

            return compare_p4_saved_run(
                authority_raw=authority_raw,
                policy_raw=policy_raw,
                reference_dir=reference_dir,
                candidate_dir=candidate_dir,
                stage_handoff=stage_handoff,
                subject=subject,
                runtime_evidence=runtime_evidence,
                comparator=compare_saved_runs,
            )

        def observe(result: object) -> bytes:
            if (
                not isinstance(result, dict)
                or result.get("approval_outcome") != "NOT_EVALUATED"
                or result.get("runtime_proof_completed") is not False
            ):
                raise JournalUnknown("real comparator returned invalid non-approving result")
            result_raw = _canonical(result)
            return _canonical(
                {
                    "schema_version": 1,
                    "attempt_id": self.identity.attempt_id,
                    "operation_id": operation_id,
                    "stage": "SAVED_RUN_COMPARED",
                    "worker": self.identity.runtime_worker,
                    "daemon": self.identity.runtime_daemon,
                    "runtime_enforcement_proven": False,
                    "approval_outcome": "NOT_EVALUATED",
                    "comparison_sha256": _sha(result_raw),
                }
            )

        return self.advance(
            "SAVED_RUN_COMPARED",
            operation_id=operation_id,
            mutate=compare,
            observe=observe,
        )

    @classmethod
    def inspect_recovery(cls, path: Path, identity: PipelineIdentity) -> dict[str, Any]:
        """Read and verify existing bytes without replaying a pending operation."""
        _require_private_journal_scope(path)
        if path.is_symlink() or not path.is_file():
            raise JournalUnknown("recovery journal missing or linked")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            named = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or info.st_size > _MAX_JOURNAL_BYTES
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise JournalUnknown("recovery journal inode/mode/size invalid")
            raw = os.read(fd, _MAX_JOURNAL_BYTES + 1)
        finally:
            os.close(fd)
        if not raw.endswith(b"\n") or len(raw.splitlines()) > _MAX_EVENTS:
            raise JournalUnknown("torn or unbounded durable journal")
        prior = "0" * 64
        prior_event = None
        pending_id: str | None = None
        pending_reserved: int | None = None
        seen_ids: set[str] = set()
        reserved_total = 0
        observed = 0
        version: int | None = None
        for line in raw.splitlines():
            try:
                if len(line) > 4096:
                    raise JournalUnknown("oversized durable journal event")
                row = bounds._load_object_bytes(
                    line,
                    max_bytes=4096,
                    label="P4 durable journal event",
                    shape={
                        "max_depth": 12,
                        "max_array_items": 32,
                        "max_object_members": 32,
                        "max_string_bytes": 1024,
                    },
                )
                if (
                    set(row)
                    != {
                        "schema_version",
                        "pipeline_id",
                        "attempt_id",
                        "stage",
                        "operation_id",
                        "status",
                        "prior_sha256",
                        "source_commit",
                        "source_tree",
                        "policy_sha256",
                        "reference_sha256",
                        "details",
                        "digest",
                    }
                    or type(row.get("details")) is not dict
                ):
                    raise JournalUnknown("journal event schema differs")
                event_version = row["schema_version"]
                if type(event_version) is not int or event_version not in (1, 2):
                    raise JournalUnknown("unsupported journal schema")
                if version is None:
                    version = event_version
                if version != event_version:
                    raise JournalUnknown("journal schema changes mid-attempt")
                stages = _STAGES if version == 2 else _LEGACY_STAGES
                digest = row.pop("digest")
                if _sha(_canonical(row)) != digest or row["prior_sha256"] != prior:
                    raise JournalUnknown("journal digest linkage invalid")
                if (
                    row["pipeline_id"] != identity.pipeline_id
                    or row["attempt_id"] != identity.attempt_id
                    or row["source_commit"] != identity.source_commit
                    or row["source_tree"] != identity.source_tree
                    or row["policy_sha256"] != identity.policy_sha256
                    or row["reference_sha256"] != identity.reference_sha256
                    or row["schema_version"] != version
                ):
                    raise JournalUnknown("journal crossed attempt/source authority")
                if row["status"] == "INTENT":
                    details = row["details"]
                    if (
                        prior_event not in {"OPEN", "OBSERVED_SOURCE_ONLY"}
                        or observed >= len(stages)
                        or row["stage"] != stages[observed]
                        or type(row["operation_id"]) is not str
                        or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", row["operation_id"]) is None
                        or row["operation_id"] in seen_ids
                        or details.get("worker")
                        != (
                            identity.build_worker
                            if row["stage"] in _BUILD_STAGES
                            else identity.runtime_worker
                        )
                        or details.get("daemon")
                        != (
                            identity.build_daemon
                            if row["stage"] in _BUILD_STAGES
                            else identity.runtime_daemon
                        )
                    ):
                        raise JournalUnknown("duplicate or unbound remote mutation intent")
                    if version == 2:
                        if set(details) != {"worker", "daemon", "reserved_output_bytes"}:
                            raise JournalUnknown("durable reservation missing")
                        amount = details["reserved_output_bytes"]
                        if (
                            type(amount) is not int
                            or amount < 0
                            or reserved_total + amount > 1_048_576
                        ):
                            raise JournalUnknown("cumulative durable output allowance exceeded")
                        pending_reserved = amount
                        reserved_total += amount
                    else:
                        if set(details) != {"worker", "daemon"}:
                            raise JournalUnknown("legacy intent malformed")
                    seen_ids.add(row["operation_id"])
                    pending_id = row["operation_id"]
                elif row["status"] == "OBSERVED_SOURCE_ONLY":
                    if (
                        prior_event != "INTENT"
                        or row["operation_id"] != pending_id
                        or row["stage"] != stages[observed]
                        or set(row["details"]) != {"observation_sha256", "output_bytes"}
                        or not _valid_sha(row["details"].get("observation_sha256"))
                        or type(row["details"].get("output_bytes")) is not int
                        or row["details"]["output_bytes"] < 0
                        or (version == 2 and row["details"]["output_bytes"] != pending_reserved)
                    ):
                        raise JournalUnknown("journal transition or acknowledgement mismatch")
                    if version == 1:
                        reserved_total += row["details"]["output_bytes"]
                        if reserved_total > 1_048_576:
                            raise JournalUnknown("legacy journal output budget exceeded")
                    observed += 1
                    pending_id = None
                    pending_reserved = None
                elif row["status"] == "UNKNOWN":
                    if (
                        prior_event != "INTENT"
                        or row["operation_id"] != pending_id
                        or row["stage"] != stages[observed]
                        or row["details"] != {}
                    ):
                        raise JournalUnknown("unknown without remote mutation")
                elif (
                    row["status"] != "OPEN"
                    or prior_event is not None
                    or row["stage"] != ""
                    or row["operation_id"] != ""
                    or row["details"] != {}
                ):
                    raise JournalUnknown("duplicate open or invalid event")
                prior_event = row["status"]
                prior = digest
            except (TypeError, ValueError, KeyError, IndexError, UnicodeError) as exc:
                raise JournalUnknown("untrusted or malformed journal record") from exc
        if prior_event is None or (prior_event == "UNKNOWN" and pending_id is None):
            raise JournalUnknown("recovery journal has no valid owner history")
        return {
            "schema_version": 2,
            "status": "RECOVERY_REQUIRES_FRESH_READBACK",
            "source_journal_schema_version": version,
            "durable_output_bytes_accounted": reserved_total,
            "stages_observed": observed,
            "remote_operation_unresolved": prior_event in {"INTENT", "UNKNOWN"},
            "historical_receipts_are_startup_authority": False,
            "runtime_enforcement_proven": False,
            "approval_outcome": "NOT_EVALUATED",
        }
