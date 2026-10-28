"""Journal one source-only trusted-helper startup group without starting the candidate.

The native startup barrier is deliberately absent: this is a bounded Engine
readback for trusted helpers, not permission to execute candidate source.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

import p4_resource_enforcement as bounds
import p4_runtime_topology as topology
from p4_pipeline_journal import _STAGES, JournalUnknown, PipelineJournal
from p4_scoped_engine import ScopedEngineRunner
from p4_trusted_runtime_adapter import OwnedDockerAttempt, OwnedItem

_ROLES = ("candidate", "evaluator", "relay", "fixture-app", "fixture-control")
_HELPERS = ("fixture-control", "fixture-app", "relay", "evaluator")
_ID = re.compile(r"[a-f0-9]{64}\Z")


def _fresh_state(
    attempt: OwnedDockerAttempt, item: OwnedItem, *, running: bool, deadline: float
) -> str:
    """Read a full bounded Engine container descriptor, not a caller's claim."""
    if (
        not isinstance(item.object_id, str)
        or not _ID.fullmatch(item.object_id)
        or attempt._attested_role_ids is None
        or item.object_id not in attempt._attested_role_ids.values()
        or time.monotonic() >= deadline
    ):
        raise JournalUnknown("helper/candidate identity or deadline changed")
    response = attempt._checked_call(
        ["docker", "container", "inspect", "--format", "{{json .}}", item.object_id],
        structured=True,
    )
    if response.exit_code != 0 or response.stderr:
        raise JournalUnknown("bounded Engine readback failed")
    try:
        value = bounds._load_object_bytes(
            response.stdout,
            max_bytes=65_536,
            label="trusted helper active graph Engine descriptor",
            shape={
                "max_depth": 32,
                "max_array_items": 1024,
                "max_object_members": 1024,
                "max_string_bytes": 65_536,
            },
        )
    except bounds.P4ResourceEnforcementError as exc:
        raise JournalUnknown("bounded Engine descriptor malformed") from exc
    config, host, state = value.get("Config"), value.get("HostConfig"), value.get("State")
    if (
        value.get("Id") != item.object_id
        or type(config) is not dict
        or type(config.get("Labels")) is not dict
        or config["Labels"].get("mcpbg.p4.owner") != attempt.attempt_id
        or type(host) is not dict
        or type(host.get("RestartPolicy")) is not dict
        or host["RestartPolicy"].get("Name") != "no"
        or type(state) is not dict
        or state.get("Running") is not running
        or state.get("Restarting") is not False
        or state.get("Dead") is not False
        or type(state.get("Pid")) is not int
        or (running and state["Pid"] <= 0)
        or (not running and state["Pid"] != 0)
        or time.monotonic() >= deadline
    ):
        raise JournalUnknown("Engine startup descriptor or owner drifted")
    return hashlib.sha256(response.stdout).hexdigest()


def reconcile_trusted_helper_group(
    *,
    attempt: OwnedDockerAttempt,
    journal: PipelineJournal,
    role_items: dict[str, OwnedItem],
    network_items: dict[str, OwnedItem],
    operation_id: str,
) -> dict[str, Any]:
    """Reserve intent, start four helpers and verify candidate stayed stopped.

    This never calls a candidate start and never asserts the candidate's
    physical pre-execution barrier, network readiness or live S0-S6 success.
    """
    if (
        type(attempt) is not OwnedDockerAttempt
        or type(journal) is not PipelineJournal
        or not isinstance(attempt.run, ScopedEngineRunner)
        or not attempt._entered
        or attempt.recovery_required
        or attempt._attested_role_ids is None
        or type(role_items) is not dict
        or type(network_items) is not dict
        or set(role_items) != set(_ROLES)
        or set(network_items) != {"subject", "fixture", "control"}
        or set(attempt._attested_role_ids) != set(_ROLES)
        or len(set(attempt._attested_role_ids.values())) != 5
        or journal.fd is None
        or journal.pending
        or journal.unknown
        or journal.stage_index != _STAGES.index("ACTIVE_GRAPH_OBSERVED")
        or journal.identity.attempt_id != attempt.attempt_id
        or journal.identity.runtime_daemon != attempt.daemon_identity
        or attempt.outer_deadline_monotonic is None
        or journal.deadline > attempt.outer_deadline_monotonic
        or time.monotonic() >= journal.deadline
        or len({item.object_id for item in network_items.values()}) != 3
        or any(
            type(item) is not OwnedItem
            or not any(owned is item for owned in attempt.items)
            or item.kind != "network"
            or item.state != "CREATED"
            or not isinstance(item.object_id, str)
            or not _ID.fullmatch(item.object_id)
            for item in network_items.values()
        )
        or any(
            type(item) is not OwnedItem
            or not any(owned is item for owned in attempt.items)
            or item.kind != "container"
            or item.object_id != attempt._attested_role_ids[role]
            or item.state != "CREATED"
            for role, item in role_items.items()
        )
    ):
        raise JournalUnknown("helper group lacks complete owned prestart and journal admission")
    deadline = min(journal.deadline, attempt.outer_deadline_monotonic)
    # Capture the previously attested immutable role mapping for the nested
    # callback. The entry guard alone does not narrow mutable adapter state
    # across the remote-effect function boundary.
    role_ids = attempt._attested_role_ids
    if role_ids is None:
        raise JournalUnknown("attested five-role identities unavailable")

    def perform() -> dict[str, Any]:
        before = _fresh_state(attempt, role_items["candidate"], running=False, deadline=deadline)
        starts = {}
        for role in _HELPERS:
            receipt = attempt.start_attested_trusted_role(
                role=role, item=role_items[role], journal=journal
            )
            if (
                receipt.get("container_id") != role_ids[role]
                or receipt.get("status") != "TRUSTED_HELPER_STARTED_SOURCE_ONLY"
                or receipt.get("runtime_enforcement_proven") is not False
            ):
                raise JournalUnknown("trusted helper start receipt mismatch")
            starts[role] = receipt["container_id"]
        # A start reply from one helper cannot attest the state of another.
        after = {
            role: _fresh_state(attempt, role_items[role], running=True, deadline=deadline)
            for role in _HELPERS
        }
        candidate_after = _fresh_state(
            attempt, role_items["candidate"], running=False, deadline=deadline
        )
        if before != candidate_after:
            raise JournalUnknown("candidate pre/post inspection drifted")
        inventory = {}
        hashes = {}
        for name in ("subject", "fixture", "control"):
            network_id = network_items[name].object_id
            if not isinstance(network_id, str) or not _ID.fullmatch(network_id):
                raise JournalUnknown("owned active network identity unavailable")
            response = attempt._checked_call(
                ["docker", "network", "inspect", "--format", "{{json .}}", network_id],
                structured=True,
            )
            if response.exit_code != 0 or response.stderr:
                raise JournalUnknown("active network Engine inspection failed")
            try:
                inventory[name] = bounds._load_object_bytes(
                    response.stdout,
                    max_bytes=65_536,
                    label="trusted helper network Engine descriptor",
                    shape={
                        "max_depth": 32,
                        "max_array_items": 1024,
                        "max_object_members": 1024,
                        "max_string_bytes": 65_536,
                    },
                )
            except bounds.P4ResourceEnforcementError as exc:
                raise JournalUnknown("malformed bounded network descriptor") from exc
            if inventory[name].get("Id") != network_items[name].object_id:
                raise JournalUnknown("network ID drifted from owned ledger")
            hashes[name] = hashlib.sha256(response.stdout).hexdigest()
        try:
            topology.verify_network_isolation(
                network_inventory=inventory,
                assigned={
                    "subject": {"candidate", "evaluator", "relay"},
                    "fixture": {"fixture-app", "relay"},
                    "control": {"fixture-control"},
                },
                owner=attempt.attempt_id,
                peer_container_ids=role_ids,
                checkpoint="helpers_active",
            )
        except topology.P4TopologyError as exc:
            raise JournalUnknown("helper-only active network topology UNKNOWN") from exc
        return {
            "starts": starts,
            "helper_descriptors_sha256": after,
            "candidate_sha256": candidate_after,
            "network_descriptors_sha256": hashes,
        }

    def observe(result: object) -> bytes:
        if not isinstance(result, dict) or set(result) != {
            "starts",
            "helper_descriptors_sha256",
            "candidate_sha256",
            "network_descriptors_sha256",
        }:
            raise JournalUnknown("helper group observer received no Engine evidence")
        receipt = {
            "schema_version": 1,
            "attempt_id": journal.identity.attempt_id,
            "operation_id": operation_id,
            "stage": "ACTIVE_GRAPH_OBSERVED",
            "worker": journal.identity.runtime_worker,
            "daemon": journal.identity.runtime_daemon,
            "runtime_enforcement_proven": False,
            "complete_integrated_runtime_wiring": False,
            "approval_outcome": "NOT_EVALUATED",
            "startup_barrier_proven": False,
            "candidate_started": False,
            "helper_start_receipts": result["starts"],
            "helper_descriptors_sha256": result["helper_descriptors_sha256"],
            "candidate_descriptor_sha256": result["candidate_sha256"],
            "active_network_verified": False,
            "helper_network_membership_verified_source_only": True,
            "helper_network_descriptors_sha256": result["network_descriptors_sha256"],
        }
        return json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()

    return journal.advance(
        "ACTIVE_GRAPH_OBSERVED",
        operation_id=operation_id,
        mutate=perform,
        observe=observe,
        output_bytes=524_288,
    )
