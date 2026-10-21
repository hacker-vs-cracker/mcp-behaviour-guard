"""Read both P4 fixture writer states from the bound runtime Engine.

This is an independent source-side readback, not proof of physical quiescence.
Only a trusted coordinator may supply the owned IDs, scoped runner and relay
counter. A native admission gate must still prevent any later writer restart.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

import p4_resource_enforcement as bounds
from p4_scoped_engine import ScopedEngineRunner
from p4_trusted_runtime_adapter import CommandResult


class WriterFenceUnknown(RuntimeError):
    """A writer may still be active or the bound Engine readback is uncertain."""


_ID = re.compile(r"[a-f0-9]{64}\Z")
_ROLES = ("fixture-app", "fixture-control")
_JSON_SHAPE = {
    "max_depth": 32,
    "max_array_items": 1024,
    "max_object_members": 1024,
    "max_string_bytes": 65536,
}
_READ_BUDGET = 65536


def _read_container(
    runner: ScopedEngineRunner, container_id: str, owner: str, deadline: float
) -> dict[str, Any]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WriterFenceUnknown("original attempt deadline exhausted")
    try:
        result = runner(
            ("docker", "container", "inspect", "--format", "{{json .}}", container_id),
            timeout=min(20.0, remaining),
            output_budget=_READ_BUDGET,
            retained_per_stream=_READ_BUDGET,
        )
        if (
            not isinstance(result, CommandResult)
            or type(result.exit_code) is not int
            or result.exit_code != 0
            or type(result.output_bytes) is not int
            or not 0 < result.output_bytes <= _READ_BUDGET
            or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes
            or result.stderr
            or not result.stdout
            or len(result.stdout) > result.output_bytes
            or time.monotonic() >= deadline
        ):
            raise WriterFenceUnknown("Engine writer inspection incomplete")
        inspected = bounds._load_object_bytes(
            result.stdout,
            max_bytes=_READ_BUDGET,
            label="P4 Engine writer inspection",
            shape=_JSON_SHAPE,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise WriterFenceUnknown("Engine writer readback unavailable") from exc
    config = inspected.get("Config")
    host = inspected.get("HostConfig")
    state = inspected.get("State")
    if (
        type(config) is not dict
        or type(host) is not dict
        or type(state) is not dict
        or type(config.get("Labels")) is not dict
        or config["Labels"].get("mcpbg.p4.owner") != owner
        or inspected.get("Id") != container_id
        or type(host.get("RestartPolicy")) is not dict
        or host["RestartPolicy"].get("Name") != "no"
        or state.get("Running") is not False
        or state.get("Restarting") is not False
        or state.get("Dead") is not False
        or type(state.get("Pid")) is not int
        or state["Pid"] != 0
        or state.get("Status") not in ("created", "exited")
        or type(inspected.get("RestartCount")) is not int
        or inspected["RestartCount"] < 0
    ):
        raise WriterFenceUnknown("writer has not been independently fenced")
    return inspected


def observe_both_writers_fenced(
    *,
    runtime_runner: ScopedEngineRunner,
    runtime_daemon_sha256: str,
    attempt_id: str,
    owned_container_ids: dict[str, str],
    active_requests: Callable[[], int],
    original_deadline_monotonic: float,
) -> dict[str, Any]:
    """Two bounded Engine readbacks per writer under one attempt deadline.

    These are source receipts only. The owning coordinator must durably record
    the intent before the query, own the relay counter, and independently
    enforce no writer restart after this observation and through export.
    """
    if (
        not isinstance(runtime_runner, ScopedEngineRunner)
        or runtime_runner.binding.daemon_id_sha256 != runtime_daemon_sha256
        or type(attempt_id) is not str
        or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", attempt_id) is None
        or type(owned_container_ids) is not dict
        or set(owned_container_ids) != set(_ROLES)
        or any(type(x) is not str or not _ID.fullmatch(x) for x in owned_container_ids.values())
        or len(set(owned_container_ids.values())) != 2
        or not callable(active_requests)
        or type(original_deadline_monotonic) is not float
        or time.monotonic() >= original_deadline_monotonic
    ):
        raise WriterFenceUnknown("writer source identities or deadline invalid")
    prior: dict[str, dict[str, Any]] = {}
    for _round in range(2):
        try:
            pending = active_requests()
        except Exception as exc:
            raise WriterFenceUnknown("relay request counter unavailable") from exc
        if type(pending) is not int or pending != 0:
            raise WriterFenceUnknown("relay still owns active requests")
        for role in _ROLES:
            obj = _read_container(
                runtime_runner, owned_container_ids[role], attempt_id, original_deadline_monotonic
            )
            # A change in restart count or identity between polls leaves UNKNOWN,
            # even if the process happens to be stopped at each observation.
            if role in prior and obj["RestartCount"] != prior[role]["RestartCount"]:
                raise WriterFenceUnknown("writer restarted between Engine observations")
            prior[role] = obj
    try:
        remaining_requests = active_requests()
    except Exception as exc:
        raise WriterFenceUnknown("relay request counter lost after writer observations") from exc
    if type(remaining_requests) is not int or remaining_requests != 0:
        raise WriterFenceUnknown("relay request counter changed after writer observations")
    return {
        "writers": {
            role: {"running": False, "pid": 0, "container_id": owned_container_ids[role]}
            for role in _ROLES
        },
        "active_requests": 0,
        "writer_observation_status": "BOUND_ENGINE_DOUBLE_READ_SOURCE_ONLY",
        "runtime_enforcement_proven": False,
        "complete_integrated_runtime_wiring": False,
        "approval_outcome": "NOT_EVALUATED",
    }
