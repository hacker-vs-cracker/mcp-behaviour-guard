"""Controller-only fixed fixture-control RPC over Engine exec, not a subject route.

The trusted operator must attest the exact control container, state volume and
network immediately before each command. No candidate code or Docker socket is
mounted in a runtime container. This source has no import-time execution.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import p4_resource_enforcement as bounds


class ControlUnknown(RuntimeError):
    pass


_ID = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
CONTROL_JSON_SHAPE: dict[str, Any] = {
    "max_depth": 32,
    "max_string_bytes": 65536,
    "max_array_items": 1024,
    "max_object_members": 1024,
}


def _strict_control_object(raw: bytes) -> dict[str, Any]:
    try:
        value = bounds._load_object_bytes(
            raw, max_bytes=262144, label="fixture control response", shape=CONTROL_JSON_SHAPE
        )
        bounds._validate_json_shape(value, CONTROL_JSON_SHAPE)
        return value
    except bounds.P4ResourceEnforcementError as exc:
        raise ControlUnknown("fixture control response not bounded strict JSON") from exc


def _response_shape(value: dict[str, Any], *, action: str, attempt_id: str | None) -> None:
    def attempt_equals() -> bool:
        return type(value.get("attempt_id")) is str and value["attempt_id"] == attempt_id

    if "error" in value:
        raise ControlUnknown("fixture control endpoint reported error")
    if action == "health":
        valid = value.get("status") == "ok" and value.get("service") == "fixture-control"
    elif action == "create":
        valid = attempt_equals() and isinstance(value.get("token"), str) and bool(value["token"])
    elif action == "reset":
        valid = type(value.get("cursor_seq")) is int and value["cursor_seq"] >= 0
    elif action == "audit":
        valid = isinstance(value.get("events"), list)
    elif action == "snapshot":
        valid = (
            isinstance(value.get("attempt"), dict)
            and value["attempt"].get("attempt_id") == attempt_id
            and isinstance(value.get("requests"), list)
            and isinstance(value.get("audit"), list)
        )
    elif action == "final-snapshot":
        valid = (
            attempt_equals()
            and value.get("state") == "FENCED"
            and value.get("audit_complete") is True
            and type(value.get("final_watermark")) is int
            and isinstance(value.get("requests"), list)
            and isinstance(value.get("audit"), list)
        )
    else:
        target = {"open": "OPEN", "close": "FENCED", "finalize": "FINALIZED"}.get(action)
        valid = target is not None and attempt_equals() and value.get("state") == target
    if not valid:
        raise ControlUnknown("fixture control action-specific response invalid")


# Code identity is bound to this module and the allowed fixed action table.
# Only localhost is contacted, inside the independently attested control role.
FIXED_CONTROL_CLIENT = """import json,sys,urllib.request
method,path,payload=sys.argv[1:4]
assert method in ('GET','POST') and path.startswith('/')
request=urllib.request.Request('http://127.0.0.1:9000'+path,
 data=(payload.encode('ascii') if method=='POST' else None),
 headers={'Content-Type':'application/json'},method=method)
with urllib.request.urlopen(request,timeout=3) as response:
 raw=response.read(262145)
 if len(raw)>262144: raise ValueError('control reply oversized')
 print(raw.decode('utf-8'))
"""


@dataclass(frozen=True)
class ControlResponse:
    code: int
    stdout: bytes
    stderr: bytes
    output_bytes: int


_ACTIONS = {
    "health": ("GET", "/health"),
    "create": ("POST", "/attempts"),
    "reset": ("POST", "/observer/reset"),
    "audit": ("GET", "/observer/events"),
    "snapshot": ("GET", "/attempts/{id}"),
    "open": ("POST", "/attempts/{id}/open"),
    "close": ("POST", "/attempts/{id}/close"),
    "final-snapshot": ("POST", "/attempts/{id}/final-snapshot"),
    "finalize": ("POST", "/attempts/{id}/finalize"),
}


def control_command(
    *,
    container_id: str,
    action: str,
    attempt_id: str | None = None,
) -> list[str]:
    """No shell, no arbitrary URL/args, no unreviewed mutation endpoint."""
    if not isinstance(container_id, str) or not _ID.fullmatch(container_id):
        raise ControlUnknown("control container immutable ID missing")
    if action not in _ACTIONS:
        raise ControlUnknown("control action not reviewed")
    if "{id}" in _ACTIONS[action][1] and (
        not isinstance(attempt_id, str) or not _ATTEMPT.fullmatch(attempt_id)
    ):
        raise ControlUnknown("control attempt identity missing")
    if action == "create" and (
        not isinstance(attempt_id, str) or not _ATTEMPT.fullmatch(attempt_id)
    ):
        raise ControlUnknown("control create attempt identity missing")
    method, path = _ACTIONS[action]
    if attempt_id is not None:
        path = path.replace("{id}", attempt_id)
    body = (
        json.dumps({"attempt_id": attempt_id}, separators=(",", ":"))
        if action == "create"
        else "{}"
    )
    return [
        "docker",
        "exec",
        "--user",
        "10001:10001",
        container_id,
        "python",
        "-B",
        "-c",
        FIXED_CONTROL_CLIENT,
        method,
        path,
        body,
    ]


def fixed_control_action(
    *,
    control_container: dict[str, Any],
    owner: str,
    volume: str,
    fixture_image: str,
    control_network_id: str,
    action: str,
    attempt_id: str | None,
    execute: Callable[..., ControlResponse],
    remaining_seconds: float,
) -> dict[str, Any]:
    """Re-attest live control role, then invoke only the reviewed local RPC.

    The outer caller records a durable operation intent before this function.
    An uncertain CLI result must leave that journal open and require recovery.
    """
    try:
        config = control_container["Config"]
        mounts = control_container["Mounts"]
        state = control_container["State"]
        host = control_container["HostConfig"]
        networks = control_container["NetworkSettings"]["Networks"]
        identity = control_container["Id"]
        # Malformed or multiple network attachments never satisfy the control role.
        peer = (
            next(iter(networks.values()))
            if isinstance(networks, dict) and len(networks) == 1
            else None
        )
        if (
            not isinstance(config, dict)
            or not isinstance(mounts, list)
            or not isinstance(host, dict)
            or not isinstance(state, dict)
            or not isinstance(networks, dict)
            or not isinstance(identity, str)
            or not _ID.fullmatch(identity)
            or config.get("Labels", {}).get("mcpbg.p4.owner") != owner
            or config.get("Image") != fixture_image
            or not re.fullmatch(
                r"ghcr\.io/[a-z0-9-]+/[a-z0-9-]+@sha256:[0-9a-f]{64}", fixture_image
            )
            or config.get("User") != "10001:10001"
            or config.get("Entrypoint") not in (None, [])
            or config.get("Cmd")
            != [
                "python",
                "control_service.py",
                "--db",
                "/state/fixture.db",
                "--host",
                "0.0.0.0",
                "--port",
                "9000",
            ]
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or host.get("PublishAllPorts") is not False
            or host.get("PortBindings") not in (None, {})
            or host.get("Binds") not in (None, [])
            or not isinstance(host.get("CapDrop"), list)
            or "ALL" not in host["CapDrop"]
            or not isinstance(host.get("SecurityOpt"), list)
            or "no-new-privileges:true" not in host["SecurityOpt"]
            or not _ID.fullmatch(control_network_id)
            or not isinstance(peer, dict)
            or peer.get("NetworkID") != control_network_id
            or state.get("Running") is not True
            or state.get("Paused") is not False
            or len(networks) != 1
            or len(mounts) != 1
            or not isinstance(mounts[0], dict)
            or mounts[0].get("Type") != "volume"
            or mounts[0].get("Destination") != "/state"
            or mounts[0].get("Name") != volume
            or mounts[0].get("RW") is not True
        ):
            raise ControlUnknown("control container identity or mount mismatch")
        cmd = control_command(container_id=identity, action=action, attempt_id=attempt_id)
        if not isinstance(remaining_seconds, (int, float)) or not 0 < remaining_seconds <= 600:
            raise ControlUnknown("control shared deadline exhausted")
        result = execute(
            cmd, timeout=min(remaining_seconds, 5), output_budget=262144, retained_per_stream=262144
        )
        if (
            not isinstance(result, ControlResponse)
            or result.code != 0
            or type(result.output_bytes) is not int
            or not 0 <= result.output_bytes <= 262144
            or not isinstance(result.stdout, bytes)
            or not isinstance(result.stderr, bytes)
            or len(result.stdout) + len(result.stderr) > result.output_bytes
        ):
            raise ControlUnknown("fixture control CLI is uncertain")
        decoded = _strict_control_object(result.stdout)
        _response_shape(decoded, action=action, attempt_id=attempt_id)
        return decoded
    except (KeyError, IndexError, TypeError, ValueError, OSError) as exc:
        raise ControlUnknown("fixture control operation or identity UNKNOWN") from exc


def audit_evidence_digest(
    *, final_snapshot: dict[str, Any], finalized_attempt: dict[str, Any], attempt_id: str
) -> dict[str, str]:
    """Bind fenced audited evidence to a *separately* confirmed final state.

    The fixture final-snapshot endpoint deliberately returns state FENCED.
    Finalization happens afterward and is verified through GET /attempts/{id}.
    """

    def natural(value: Any) -> bool:
        return type(value) is int and value >= 0

    if not isinstance(final_snapshot, dict) or not isinstance(finalized_attempt, dict):
        raise ControlUnknown("fenced and finalized evidence must be objects")
    record = finalized_attempt.get("attempt")
    requests = final_snapshot.get("requests")
    events = final_snapshot.get("audit")
    final_requests = finalized_attempt.get("requests")
    final_events = finalized_attempt.get("audit")
    if (
        not _ATTEMPT.fullmatch(attempt_id)
        or final_snapshot.get("attempt_id") != attempt_id
        or final_snapshot.get("state") != "FENCED"
        or final_snapshot.get("audit_complete") is not True
        or not natural(final_snapshot.get("final_watermark"))
        or type(requests) is not list
        or type(events) is not list
        or not isinstance(record, dict)
        or record.get("attempt_id") != attempt_id
        or record.get("state") != "FINALIZED"
        or record.get("audit_complete") != 1
        or not natural(record.get("final_watermark"))
        or not natural(record.get("audit_watermark"))
        or not natural(record.get("final_request_count"))
        or type(final_requests) is not list
        or type(final_events) is not list
    ):
        raise ControlUnknown("fenced audit or independently finalized fixture state missing")
    watermark = final_snapshot["final_watermark"]
    if (
        record["final_watermark"] != watermark
        or record["audit_watermark"] != watermark
        or record["final_request_count"] != len(requests)
        or len(requests) != len(final_requests)
        or len(events) != len(final_events)
    ):
        raise ControlUnknown("audit watermark or request count inconsistent")
    # Current FixtureStore uses per-attempt monotonically increasing seq.
    # Never infer count from unrelated/global event IDs.
    seen_events: set[str] = set()
    for ordinal, (event, final_event) in enumerate(zip(events, final_events, strict=True), 1):
        if (
            type(event) is not dict
            or type(final_event) is not dict
            or type(event.get("seq")) is not int
            or type(final_event.get("seq")) is not int
            or event["seq"] != final_event["seq"]
            or event["seq"] != ordinal
            or event.get("event_id") != final_event.get("event_id")
            or not isinstance(event.get("event_id"), str)
            or not event["event_id"]
            or event["event_id"] in seen_events
            or final_event.get("attempt_id") != attempt_id
            or event.get("request_id") != final_event.get("request_id")
        ):
            raise ControlUnknown("fenced audit event identity mismatch")
        seen_events.add(event["event_id"])
    if len(events) != watermark:
        raise ControlUnknown("fenced audit sequence coverage incomplete")
    seen_requests: set[str] = set()
    terminal = {"COMMITTED", "REJECTED", "ROLLED_BACK", "FAILED"}
    for request, final_request in zip(requests, final_requests, strict=True):
        if (
            type(request) is not dict
            or type(final_request) is not dict
            or request.get("attempt_id") != attempt_id
            or final_request.get("attempt_id") != attempt_id
            or request.get("request_id") != final_request.get("request_id")
            or request.get("state") != final_request.get("state")
            or request.get("state") not in terminal
            or not isinstance(request.get("request_id"), str)
            or not request["request_id"]
            or request["request_id"] in seen_requests
        ):
            raise ControlUnknown("fenced request or terminal state mismatch")
        seen_requests.add(request["request_id"])
    for event in events:
        if event["request_id"] not in seen_requests:
            raise ControlUnknown("audited event has no corresponding request")

    def canonical(value: dict[str, Any]) -> bytes:
        try:
            return json.dumps(
                value, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        except (TypeError, ValueError) as exc:
            raise ControlUnknown("fixture evidence JSON invalid") from exc

    return {
        "attempt_id": attempt_id,
        "fenced_snapshot_sha256": hashlib.sha256(canonical(final_snapshot)).hexdigest(),
        "finalized_attempt_sha256": hashlib.sha256(canonical(finalized_attempt)).hexdigest(),
        "source": "trusted_control_container_fixed_rpc",
    }
