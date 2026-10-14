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


class ControlUnknown(RuntimeError):
    pass


_ID = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")

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
            or next(iter(networks.values()), {}).get("NetworkID") != control_network_id
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
        decoded = json.loads(result.stdout)
        if not isinstance(decoded, dict):
            raise ControlUnknown("fixture control response invalid")
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
    if (
        not isinstance(final_snapshot, dict)
        or final_snapshot.get("attempt_id") != attempt_id
        or final_snapshot.get("state") != "FENCED"
        or final_snapshot.get("audit_complete") is not True
        or type(final_snapshot.get("final_watermark")) is not int
        or not isinstance(final_snapshot.get("requests"), list)
        or not isinstance(final_snapshot.get("audit"), list)
        or not isinstance(finalized_attempt, dict)
        or not isinstance(finalized_attempt.get("attempt"), dict)
        or finalized_attempt["attempt"].get("attempt_id") != attempt_id
        or finalized_attempt["attempt"].get("state") != "FINALIZED"
        or finalized_attempt["attempt"].get("audit_complete") != 1
    ):
        raise ControlUnknown("fenced audit or independently finalized fixture state missing")

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
