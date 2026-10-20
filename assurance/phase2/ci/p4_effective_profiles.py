"""Strict, source-only five-role effective Engine execution profile checks.

Expected profiles must come from reviewed controller source, never from Engine
inspection or candidate output. This is not a live startup or producer proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


class ProfileMismatch(ValueError):
    """A role differs from its reviewed immutable effective configuration."""


_ROLES = frozenset({"candidate", "evaluator", "relay", "fixture-app", "fixture-control"})
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REF = re.compile(r"(?:sha256:|[a-z0-9._/:-]+@sha256:)[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class RoleExecutionProfile:
    """Exact per-role expected values, with no defaults inferred from inspect."""

    role: str
    requested_image: str
    resolved_image_id: str
    user: str
    entrypoint: tuple[str, ...]
    command: tuple[str, ...]
    environment: tuple[str, ...]
    workdir: str
    pid_mode: str
    ipc_mode: str
    logging_driver: str
    logging_options: tuple[tuple[str, str], ...]
    tmpfs: tuple[tuple[str, str], ...]
    cap_drop: tuple[str, ...]
    security_options: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            self.role not in _ROLES
            or not isinstance(self.requested_image, str)
            or not isinstance(self.resolved_image_id, str)
            or not _IMAGE.fullmatch(self.resolved_image_id)
            or not _REF.fullmatch(self.requested_image)
            or type(self.user) is not str
            or not self.user
            or type(self.workdir) is not str
            or not self.workdir.startswith("/")
            or self.pid_mode not in {"", "private"}
            or self.ipc_mode not in {"", "private"}
            or self.logging_driver != "local"
            or self.cap_drop != ("ALL",)
            or self.security_options != ("no-new-privileges:true",)
        ):
            raise ProfileMismatch("invalid reviewed role profile")
        for values in (self.entrypoint, self.command, self.environment):
            if type(values) is not tuple or any(type(x) is not str for x in values):
                raise ProfileMismatch("role argv/env must be immutable strings")
        if not self.entrypoint or any(not x or "\0" in x for x in self.entrypoint):
            raise ProfileMismatch("role entrypoint invalid")
        for pairs in (self.logging_options, self.tmpfs):
            if (
                type(pairs) is not tuple
                or any(
                    type(x) is not tuple or len(x) != 2 or any(type(v) is not str for v in x)
                    for x in pairs
                )
                or len(set(k for k, _ in pairs)) != len(pairs)
            ):
                raise ProfileMismatch("role options must be immutable unique pairs")


def attest_effective_profiles(
    *,
    profiles: dict[str, RoleExecutionProfile],
    inspections: dict[str, dict[str, Any]],
    image_inspections: dict[str, dict[str, Any]],
    expected_images: dict[str, str],
) -> str:
    """Fail on a single differing execution setting; return canonical profile SHA.

    Immutable inputs are a caller obligation. No claim of provenance or physical
    runtime isolation is made here. No role is exempt, including the relay.
    """
    if (
        set(profiles) != _ROLES
        or set(inspections) != _ROLES
        or set(image_inspections) != _ROLES
        or set(expected_images) != _ROLES
    ):
        raise ProfileMismatch("five complete role profiles required")
    canonical: dict[str, Any] = {}
    for role in sorted(_ROLES):
        profile = profiles[role]
        if type(profile) is not RoleExecutionProfile or profile.role != role:
            raise ProfileMismatch("foreign or mutable role profile")
        container = inspections[role]
        image = image_inspections[role]
        config = container.get("Config")
        host = container.get("HostConfig")
        if not isinstance(config, dict) or not isinstance(host, dict):
            raise ProfileMismatch("effective role inspect incomplete")
        log = host.get("LogConfig")
        if not isinstance(log, dict):
            raise ProfileMismatch("effective logging config absent")
        checks = (
            expected_images[role] == profile.requested_image,
            config.get("Image") == profile.requested_image,
            container.get("Image") == profile.resolved_image_id,
            image.get("Id") == profile.resolved_image_id,
            profile.requested_image in image.get("RepoDigests", []),
            image.get("Os") == "linux",
            image.get("Architecture") == "amd64",
            config.get("User") == profile.user,
            config.get("Entrypoint") == list(profile.entrypoint),
            config.get("Cmd") == list(profile.command),
            config.get("Env") == list(profile.environment),
            config.get("WorkingDir") == profile.workdir,
            config.get("ExposedPorts") in (None, {}),
            host.get("PidMode") == profile.pid_mode,
            host.get("IpcMode") == profile.ipc_mode,
            log.get("Type") == profile.logging_driver,
            log.get("Config") == dict(profile.logging_options),
            host.get("Tmpfs") == dict(profile.tmpfs),
            host.get("CapDrop") == list(profile.cap_drop),
            host.get("SecurityOpt") == list(profile.security_options),
            host.get("PortBindings") in (None, {}),
            host.get("PublishAllPorts") is False,
            host.get("Privileged") is False,
            host.get("ReadonlyRootfs") is True,
            host.get("CapAdd") in (None, []),
            host.get("Devices") in (None, []),
            host.get("UsernsMode") in (None, ""),
            host.get("CgroupnsMode") in (None, "private"),
            host.get("UTSMode") in (None, ""),
            host.get("ExtraHosts") in (None, []),
            host.get("Dns") in (None, []),
        )
        if not all(checks):
            raise ProfileMismatch(f"effective role profile drift: {role}")
        canonical[role] = {
            "image": profile.requested_image,
            "image_id": profile.resolved_image_id,
            "user": profile.user,
            "entrypoint": profile.entrypoint,
            "command": profile.command,
            "environment": profile.environment,
            "workdir": profile.workdir,
            "pid": profile.pid_mode,
            "ipc": profile.ipc_mode,
            "log": (profile.logging_driver, profile.logging_options),
            "tmpfs": profile.tmpfs,
            "cap_drop": profile.cap_drop,
            "security": profile.security_options,
        }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
