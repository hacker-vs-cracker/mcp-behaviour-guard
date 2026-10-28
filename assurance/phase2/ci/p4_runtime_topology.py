"""Validate effective P4 relay connectivity and identity before any start.

This verifier does not create or start containers. It is the binding that a
separately owned controller must call at the staged runtime boundary.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


class P4TopologyError(ValueError):
    pass


ID = re.compile(r"[0-9a-f]{64}\Z")


def _mapping(obj: object, reason: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise P4TopologyError(reason)
    return obj


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def verify_network_isolation(
    *,
    network_inventory: dict[str, dict[str, Any]],
    assigned: dict[str, set[str]],
    owner: str,
    peer_container_ids: dict[str, str],
    checkpoint: str = "active",
) -> None:
    """Distinguish configured empty networks from post-start active peers.

    A configured checkpoint never asserts that any container has executed.
    Active peers must match every intended role exactly. Neither checkpoint
    authorizes candidate startup without an independently proved barrier.
    """
    expected = {
        "subject": {"candidate", "evaluator", "relay"},
        "fixture": {"fixture-app", "relay"},
        "control": {"fixture-control"},
    }
    if checkpoint not in {"configured", "helpers_active", "active"}:
        raise P4TopologyError("unknown network checkpoint")
    if set(assigned) != set(expected) or any(assigned[k] != v for k, v in expected.items()):
        raise P4TopologyError("unmetered fixture or control network edge")
    if set(network_inventory) != set(expected) or len(network_inventory) != 3:
        raise P4TopologyError("unowned network topology")
    if not isinstance(owner, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", owner):
        raise P4TopologyError("invalid network owner")
    roles = set().union(*expected.values())
    if (
        set(peer_container_ids) != roles
        or any(not _valid_id(ident) for ident in peer_container_ids.values())
        or len(set(peer_container_ids.values())) != len(peer_container_ids)
    ):
        raise P4TopologyError("trusted role container identities missing or reused")
    seen: set[str] = set()
    for key in ("subject", "fixture", "control"):
        network = _mapping(network_inventory[key], "Docker network inspect malformed")
        labels = _mapping(network.get("Labels"), "network owner labels malformed")
        identity = network.get("Id")
        if (
            not isinstance(identity, str)
            or not _valid_id(identity)
            or identity in seen
            or labels.get("mcpbg.p4.owner") != owner
            or network.get("Internal") is not True
            or network.get("Attachable") is not False
            or network.get("Ingress") is not False
            or network.get("Driver") != "bridge"
            or network.get("EnableIPv6") is not False
            or not isinstance(network.get("Options"), dict)
            or network["Options"].get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated"
        ):
            raise P4TopologyError("effective network is not private and attempt-owned")
        peers = _mapping(network.get("Containers"), "network peer inventory missing")
        actual_ids = set(peers)
        intended_ids = {peer_container_ids[role] for role in expected[key]}
        if checkpoint == "configured":
            if actual_ids:
                raise P4TopologyError("created network has a premature active peer")
        elif checkpoint == "helpers_active":
            # The candidate remains stopped and may not appear as an active
            # network peer. No sixth role or early candidate peer is allowed.
            helper_ids = {peer_container_ids[role] for role in expected[key] - {"candidate"}}
            if actual_ids != helper_ids:
                raise P4TopologyError("helper-only network has unexpected or missing peer")
        elif actual_ids != intended_ids:
            raise P4TopologyError("effective network contains bypass or missing role")
        for peer_id, peer in peers.items():
            if not _valid_id(peer_id) or not isinstance(peer, dict):
                raise P4TopologyError("network peer identity malformed")
        seen.add(identity)


def verify_relay_prestart(
    *,
    container: dict[str, Any],
    image: dict[str, Any],
    role: dict[str, Any],
    program: Path,
    owner: str,
    image_ref: str,
    subject_network_id: str,
    fixture_network_id: str,
    subject_network_name: str,
    fixture_network_name: str,
    policy: dict[str, Any],
    expected_remaining_seconds: int,
) -> None:
    """Pin image, code, effective command/user/env/mounts and two-network fence."""
    configuration = _mapping(container.get("Config"), "relay config missing")
    host = _mapping(container.get("HostConfig"), "relay host limits missing")
    state = _mapping(container.get("State"), "relay process state missing")
    connections = _mapping(container.get("NetworkSettings"), "relay peers missing")
    networks = _mapping(connections.get("Networks"), "relay networks missing")
    img_cfg = _mapping(image.get("Config"), "resolved relay base image missing")
    limits = _mapping(
        _mapping(policy.get("limits"), "limits missing").get("docker_runtime"),
        "docker limits missing",
    )
    expected_roles = {
        "subject_network": ["candidate", "evaluator", "relay"],
        "fixture_network": ["fixture-app", "relay"],
        "control_network": ["fixture-control"],
        "max_networks": 3,
    }
    if role.get("network_topology") != expected_roles:
        raise P4TopologyError("relay role network profile does not match verified topology")
    if (
        type(expected_remaining_seconds) is not int
        or not 0 < expected_remaining_seconds <= 600
        or role.get("argv")
        != [
            "/trusted/p4_metered_fixture_relay.py",
            "--upstream-host",
            "fixture-origin",
            "--upstream-port",
            "8001",
            "--listen-port",
            "8001",
            "--remaining-seconds",
            "{remaining_seconds}",
        ]
    ):
        raise P4TopologyError("relay pipeline deadline is not bound")
    approved_cmd = [
        str(expected_remaining_seconds) if arg == "{remaining_seconds}" else arg
        for arg in role["argv"]
    ]
    labels = _mapping(configuration.get("Labels"), "relay owner missing")
    if (
        role.get("name") != "p4-metered-relay-role-v1"
        or role.get("p3_evaluator_role_inheritance") is not False
        or role.get("runtime_execution_enabled") is not False
        or role.get("public_ports") is not False
        or not _valid_id(container.get("Id"))
        or labels.get("mcpbg.p4.owner") != owner
        or configuration.get("Image") != image_ref
        or image_ref not in image.get("RepoDigests", [])
        or image.get("Os") != "linux"
        or image.get("Architecture") != "amd64"
        or configuration.get("Entrypoint") != role.get("entrypoint")
        or configuration.get("Cmd") != approved_cmd
        or configuration.get("User") != "10003:10003"
        or configuration.get("Env") != img_cfg.get("Env")
        or state.get("Running") is not False
        or state.get("Pid") not in (None, 0)
        or host.get("Privileged") is not False
        or host.get("ReadonlyRootfs") is not True
        or host.get("PublishAllPorts") is not False
        or host.get("PortBindings") not in (None, {})
        or host.get("Binds") not in (None, [])
        or host.get("Devices") not in (None, [])
        or host.get("CapAdd") not in (None, [])
        or not isinstance(host.get("CapDrop"), list)
        or "ALL" not in host["CapDrop"]
        or not isinstance(host.get("SecurityOpt"), list)
        or "no-new-privileges:true" not in host["SecurityOpt"]
        or host.get("NetworkMode") not in networks
        or host.get("Memory") != limits.get("memory_bytes")
        or host.get("MemorySwap") != limits.get("memory_bytes")
        or host.get("PidsLimit") != limits.get("pids_limit")
        or host.get("NanoCpus") != limits.get("nano_cpus")
    ):
        raise P4TopologyError("relay program, effective image or containment differs")
    if (
        not _valid_id(subject_network_id)
        or not _valid_id(fixture_network_id)
        or subject_network_id == fixture_network_id
        or len(networks) != 2
        or not isinstance(subject_network_name, str)
        or not isinstance(fixture_network_name, str)
        or subject_network_name == fixture_network_name
        or set(networks) != {subject_network_name, fixture_network_name}
        or not isinstance(networks[subject_network_name], dict)
        or not isinstance(networks[fixture_network_name], dict)
        or networks[subject_network_name].get("NetworkID") != subject_network_id
        or networks[fixture_network_name].get("NetworkID") != fixture_network_id
    ):
        raise P4TopologyError("relay missing isolated subject/fixture network")
    mounts = container.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 1:
        raise P4TopologyError("relay has unexpected mounts")
    mount = _mapping(mounts[0], "relay program mount malformed")
    if program.is_symlink() or not program.is_file() or not program.is_absolute():
        raise P4TopologyError("trusted relay program must be an exact regular path")
    code_path = role.get("container_program_target")
    if (
        mount.get("Type") != "bind"
        or mount.get("RW") is not False
        or mount.get("Destination") != code_path
        or mount.get("Source") != str(program)
        or role.get("trusted_program_sha256") != hashlib.sha256(program.read_bytes()).hexdigest()
    ):
        raise P4TopologyError("relay code mount differs from approved bytes")


def verify_dns_alias_routing(
    *,
    endpoints: dict[str, dict[str, Any]],
    network_ids: dict[str, str],
    network_names: dict[str, str],
) -> None:
    """Bind Docker's effective per-container aliases to the metered data path.

    Subject code keeps the historical `fixture-app` origin, but Docker DNS
    routes it to the relay. The relay uses `fixture-origin` on its other
    network to prevent DNS self-resolution. No control alias may leak.
    """
    expected = {
        "candidate": {"subject"},
        "evaluator": {"subject"},
        "relay": {"subject", "fixture"},
        "fixture-app": {"fixture"},
        "fixture-control": {"control"},
    }
    reserved = {"fixture-app", "fixture-origin", "fixture-control"}
    authorized = {
        ("relay", "subject"): {"fixture-app"},
        ("fixture-app", "fixture"): {"fixture-origin"},
        ("fixture-control", "control"): {"fixture-control"},
    }
    if (
        not isinstance(endpoints, dict)
        or set(endpoints) != set(expected)
        or not isinstance(network_ids, dict)
        or set(network_ids) != {"subject", "fixture", "control"}
        or not isinstance(network_names, dict)
        or set(network_names) != set(network_ids)
        or len(set(network_names.values())) != 3
        or len(set(network_ids.values())) != 3
        or any(not _valid_id(identity) for identity in network_ids.values())
    ):
        raise P4TopologyError("trusted DNS network inventory incomplete")
    for role, networks in expected.items():
        effective = _mapping(endpoints[role], "effective Docker endpoints missing")
        intended_names = {network_names[network] for network in networks}
        if set(effective) != intended_names:
            raise P4TopologyError("unexpected network joined by trusted role")
        for network in networks:
            name = network_names[network]
            endpoint = _mapping(effective[name], "effective Docker network missing")
            aliases = endpoint.get("Aliases")
            if (
                endpoint.get("NetworkID") != network_ids[network]
                or not isinstance(aliases, list)
                or any(not isinstance(alias, str) or not alias for alias in aliases)
                or len(aliases) != len(set(aliases))
                or set(aliases) & reserved != authorized.get((role, network), set())
            ):
                raise P4TopologyError("Docker DNS alias could bypass relay or self-resolve")


def attest_owned_prestart_graph(
    *,
    attempt: Any,
    networks: dict[str, Any],
    containers: dict[str, Any],
    volumes: dict[str, Any],
    expected_images: dict[str, str],
    relay_profile: dict[str, Any],
    role_profiles: dict[str, Any],
    relay_program: Path,
    remaining_seconds: int,
) -> dict[str, Any]:
    """Read back five *created, not started* roles from the admitted Engine.

    Only existing owned resources are inspected; this never creates, attaches,
    starts, or deletes containers. Every read is charged to the attempt's shared
    deadline and output meter by its pinned Engine caller. An incomplete readback
    is UNKNOWN, not permission to start. Source acceptance is not physical proof.
    """
    import p4_resource_enforcement as bounds
    from p4_effective_profiles import attest_effective_profiles
    from p4_scoped_engine import ScopedEngineRunner

    role_nets = {
        "candidate": {"subject"},
        "evaluator": {"subject"},
        "relay": {"subject", "fixture"},
        "fixture-app": {"fixture"},
        "fixture-control": {"control"},
    }
    allowed_nets = {"subject", "fixture", "control"}
    try:
        if (
            getattr(attempt, "_entered", False) is not True
            or not isinstance(getattr(attempt, "run", None), ScopedEngineRunner)
            or getattr(attempt, "recovery_required", False) is not False
            or getattr(attempt, "attempt_deadline", None) is None
            or set(networks) != allowed_nets
            or set(volumes) != {"fixture", "evaluator"}
            or set(containers) != set(role_nets)
            or set(expected_images) != set(role_nets)
            or not isinstance(relay_profile, dict)
            or not isinstance(role_profiles, dict)
            or type(remaining_seconds) is not int
            or not 0 < remaining_seconds <= 600
        ):
            raise P4TopologyError("complete owned private Engine graph required")
        inventory = list(getattr(attempt, "items", []))
        kinds = [getattr(item, "kind", None) for item in inventory]
        if (
            len(inventory) != 10
            or any(type(kind) is not str for kind in kinds)
            or kinds.count("network") != 3
            or kinds.count("container") != 5
            or kinds.count("volume") != 2
        ):
            raise P4TopologyError("unexpected attempt-owned resource inventory")
        owned = []
        for kind, assignments in (("network", networks), ("container", containers)):
            for item in assignments.values():
                if (
                    not any(entry is item for entry in inventory)
                    or getattr(item, "kind", None) != kind
                    or getattr(item, "state", None) != "CREATED"
                    or not _valid_id(getattr(item, "object_id", None))
                    or not isinstance(getattr(item, "name", None), str)
                    or not item.name.startswith("mcpbg-p4-" + attempt.attempt_id + "-")
                ):
                    raise P4TopologyError("unowned or unconfirmed graph resource")
                owned.append(item.object_id)
        if volumes["fixture"] is volumes["evaluator"] or any(
            not any(entry is item for entry in inventory)
            or getattr(item, "kind", None) != "volume"
            or getattr(item, "state", None) != "CREATED"
            or getattr(item, "object_id", None) != getattr(item, "name", None)
            or not isinstance(getattr(item, "name", None), str)
            or not item.name.startswith("mcpbg-p4-" + attempt.attempt_id + "-")
            or not getattr(item, "artifact_tmpfs_attested", False)
            or getattr(item, "artifact_owner_uid", None) != (10001 if name == "fixture" else 10003)
            for name, item in volumes.items()
        ):
            raise P4TopologyError("two separately attested owned volumes required")
        snapshot = [
            (id(item), item.kind, item.name, item.object_id, item.state) for item in inventory
        ]
        if len(set(owned)) != 8 or any(
            not isinstance(x, str)
            or re.fullmatch(r"(?:sha256:|[a-z0-9._/:\-]+@sha256:)[0-9a-f]{64}", x) is None
            for x in expected_images.values()
        ):
            raise P4TopologyError("duplicated resource or missing exact image binding")
        shape = bounds._mapping(attempt.policy.get("json_intake"), "JSON intake")
        max_bytes = bounds._positive_int(shape.get("max_bytes"), "JSON max_bytes")
        runtime = bounds._limits(attempt.policy, "docker_runtime")

        def inspect(kind: str, object_id: str) -> dict[str, Any]:
            result = attempt._checked_call(
                ["docker", kind, "inspect", "--format", "{{json .}}", object_id],
                structured=True,
            )
            if result.exit_code != 0 or not result.stdout:
                raise P4TopologyError("private Engine inventory missing")
            return bounds._load_object_bytes(
                result.stdout,
                max_bytes=max_bytes,
                label="P4 effective Engine inventory",
                shape=shape,
            )

        net_inventory = {key: inspect("network", item.object_id) for key, item in networks.items()}
        role_inventory = {
            role: inspect("container", item.object_id) for role, item in containers.items()
        }
        ids = {role: item.object_id for role, item in containers.items()}
        names = {key: item.name for key, item in networks.items()}
        net_ids = {key: item.object_id for key, item in networks.items()}
        for key, obj in net_inventory.items():
            if obj.get("Id") != net_ids[key] or obj.get("Name") != names[key]:
                raise P4TopologyError("network name or identity drift")
        verify_network_isolation(
            network_inventory=net_inventory,
            assigned={
                key: {role for role, edges in role_nets.items() if key in edges}
                for key in allowed_nets
            },
            owner=attempt.attempt_id,
            peer_container_ids=ids,
        )
        endpoints: dict[str, dict[str, Any]] = {}
        for role, obj in role_inventory.items():
            config = _mapping(obj.get("Config"), "effective role config missing")
            host = _mapping(obj.get("HostConfig"), "effective role host missing")
            state = _mapping(obj.get("State"), "effective role state missing")
            labels = _mapping(config.get("Labels"), "effective role owner missing")
            nsetting = _mapping(obj.get("NetworkSettings"), "effective role networks missing")
            endpoint = _mapping(nsetting.get("Networks"), "effective role endpoints missing")
            if (
                obj.get("Id") != ids[role]
                or obj.get("Name") != "/" + containers[role].name
                or labels.get("mcpbg.p4.owner") != attempt.attempt_id
                or config.get("Image") != expected_images[role]
                or state.get("Running") is not False
                or state.get("Pid") not in (0, None)
                or state.get("Restarting") is True
                or host.get("Privileged") is not False
                or host.get("ReadonlyRootfs") is not True
                or host.get("Memory") != runtime["memory_bytes"]
                or host.get("MemorySwap") != runtime["memory_bytes"]
                or host.get("PidsLimit") != runtime["pids_limit"]
                or host.get("NanoCpus") != runtime["nano_cpus"]
                or host.get("NetworkMode") not in endpoint
                or host.get("PublishAllPorts") is not False
                or host.get("PortBindings") not in (None, {})
                or host.get("CapAdd") not in (None, [])
                or not isinstance(host.get("CapDrop"), list)
                or "ALL" not in host["CapDrop"]
                or not isinstance(host.get("SecurityOpt"), list)
                or "no-new-privileges:true" not in host["SecurityOpt"]
                or host.get("Devices") not in (None, [])
                or (role != "relay" and host.get("Binds") not in (None, []))
            ):
                raise P4TopologyError("effective role identity, isolation or prestart drift")
            mounts = obj.get("Mounts")
            expected_mount = {
                "candidate": {},
                "relay": None,
                "evaluator": {"/trusted-output": volumes["evaluator"].name},
                "fixture-app": {"/state": volumes["fixture"].name},
                "fixture-control": {"/state": volumes["fixture"].name},
            }[role]
            if role == "candidate" and mounts not in (None, []):
                raise P4TopologyError("candidate acquired unexpected mount")
            if expected_mount is not None:
                if not isinstance(mounts, list) or len(mounts) != len(expected_mount):
                    raise P4TopologyError("owned role mount inventory incomplete")
                if any(
                    not isinstance(m, dict)
                    or m.get("Type") != "volume"
                    or m.get("Destination") not in expected_mount
                    or m.get("Name") != expected_mount[m["Destination"]]
                    or m.get("RW") is not True
                    for m in mounts
                ):
                    raise P4TopologyError("effective role volume mount bypass")
            endpoints[role] = endpoint
        verify_dns_alias_routing(endpoints=endpoints, network_ids=net_ids, network_names=names)
        image_inventory = {role: inspect("image", ref) for role, ref in expected_images.items()}
        profile_digest = attest_effective_profiles(
            profiles=role_profiles,
            inspections=role_inventory,
            image_inspections=image_inventory,
            expected_images=expected_images,
        )
        relay_image = image_inventory["relay"]
        verify_relay_prestart(
            container=role_inventory["relay"],
            image=relay_image,
            role=relay_profile,
            program=relay_program,
            owner=attempt.attempt_id,
            image_ref=expected_images["relay"],
            subject_network_id=net_ids["subject"],
            fixture_network_id=net_ids["fixture"],
            subject_network_name=names["subject"],
            fixture_network_name=names["fixture"],
            policy=attempt.policy,
            expected_remaining_seconds=remaining_seconds,
        )
        if (
            snapshot
            != [(id(item), item.kind, item.name, item.object_id, item.state) for item in inventory]
            or getattr(attempt, "recovery_required", False) is not False
        ):
            raise P4TopologyError("owned inventory drifted during multi-read attestation")
        return {
            "status": "FIVE_ROLE_PRESTART_READBACK_SOURCE_ONLY",
            "roles": ids,
            "networks": net_ids,
            "volumes": {name: item.name for name, item in volumes.items()},
            "effective_profiles_sha256": profile_digest,
            "runtime_execution_proven": False,
            "worker_cleanup_proven": False,
            "all_writers_fenced": False,
        }
    except Exception as exc:
        if getattr(attempt, "_entered", False) is True:
            attempt.recovery_required = True
        if isinstance(exc, P4TopologyError):
            raise
        raise P4TopologyError("owned Engine prestart readback UNKNOWN") from exc
