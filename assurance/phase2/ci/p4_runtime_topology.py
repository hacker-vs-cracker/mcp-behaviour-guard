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
) -> None:
    """Reject bypass edges and public/foreign networks, not merely route names."""
    expected = {
        "subject": {"candidate", "evaluator", "relay"},
        "fixture": {"fixture-app", "relay"},
        "control": {"fixture-control"},
    }
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
        if actual_ids != intended_ids:
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
