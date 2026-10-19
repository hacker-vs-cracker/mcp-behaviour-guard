from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
SRC = CI / "p4_runtime_topology.py"


def module():
    spec = importlib.util.spec_from_file_location("test_p4_runtime_topology", SRC)
    assert spec and spec.loader
    value = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = value
    spec.loader.exec_module(value)
    return value


def peers():
    return {
        key: c * 64
        for key, c in (
            ("candidate", "1"),
            ("evaluator", "2"),
            ("relay", "3"),
            ("fixture-app", "4"),
            ("fixture-control", "5"),
        )
    }


def networks():
    expected = assignments()
    ids = peers()
    return {
        key: dict(
            Id=hexval * 64,
            Labels={"mcpbg.p4.owner": "attempt1"},
            Internal=True,
            Attachable=False,
            Ingress=False,
            Driver="bridge",
            EnableIPv6=False,
            Options={"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
            Containers={ids[role]: {"Name": role} for role in expected[key]},
        )
        for key, hexval in (("subject", "a"), ("fixture", "b"), ("control", "c"))
    }


def assignments():
    return {
        "subject": {"candidate", "evaluator", "relay"},
        "fixture": {"fixture-app", "relay"},
        "control": {"fixture-control"},
    }


def test_network_topology_requires_full_isolation():
    m = module()
    m.verify_network_isolation(
        network_inventory=networks(),
        assigned=assignments(),
        owner="attempt1",
        peer_container_ids=peers(),
    )
    invalid = assignments()
    invalid["subject"].add("fixture-app")
    with pytest.raises(m.P4TopologyError, match="unmetered"):
        m.verify_network_isolation(
            network_inventory=networks(),
            assigned=invalid,
            owner="attempt1",
            peer_container_ids=peers(),
        )
    for key, replacement in (
        ("Internal", False),
        ("Ingress", True),
        ("Attachable", True),
        ("Driver", "host"),
        ("Id", "z" * 64),
    ):
        distorted = networks()
        distorted["subject"][key] = replacement
        with pytest.raises(m.P4TopologyError):
            m.verify_network_isolation(
                network_inventory=distorted,
                assigned=assignments(),
                owner="attempt1",
                peer_container_ids=peers(),
            )
    bypass = networks()
    bypass["subject"]["Containers"][peers()["fixture-app"]] = {"Name": "fixture-app"}
    with pytest.raises(m.P4TopologyError, match="bypass"):
        m.verify_network_isolation(
            network_inventory=bypass,
            assigned=assignments(),
            owner="attempt1",
            peer_container_ids=peers(),
        )
    swapped = networks()
    swapped["fixture"]["Id"] = "a" * 64
    with pytest.raises(m.P4TopologyError):
        m.verify_network_isolation(
            network_inventory=swapped,
            assigned=assignments(),
            owner="attempt1",
            peer_container_ids=peers(),
        )


def relay_case():
    role = json.loads((CI / "p4-relay-role-profile.json").read_text())
    policy = json.loads((CI / "p4-resource-policy.json").read_text())
    image_ref = json.loads((CI / "p3-promoted-authority.json").read_text())["runtime"]["images"][
        "evaluator"
    ]
    program = CI / "p4_metered_fixture_relay.py"
    image = {
        "RepoDigests": [image_ref],
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"Env": ["PATH=/usr/bin", "PYTHONUNBUFFERED=1"]},
    }
    container = {
        "Id": "d" * 64,
        "Config": {
            "Image": image_ref,
            "Entrypoint": role["entrypoint"],
            "Cmd": ["580" if arg == "{remaining_seconds}" else arg for arg in role["argv"]],
            "User": "10003:10003",
            "Env": image["Config"]["Env"],
            "Labels": {"mcpbg.p4.owner": "attempt1"},
        },
        "State": {"Running": False, "Pid": 0},
        "HostConfig": {
            "NetworkMode": "subject-net",
            "Privileged": False,
            "ReadonlyRootfs": True,
            "PublishAllPorts": False,
            "PortBindings": {},
            "Binds": [],
            "Devices": [],
            "CapAdd": [],
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": 268435456,
            "MemorySwap": 268435456,
            "PidsLimit": 64,
            "NanoCpus": 500000000,
        },
        "NetworkSettings": {
            "Networks": {
                "subject-net": {"NetworkID": "a" * 64},
                "fixture-net": {"NetworkID": "b" * 64},
            }
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(program),
                "Destination": role["container_program_target"],
                "RW": False,
            }
        ],
    }
    return dict(
        container=container,
        image=image,
        role=role,
        program=program,
        owner="attempt1",
        image_ref=image_ref,
        subject_network_id="a" * 64,
        fixture_network_id="b" * 64,
        subject_network_name="subject-net",
        fixture_network_name="fixture-net",
        policy=policy,
        expected_remaining_seconds=580,
    )


def test_relay_attests_actual_image_command_identity_network_and_code():
    m = module()
    data = relay_case()
    m.verify_relay_prestart(**data)
    for obj, key, value in (
        ("Config", "Cmd", ["--help"]),
        ("Config", "User", "root"),
        ("Config", "Env", ["AWS_SECRET_ACCESS_KEY=x"]),
        ("HostConfig", "Privileged", True),
        ("HostConfig", "PortBindings", {"8001/tcp": [{"HostPort": "80"}]}),
        ("HostConfig", "Memory", 268435457),
        ("HostConfig", "CapDrop", []),
        ("HostConfig", "SecurityOpt", []),
    ):
        altered = relay_case()
        altered["container"][obj][key] = value
        with pytest.raises(m.P4TopologyError):
            m.verify_relay_prestart(**altered)
    for changed in (
        {"subject_network_id": "b" * 64},
        {"fixture_network_id": "c" * 64},
    ):
        with pytest.raises(m.P4TopologyError):
            m.verify_relay_prestart(**dict(data, **changed))
    role = dict(data["role"], trusted_program_sha256="f" * 64)
    with pytest.raises(m.P4TopologyError):
        m.verify_relay_prestart(**dict(data, role=role))
    data["container"]["Mounts"].append({"Destination": "/var/run/docker.sock"})
    with pytest.raises(m.P4TopologyError):
        m.verify_relay_prestart(**data)


def test_relay_rejects_role_profile_drift_and_wrong_platform():
    m = module()
    for changed in (
        {"control_network": ["trusted-controller", "fixture-control"]},
        {"fixture_network": ["candidate", "fixture-app", "relay"]},
        {"subject_network": ["candidate", "relay"]},
    ):
        props = relay_case()
        props["role"]["network_topology"].update(changed)
        with pytest.raises(m.P4TopologyError, match="network profile"):
            m.verify_relay_prestart(**props)
    for key, value in (("Os", "windows"), ("Architecture", "arm64")):
        props = relay_case()
        props["image"][key] = value
        with pytest.raises(m.P4TopologyError, match="image or containment"):
            m.verify_relay_prestart(**props)


@pytest.mark.parametrize("remaining", [0, -1, 601, True, "600"])
def test_relay_prestart_rejects_untrusted_pipeline_deadline(remaining):
    mod = module()
    params = relay_case()
    params["expected_remaining_seconds"] = remaining
    with pytest.raises(mod.P4TopologyError, match="pipeline deadline"):
        mod.verify_relay_prestart(**params)


def test_relay_prestart_rejects_mismatched_runtime_remaining_seconds():
    mod = module()
    params = relay_case()
    params["expected_remaining_seconds"] = 579
    with pytest.raises(mod.P4TopologyError, match="containment"):
        mod.verify_relay_prestart(**params)


def _dns_endpoints():
    names = {"subject": "s-net", "fixture": "f-net", "control": "c-net"}
    ids = {"subject": "a" * 64, "fixture": "b" * 64, "control": "c" * 64}
    roles = {
        "candidate": {"subject": []},
        "evaluator": {"subject": []},
        "relay": {"subject": ["fixture-app"], "fixture": []},
        "fixture-app": {"fixture": ["fixture-origin"]},
        "fixture-control": {"control": ["fixture-control"]},
    }
    data = {
        role: {
            names[zone]: {"NetworkID": ids[zone], "Aliases": aliases}
            for zone, aliases in zones.items()
        }
        for role, zones in roles.items()
    }
    return {"endpoints": data, "network_ids": ids, "network_names": names}


def test_relay_dns_aliases_preserve_logical_fixture_without_back_routing():
    m = module()
    data = _dns_endpoints()
    m.verify_dns_alias_routing(**data)
    import copy

    for role, zone, aliases in (
        ("candidate", "s-net", ["fixture-app"]),
        ("relay", "s-net", ["fixture-origin"]),
        ("relay", "f-net", ["fixture-app"]),
        ("fixture-app", "f-net", ["fixture-app"]),
        ("fixture-control", "c-net", []),
    ):
        altered = copy.deepcopy(data)
        altered["endpoints"][role][zone]["Aliases"] = aliases
        with pytest.raises(m.P4TopologyError, match="DNS alias"):
            m.verify_dns_alias_routing(**altered)
    altered = copy.deepcopy(data)
    altered["endpoints"]["relay"]["c-net"] = altered["endpoints"]["relay"]["s-net"]
    with pytest.raises(m.P4TopologyError, match="unexpected network"):
        m.verify_dns_alias_routing(**altered)


def test_internal_network_without_isolated_gateway_is_never_accepted():
    m = module()
    for change in (
        {"Options": {}},
        {"Options": {"com.docker.network.bridge.gateway_mode_ipv4": "nat"}},
        {"EnableIPv6": True},
    ):
        altered = networks()
        altered["subject"].update(change)
        with pytest.raises(m.P4TopologyError):
            m.verify_network_isolation(
                network_inventory=altered,
                assigned=assignments(),
                owner="attempt1",
                peer_container_ids=peers(),
            )
