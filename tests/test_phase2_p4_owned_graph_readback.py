"""Offline composition tests; never contact or create Docker resources."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
sys.path.insert(0, str(CI))


def module():
    spec = importlib.util.spec_from_file_location("test_owned_graph", CI / "p4_runtime_topology.py")
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def mock_attempt():
    from p4_effective_profiles import RoleExecutionProfile
    from p4_scoped_engine import EngineBinding, ScopedEngineRunner

    roles = {
        "candidate": "1",
        "evaluator": "2",
        "relay": "3",
        "fixture-app": "4",
        "fixture-control": "5",
    }
    nets = {"subject": "a", "fixture": "b", "control": "c"}
    membership = {
        "candidate": {"subject"},
        "evaluator": {"subject"},
        "relay": {"subject", "fixture"},
        "fixture-app": {"fixture"},
        "fixture-control": {"control"},
    }
    owner = "attempt1"
    networks = {
        k: SimpleNamespace(
            kind="network", name=f"mcpbg-p4-{owner}-net-{k}", state="CREATED", object_id=v * 64
        )
        for k, v in nets.items()
    }
    containers = {
        k: SimpleNamespace(
            kind="container", name=f"mcpbg-p4-{owner}-role-{k}", state="CREATED", object_id=v * 64
        )
        for k, v in roles.items()
    }
    volumes = {
        "fixture": SimpleNamespace(
            kind="volume",
            name="mcpbg-p4-attempt1-vol-1",
            state="CREATED",
            object_id="mcpbg-p4-attempt1-vol-1",
            artifact_tmpfs_attested=True,
            artifact_owner_uid=10001,
        ),
        "evaluator": SimpleNamespace(
            kind="volume",
            name="mcpbg-p4-attempt1-vol-2",
            state="CREATED",
            object_id="mcpbg-p4-attempt1-vol-2",
            artifact_tmpfs_attested=True,
            artifact_owner_uid=10003,
        ),
    }
    images = {k: "sha256:" + v * 64 for k, v in roles.items()}
    runtime = json.loads((CI / "p4-resource-policy.json").read_text())["limits"]["docker_runtime"]
    rows = {}
    for key, item in networks.items():
        rows[("network", item.object_id)] = {
            "Id": item.object_id,
            "Name": item.name,
            "Labels": {"mcpbg.p4.owner": owner},
            "Internal": True,
            "Attachable": False,
            "Ingress": False,
            "Driver": "bridge",
            "EnableIPv6": False,
            "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
            "Containers": {
                containers[r].object_id: {"Name": containers[r].name}
                for r in membership
                if key in membership[r]
            },
        }
    reserved = {
        ("relay", "subject"): ["fixture-app"],
        ("fixture-app", "fixture"): ["fixture-origin"],
        ("fixture-control", "control"): ["fixture-control"],
    }
    profiles = {}
    for role, item in containers.items():
        eps = {
            networks[k].name: {
                "NetworkID": networks[k].object_id,
                "Aliases": reserved.get((role, k), []),
            }
            for k in membership[role]
        }
        mounts = {
            "candidate": [],
            "relay": [
                {
                    "Type": "bind",
                    "RW": False,
                    "Destination": "/trusted/p4_metered_fixture_relay.py",
                    "Source": "/tmp/readonly-relay",
                }
            ],
            "evaluator": [
                {
                    "Type": "volume",
                    "Name": volumes["evaluator"].name,
                    "Destination": "/trusted-output",
                    "RW": True,
                }
            ],
            "fixture-app": [
                {
                    "Type": "volume",
                    "Name": volumes["fixture"].name,
                    "Destination": "/state",
                    "RW": True,
                }
            ],
            "fixture-control": [
                {
                    "Type": "volume",
                    "Name": volumes["fixture"].name,
                    "Destination": "/state",
                    "RW": True,
                }
            ],
        }[role]
        user = (
            "10002:10002"
            if role == "candidate"
            else ("10003:10003" if role in {"relay", "evaluator"} else "10001:10001")
        )
        entrypoint = ["python", "-B"]
        command = ["/trusted/fixed-" + role + ".py"]
        env = ["LANG=C"]
        workdir = "/work"
        profiles[role] = RoleExecutionProfile(
            role=role,
            requested_image=images[role],
            resolved_image_id=images[role],
            user=user,
            entrypoint=tuple(entrypoint),
            command=tuple(command),
            environment=tuple(env),
            workdir=workdir,
            pid_mode="",
            ipc_mode="private",
            logging_driver="local",
            logging_options=(("max-file", "2"), ("max-size", "1m")),
            tmpfs=(("/tmp", "rw,nosuid,nodev,size=16777216"),),
            cap_drop=("ALL",),
            security_options=("no-new-privileges:true",),
        )
        rows[("container", item.object_id)] = {
            "Mounts": mounts,
            "Id": item.object_id,
            "Name": "/" + item.name,
            "Config": {
                "Labels": {"mcpbg.p4.owner": owner},
                "Image": images[role],
                "User": user,
                "Entrypoint": entrypoint,
                "Cmd": command,
                "Env": env,
                "WorkingDir": workdir,
            },
            "Image": images[role],
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Memory": runtime["memory_bytes"],
                "MemorySwap": runtime["memory_bytes"],
                "PidsLimit": runtime["pids_limit"],
                "NanoCpus": runtime["nano_cpus"],
                "NetworkMode": next(iter(eps)),
                "PublishAllPorts": False,
                "PortBindings": {},
                "Binds": None,
                "Devices": None,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "PidMode": "",
                "IpcMode": "private",
                "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "2"}},
                "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=16777216"},
            },
            "State": {"Running": False, "Pid": 0, "Restarting": False},
            "NetworkSettings": {"Networks": eps},
        }
    for image_id in images.values():
        rows[("image", image_id)] = {
            "Id": image_id,
            "RepoDigests": [image_id],
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Env": ["LANG=C"]},
        }
    calls = []

    def checked(args, **_kw):
        calls.append(tuple(args))
        try:
            content = rows[(args[1], args[-1])]
        except KeyError:
            return SimpleNamespace(exit_code=1, stdout=b"", stderr=b"no object")
        return SimpleNamespace(
            exit_code=0, stdout=json.dumps(content, sort_keys=True).encode(), stderr=b""
        )

    runner = ScopedEngineRunner(EngineBinding("unix:///run/mcpbg-p4-a/engine.sock", "e" * 64, 1, 2))
    attempt = SimpleNamespace(
        _entered=True,
        run=runner,
        recovery_required=False,
        attempt_deadline=object(),
        attempt_id=owner,
        items=[*networks.values(), *containers.values(), *volumes.values()],
        policy=json.loads((CI / "p4-resource-policy.json").read_text()),
        _checked_call=checked,
        role_profiles=profiles,
    )
    return attempt, networks, containers, volumes, images, rows, calls


def check(m, a, networks, roles, volumes, images):
    return m.attest_owned_prestart_graph(
        attempt=a,
        networks=networks,
        containers=roles,
        volumes=volumes,
        expected_images=images,
        relay_profile={},
        role_profiles=a.role_profiles,
        relay_program=Path("/tmp/readonly-relay"),
        remaining_seconds=300,
    )


def test_complete_readback_invokes_all_verified_boundaries(monkeypatch):
    m = module()
    a, networks, roles, volumes, images, _, calls = mock_attempt()
    invoked = []
    monkeypatch.setattr(m, "verify_relay_prestart", lambda **kw: invoked.append(kw))
    result = check(m, a, networks, roles, volumes, images)
    assert result["status"] == "FIVE_ROLE_PRESTART_READBACK_SOURCE_ONLY"
    assert result["runtime_execution_proven"] is False
    assert len(calls) == 13  # 3 network, 5 container, 5 exact resolved images
    assert invoked and invoked[0]["container"]["Id"] == roles["relay"].object_id
    assert a.recovery_required is False


@pytest.mark.parametrize(
    "tamper",
    [
        "network_public",
        "network_outsider",
        "candidate_control_edge",
        "wrong_alias",
        "started",
        "wrong_image",
        "privileged",
        "foreign_owner",
        "missing_inventory",
        "malformed_json",
        "relay_drift",
        "duplicate_object",
        "foreign_item",
        "ambiguous_result",
        "mount_bypass",
        "volume_foreign",
        "volume_reuse",
        "wrong_limits",
        "unbound_image",
        "foreign_volume_name",
        "extra_item",
        "mid_read_drift",
    ],
)
def test_rejects_partial_or_bypassed_prestart_graph(monkeypatch, tamper):
    m = module()
    a, networks, roles, volumes, images, rows, _ = mock_attempt()
    monkeypatch.setattr(
        m,
        "verify_relay_prestart",
        lambda **kw: (
            (_ for _ in ()).throw(m.P4TopologyError("relay drift"))
            if tamper == "relay_drift"
            else None
        ),
    )
    if tamper == "network_public":
        rows[("network", networks["subject"].object_id)]["Internal"] = False
    elif tamper == "network_outsider":
        rows[("network", networks["subject"].object_id)]["Containers"]["9" * 64] = {}
    elif tamper == "candidate_control_edge":
        rows[("container", roles["candidate"].object_id)]["NetworkSettings"]["Networks"][
            networks["control"].name
        ] = {"NetworkID": networks["control"].object_id, "Aliases": []}
    elif tamper == "wrong_alias":
        rows[("container", roles["candidate"].object_id)]["NetworkSettings"]["Networks"][
            networks["subject"].name
        ]["Aliases"] = ["fixture-app"]
    elif tamper == "started":
        rows[("container", roles["candidate"].object_id)]["State"]["Running"] = True
    elif tamper == "wrong_image":
        rows[("container", roles["evaluator"].object_id)]["Config"]["Image"] = "untrusted"
    elif tamper == "privileged":
        rows[("container", roles["candidate"].object_id)]["HostConfig"]["Privileged"] = True
    elif tamper == "foreign_owner":
        rows[("container", roles["candidate"].object_id)]["Config"]["Labels"]["mcpbg.p4.owner"] = (
            "other"
        )
    elif tamper == "missing_inventory":
        del rows[("network", networks["fixture"].object_id)]
    elif tamper == "malformed_json":

        def invalid(_args):
            return SimpleNamespace(exit_code=0, stdout=b'{"x":1,"x":2}', stderr=b"")

        a._checked_call = invalid
    elif tamper == "duplicate_object":
        roles["candidate"].object_id = roles["evaluator"].object_id
    elif tamper == "foreign_item":
        roles["candidate"] = copy.copy(roles["candidate"])
    elif tamper == "unbound_image":
        images["candidate"] = "mutable:latest"
    elif tamper == "mid_read_drift":
        previous = a._checked_call
        counts = [0]

        def drift(args, **_kw):
            counts[0] += 1
            if counts[0] == 3:
                roles["candidate"].state = "UNKNOWN"
            return previous(args, **_kw)

        a._checked_call = drift
    elif tamper == "wrong_limits":
        rows[("container", roles["candidate"].object_id)]["HostConfig"]["Memory"] = 999
    elif tamper == "foreign_volume_name":
        volumes["fixture"].name = "unowned-volume"
        volumes["fixture"].object_id = "unowned-volume"
    elif tamper == "extra_item":
        a.items.append(SimpleNamespace(kind="container", object_id="f" * 64, name="unrecognized"))
    elif tamper == "mount_bypass":
        rows[("container", roles["candidate"].object_id)]["Mounts"] = [
            {"Type": "bind", "Destination": "/var/run/docker.sock"}
        ]
    elif tamper == "volume_foreign":
        volumes["fixture"].artifact_tmpfs_attested = False
    elif tamper == "volume_reuse":
        volumes["evaluator"] = volumes["fixture"]
    elif tamper == "ambiguous_result":

        def unclear(_args):
            raise RuntimeError("daemon output unavailable")

        a._checked_call = unclear
    with pytest.raises(m.P4TopologyError):
        check(m, a, networks, roles, volumes, images)
    assert a.recovery_required is True


def test_requires_scoped_owned_live_attempt():
    m = module()
    a, networks, roles, volumes, images, _, calls = mock_attempt()
    a.run = object()
    with pytest.raises(m.P4TopologyError):
        check(m, a, networks, roles, volumes, images)
    assert not calls
    assert a.recovery_required is True


def test_adapter_records_only_successful_graph_readback(monkeypatch, tmp_path):
    import p4_runtime_topology as topology
    from p4_trusted_runtime_adapter import OwnedDockerAttempt, P4RecoveryRequired

    attempt = OwnedDockerAttempt(
        policy={},
        attempt_id="attempt1",
        lease_path=tmp_path / "lock",
        ledger_path=tmp_path / "ledger",
    )
    expected = {
        "status": "FIVE_ROLE_PRESTART_READBACK_SOURCE_ONLY",
        "roles": {"candidate": "a" * 64},
        "networks": {"subject": "b" * 64},
        "volumes": {"fixture": "owned"},
        "effective_profiles_sha256": "d" * 64,
        "runtime_execution_proven": False,
    }
    monkeypatch.setattr(topology, "attest_owned_prestart_graph", lambda **kw: expected)
    recorded = []
    monkeypatch.setattr(attempt, "_record", lambda event, **kw: recorded.append((event, kw)))
    result = attempt.attest_owned_five_role_graph(
        networks={},
        containers={},
        volumes={},
        expected_images={},
        relay_profile={},
        role_profiles={},
        relay_program=tmp_path / "relay.py",
        remaining_seconds=100,
    )
    assert result == expected
    assert recorded[0][0] == "PRESTART_GRAPH_ATTESTED"
    assert len(recorded[0][1]["details"]["readback_sha256"]) == 64

    def broken(*_a, **_kw):
        raise P4RecoveryRequired("ledger not durable")

    monkeypatch.setattr(attempt, "_record", broken)
    with pytest.raises(P4RecoveryRequired, match="ledger"):
        attempt.attest_owned_five_role_graph(
            networks={},
            containers={},
            volumes={},
            expected_images={},
            relay_profile={},
            role_profiles={},
            relay_program=tmp_path / "relay.py",
            remaining_seconds=100,
        )


@pytest.mark.parametrize(
    "role", ["candidate", "evaluator", "relay", "fixture-app", "fixture-control"]
)
@pytest.mark.parametrize(
    "field,value",
    [
        ("Config.User", "0:0"),
        ("Config.Entrypoint", ["/bin/sh"]),
        ("Config.Cmd", ["--unreviewed"]),
        ("Config.Env", ["LANG=C", "EXTRA=1"]),
        ("Config.WorkingDir", "/tmp"),
        ("HostConfig.PidMode", "host"),
        ("HostConfig.IpcMode", "host"),
        ("HostConfig.LogConfig", {"Type": "json-file", "Config": {}}),
        ("HostConfig.Tmpfs", {"/tmp": "rw,exec"}),
        ("HostConfig.UsernsMode", "host"),
    ],
)
def test_every_role_rejects_effective_execution_mutations(monkeypatch, role, field, value):
    m = module()
    attempt, networks, roles, volumes, images, rows, _ = mock_attempt()
    monkeypatch.setattr(m, "verify_relay_prestart", lambda **_kw: None)
    current = rows[("container", roles[role].object_id)]
    parent, key = field.split(".")
    current[parent][key] = value
    with pytest.raises(m.P4TopologyError):
        check(m, attempt, networks, roles, volumes, images)
    assert attempt.recovery_required is True


def test_profile_is_required_and_resolved_image_is_verified(monkeypatch):
    m = module()
    attempt, networks, roles, volumes, images, rows, _ = mock_attempt()
    monkeypatch.setattr(m, "verify_relay_prestart", lambda **_kw: None)
    del attempt.role_profiles["fixture-control"]
    with pytest.raises(m.P4TopologyError):
        check(m, attempt, networks, roles, volumes, images)
    attempt, networks, roles, volumes, images, rows, _ = mock_attempt()
    rows[("image", images["fixture-app"])]["Id"] = "a" * 64
    with pytest.raises(m.P4TopologyError):
        check(m, attempt, networks, roles, volumes, images)


def test_requested_manifest_digest_and_resolved_image_id_are_distinct(monkeypatch):
    from dataclasses import replace

    m = module()
    attempt, networks, roles, volumes, images, rows, _ = mock_attempt()
    monkeypatch.setattr(m, "verify_relay_prestart", lambda **_kw: None)
    old = images["candidate"]
    manifest = "ghcr.io/example/fixture@sha256:" + "f" * 64
    images["candidate"] = manifest
    attempt.role_profiles["candidate"] = replace(
        attempt.role_profiles["candidate"], requested_image=manifest
    )
    rows[("container", roles["candidate"].object_id)]["Config"]["Image"] = manifest
    rows[("image", manifest)] = rows.pop(("image", old))
    rows[("image", manifest)]["RepoDigests"] = [manifest]
    assert check(m, attempt, networks, roles, volumes, images)["effective_profiles_sha256"]
