from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parents[1] / "assurance/phase2/ci"


def module():
    spec = importlib.util.spec_from_file_location(
        "p4_control_audit_test", CI / "p4_control_audit.py"
    )
    assert spec and spec.loader
    x = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = x
    spec.loader.exec_module(x)
    return x


def _container():
    return {
        "Id": "a" * 64,
        "Config": {
            "Labels": {"mcpbg.p4.owner": "attempt1"},
            "Image": "ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-fixture@sha256:"
            + "c" * 64,
            "User": "10001:10001",
            "Entrypoint": None,
            "Cmd": [
                "python",
                "control_service.py",
                "--db",
                "/state/fixture.db",
                "--host",
                "0.0.0.0",
                "--port",
                "9000",
            ],
        },
        "HostConfig": {
            "Privileged": False,
            "ReadonlyRootfs": True,
            "PublishAllPorts": False,
            "PortBindings": None,
            "Binds": [],
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
        },
        "State": {"Running": True, "Paused": False},
        "Mounts": [{"Type": "volume", "Destination": "/state", "Name": "vol1", "RW": True}],
        "NetworkSettings": {"Networks": {"net-control": {"NetworkID": "b" * 64}}},
    }


def test_fixed_control_rpc_uses_only_localhost_and_exact_control_id():
    m = module()
    result = []

    def fake(argv, **kwargs):
        result.append((argv, kwargs))
        response = b'{"status":"ok"}'
        return m.ControlResponse(0, response, b"", len(response))

    value = m.fixed_control_action(
        control_container=_container(),
        owner="attempt1",
        volume="vol1",
        fixture_image=_container()["Config"]["Image"],
        control_network_id="b" * 64,
        action="health",
        attempt_id=None,
        execute=fake,
        remaining_seconds=6,
    )
    assert value == {"status": "ok"}
    argv = result[0][0]
    assert argv[:5] == ["docker", "exec", "--user", "10001:10001", "a" * 64]
    assert "127.0.0.1:9000" in argv[8]
    assert argv[9:] == ["GET", "/health", "{}"]


def test_control_cannot_accept_candidate_paths_or_foreign_mounts():
    m = module()
    for action in ("/custom", "shell", "delete", "../../attempts"):
        with pytest.raises(m.ControlUnknown):
            m.control_command(container_id="a" * 64, action=action)
    with pytest.raises(m.ControlUnknown):
        m.control_command(container_id="a" * 64, action="finalize", attempt_id="bad/../")
    altered = _container()
    altered["Mounts"] = [{"Type": "bind", "Destination": "/state", "Name": "vol1", "RW": True}]
    with pytest.raises(m.ControlUnknown):
        m.fixed_control_action(
            control_container=altered,
            owner="attempt1",
            volume="vol1",
            fixture_image=_container()["Config"]["Image"],
            control_network_id="b" * 64,
            action="health",
            attempt_id=None,
            execute=lambda *_a, **_k: pytest.fail("unverified container executed"),
            remaining_seconds=4,
        )


def test_recovery_on_uncertain_control_response():
    m = module()
    with pytest.raises(m.ControlUnknown):
        m.fixed_control_action(
            control_container=_container(),
            owner="attempt1",
            volume="vol1",
            fixture_image=_container()["Config"]["Image"],
            control_network_id="b" * 64,
            action="close",
            attempt_id="attempt1",
            execute=lambda *_a, **_k: m.ControlResponse(3, b"", b"error", 5),
            remaining_seconds=4,
        )


def test_final_audit_is_not_approval():
    m = module()
    fenced = {
        "attempt_id": "attempt1",
        "state": "FENCED",
        "audit_complete": True,
        "final_watermark": 1,
        "requests": [],
        "audit": [{"id": 1}],
    }
    finalized = {"attempt": {"attempt_id": "attempt1", "state": "FINALIZED", "audit_complete": 1}}
    result = m.audit_evidence_digest(
        final_snapshot=fenced,
        finalized_attempt=finalized,
        attempt_id="attempt1",
    )
    assert set(result) == {
        "attempt_id",
        "fenced_snapshot_sha256",
        "finalized_attempt_sha256",
        "source",
    }
    with pytest.raises(m.ControlUnknown):
        m.audit_evidence_digest(
            final_snapshot={**fenced, "state": "FINALIZED"},
            finalized_attempt=finalized,
            attempt_id="attempt1",
        )
    with pytest.raises(m.ControlUnknown):
        m.audit_evidence_digest(
            final_snapshot=fenced,
            finalized_attempt={"attempt": {"attempt_id": "attempt1", "state": "OPEN"}},
            attempt_id="attempt1",
        )


@pytest.mark.parametrize(
    "networks",
    [
        {},
        {"wrong": None},
        {"wrong": "untrusted"},
        {"one": {"NetworkID": "b" * 64}, "two": {"NetworkID": "b" * 64}},
        ["not-a-network-map"],
    ],
)
def test_control_network_inventory_must_be_one_verified_mapping(networks):
    m = module()
    control = _container()
    control["NetworkSettings"]["Networks"] = networks
    with pytest.raises(m.ControlUnknown):
        m.fixed_control_action(
            control_container=control,
            owner="attempt1",
            volume="vol1",
            fixture_image=_container()["Config"]["Image"],
            control_network_id="b" * 64,
            action="health",
            attempt_id=None,
            execute=lambda *_a, **_k: pytest.fail("untrusted control network reached"),
            remaining_seconds=4,
        )
