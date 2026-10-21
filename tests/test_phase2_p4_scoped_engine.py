"""Source-only scoped Docker endpoint negative tests. Never contacts a daemon."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parents[1] / "assurance/phase2/ci"
sys.path.insert(0, str(CI))
import p4_scoped_engine as scoped  # noqa: E402
from p4_native_build_execution import BuildCommandResult  # noqa: E402


def test_scoped_success_and_host_binding(monkeypatch, tmp_path):
    calls = []
    daemon = b"private-engine-identity"
    endpoint = "unix:///run/mcpbg-p4-a/engine.sock"
    binding = scoped.EngineBinding(endpoint, hashlib.sha256(daemon).hexdigest(), 7, 21)
    monkeypatch.setattr(scoped.ScopedEngineRunner, "_socket_check", lambda self: None)

    def invoke(argv, *, endpoint, remaining, byte_budget):
        calls.append(list(argv))
        assert argv[:3] == ("docker", "--host", endpoint)
        if argv[3] == "info":
            return BuildCommandResult(0, daemon + b"\n", b"", len(daemon) + 1)
        return BuildCommandResult(0, b"ok", b"", 2)

    runner = scoped.ScopedEngineRunner(binding, invoke=invoke)
    result = runner(
        ["docker", "container", "inspect", "test"],
        timeout=20,
        output_budget=100,
        retained_per_stream=10,
    )
    assert result.stdout == b"ok"
    assert [args[3] for args in calls] == ["info", "container", "info"]
    assert all(args[2] == endpoint for args in calls)


def test_rejects_ambient_endpoint_override_before_daemon(monkeypatch):
    binding = scoped.EngineBinding("unix:///run/mcpbg-p4-a/engine.sock", "0" * 64, 1, 1)
    called = []
    runner = scoped.ScopedEngineRunner(binding, invoke=lambda *a, **k: called.append(a))
    for args in (
        ["docker", "--host", "tcp://other", "info"],
        ["docker", "container", "inspect", "--context", "other"],
        ["docker", "buildx", "build"],
        ["docker", "inspect", "bad\x00id"],
    ):
        with pytest.raises(scoped.EngineUncertain):
            runner(args, timeout=4, output_budget=512, retained_per_stream=100)
    assert called == []


def test_daemon_identity_change_prevents_action(monkeypatch):
    binding = scoped.EngineBinding("unix:///run/mcpbg-p4-a/engine.sock", "0" * 64, 1, 1)
    monkeypatch.setattr(scoped.ScopedEngineRunner, "_socket_check", lambda self: None)
    commands = []

    def invoke(argv, *, endpoint, remaining, byte_budget):
        commands.append(argv[3])
        return BuildCommandResult(0, b"wrong-daemon\n", b"", 13)

    with pytest.raises(scoped.EngineUncertain, match="daemon identity"):
        scoped.ScopedEngineRunner(binding, invoke=invoke)(
            ["docker", "container", "inspect", "a"],
            timeout=8,
            output_budget=100,
            retained_per_stream=50,
        )
    assert commands == ["info"]


def test_post_operation_unknown_latches_ambiguity(monkeypatch):
    daemon = b"worker-1"
    binding = scoped.EngineBinding(
        "unix:///run/mcpbg-p4-a/engine.sock", hashlib.sha256(daemon).hexdigest(), 1, 2
    )
    monkeypatch.setattr(scoped.ScopedEngineRunner, "_socket_check", lambda self: None)
    commands = []

    def invoke(argv, *, endpoint, remaining, byte_budget):
        commands.append(argv[3])
        output = daemon + b"\n" if len(commands) == 1 else b"bad\n"
        return BuildCommandResult(0, output, b"", len(output))

    with pytest.raises(scoped.EngineUncertain, match="post-command"):
        scoped.ScopedEngineRunner(binding, invoke=invoke)(
            ["docker", "network", "create", "owned"],
            timeout=8,
            output_budget=100,
            retained_per_stream=50,
        )
    assert commands == ["info", "network", "info"]


def test_socket_capture_rejects_non_socket(monkeypatch, tmp_path):
    p = tmp_path / "engine.sock"
    p.write_text("not a socket")
    monkeypatch.setattr(scoped, "_ENDPOINT", __import__("re").compile(r"unix://.*/engine\.sock\Z"))
    with pytest.raises(scoped.EngineUncertain, match="not a UNIX socket"):
        scoped.socket_binding("unix://" + str(p), "0" * 64)


def test_real_engine_path_requires_inherited_shared_deadline(tmp_path):
    import json

    from p4_trusted_runtime_adapter import OwnedDockerAttempt, P4AdapterError

    policy = json.loads((CI / "p4-resource-policy.json").read_text())
    binding = scoped.EngineBinding("unix:///run/mcpbg-p4-a/engine.sock", "0" * 64, 1, 1)
    runner = scoped.ScopedEngineRunner(binding, invoke=lambda *a, **k: None)
    with (
        pytest.raises(P4AdapterError, match="original build admission deadline"),
        OwnedDockerAttempt(
            policy=policy,
            attempt_id="test-no-deadline",
            lease_path=tmp_path / "run.lock",
            ledger_path=tmp_path / "owned-test-no-deadline.jsonl",
            daemon_context=binding.endpoint,
            daemon_identity=binding.daemon_id_sha256,
            run=runner,
        ),
    ):
        pass
