"""Source-only scoped Docker endpoint negative tests. Never contacts a daemon."""

from __future__ import annotations

import hashlib
import sys
import tempfile
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


@pytest.mark.parametrize(
    "override",
    (
        "--host=unix:///other.sock",
        "--context=default",
        "--config=/tmp/unreviewed",
        "-H",
        "-Hunix:///other.sock",
        "-H=unix:///other.sock",
        "-c",
    ),
)
def test_rejects_alternate_endpoint_flag_spellings_before_io(override):
    binding = scoped.EngineBinding("unix:///run/mcpbg-p4-a/engine.sock", "0" * 64, 1, 1)
    called = []
    runner = scoped.ScopedEngineRunner(binding, invoke=lambda *a, **k: called.append(a))
    with pytest.raises(scoped.EngineUncertain, match="override"):
        runner(
            ["docker", "container", "inspect", override],
            timeout=4,
            output_budget=512,
            retained_per_stream=100,
        )
    assert called == []


@pytest.fixture
def short_unix_socket_parent():
    """Use a short, canonical path: Darwin AF_UNIX paths are ~104 bytes max.

    Avoid weakening the Engine socket checks or mocking the socket itself.
    Resolve /tmp first because on macOS it is usually a symlink to /private/tmp.
    """
    with tempfile.TemporaryDirectory(
        prefix="mbg-", dir=str(Path("/tmp").resolve(strict=True))
    ) as path:
        yield Path(path)


@pytest.mark.parametrize("fault", ("symlink", "world_writable", "owner_drift", "missing", "valid"))
def test_private_socket_parent_revalidated_on_every_call(
    monkeypatch, short_unix_socket_parent, fault
):
    import os
    import re
    import socket

    monkeypatch.setattr(scoped, "_ENDPOINT", re.compile(r"unix://.*/engine\.sock\Z"))
    directory = short_unix_socket_parent / "private"
    directory.mkdir(mode=0o700)
    sock = socket.socket(socket.AF_UNIX)
    sock_path = directory / "engine.sock"
    sock.bind(str(sock_path))
    os.chmod(sock_path, 0o600)
    try:
        real = sock_path.lstat()
        binding = scoped.EngineBinding(
            "unix://" + str(sock_path), "0" * 64, real.st_dev, real.st_ino
        )
        original = Path.lstat

        def lstat(path):
            if path == directory and fault == "missing":
                raise FileNotFoundError("injected lost parent")
            raw = list(original(path))
            # The test's temporary UNIX socket/parent are unprivileged; model
            # independently admitted root ownership and change one property.
            if path in (directory, sock_path):
                raw[4] = 0
            if path == directory:
                if fault == "world_writable":
                    raw[0] |= 0o002
                if fault == "owner_drift":
                    raw[4] = 1
            return os.stat_result(raw)

        monkeypatch.setattr(Path, "lstat", lstat)
        if fault == "symlink":
            original_resolve = Path.resolve

            def resolve(path, *args, **kwargs):
                if path == directory:
                    return short_unix_socket_parent / "different-directory"
                return original_resolve(path, *args, **kwargs)

            monkeypatch.setattr(Path, "resolve", resolve)
        runner = scoped.ScopedEngineRunner(binding, invoke=lambda *a, **k: pytest.fail("IO"))
        if fault == "valid":
            runner._socket_check()
        else:
            with pytest.raises(scoped.EngineUncertain, match="socket|directory"):
                runner._socket_check()
    finally:
        sock.close()


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
