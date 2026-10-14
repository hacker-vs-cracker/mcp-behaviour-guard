from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parents[1] / "assurance/phase2/ci"


def module():
    sys.path.insert(0, str(CI))
    spec = importlib.util.spec_from_file_location(
        "p4_native_build_execution_test", CI / "p4_native_build_execution.py"
    )
    assert spec and spec.loader
    item = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = item
    try:
        spec.loader.exec_module(item)
    finally:
        sys.path.pop(0)
    return item


def _params(m, tmp_path):
    admission = m.stage.NativeBuildAdmission(
        worker_source="a" * 40,
        platform="linux/amd64",
        daemon_endpoint="unix:///run/mcpbg-p4-1/engine.sock",
        daemon_id="b" * 64,
        daemon_data_root="/mnt/mcpbg-p4-1/docker",
        dedicated_block_device_bytes=1073741824,
        disk_hard_limited=True,
        all_docker_writes_contained=True,
        owner_lease_scope="c" * 64,
    )
    policy = json.loads((CI / "p4-resource-policy.json").read_text())
    command = [
        "docker",
        "--host",
        admission.daemon_endpoint,
        "build",
        "--platform",
        "linux/amd64",
        "--pull=false",
        "--network=none",
        "--no-cache",
        "x",
    ]
    return admission, policy, command


def test_build_requires_private_journal_and_bounds(tmp_path):
    m = module()
    admission, policy, command = _params(m, tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "owned-build.jsonl"
    records = []

    def fake(argv, **kw):
        records.append((argv, kw))
        return m.BuildCommandResult(0, b"ok", b"", 2)

    with m.DurableBuildJournal(path) as journal:
        result = m.run_reviewed_private_build(
            command=command,
            admission=admission,
            journal=journal,
            policy=policy,
            deadline=float(time.monotonic() + 6),
            run=fake,
        )
        assert result["worker_cleanup_verified"] is False
        assert result["image_transfer_verified"] is False
        assert len(records) == 1
        assert records[0][1]["byte_budget"] == 1048576
    assert [json.loads(x)["event"] for x in path.read_text().splitlines()] == [
        "BUILD_SUBMITTED",
        "BUILD_CLI_RETURNED",
    ]
    with pytest.raises(FileExistsError), m.DurableBuildJournal(path):
        pass


def test_failed_or_uncertain_build_never_returns_clean(tmp_path):
    m = module()
    admission, policy, command = _params(m, tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    with m.DurableBuildJournal(private / "owned-build.jsonl") as journal:
        with pytest.raises(m.P4BuildUnknown):
            m.run_reviewed_private_build(
                command=command,
                admission=admission,
                journal=journal,
                policy=policy,
                deadline=float(time.monotonic() + 5),
                run=lambda *_a, **_kw: m.BuildCommandResult(1, b"", b"fail", 4),
            )
    assert '"BUILD_UNKNOWN"' in (private / "owned-build.jsonl").read_text()


def test_native_build_disallows_cli_or_privileged_shortcuts(tmp_path):
    m = module()
    admission, policy, command = _params(m, tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    with m.DurableBuildJournal(private / "owned-build.jsonl") as journal:
        for invalid in (
            ["docker", "buildx", "build"],
            ["docker", "--host", "unix:///var/run/docker.sock", *command[3:]],
            [*command, "--allow=network.host"],
            [x for x in command if x != "--network=none"],
        ):
            with pytest.raises(m.P4BuildUnknown):
                m.run_reviewed_private_build(
                    command=invalid,
                    admission=admission,
                    journal=journal,
                    policy=policy,
                    deadline=float(time.monotonic() + 5),
                    run=lambda *_a, **_kw: pytest.fail("unsafe command executed"),
                )


def test_bounded_subprocess_rejects_unbounded_specs():
    m = module()
    ep = "unix:///run/mcpbg-p4-1/engine.sock"
    for args in (
        dict(argv=["docker", "--host", ep, "build"], endpoint=ep, remaining=301, byte_budget=1024),
        dict(argv=["docker", "--host", ep, "build"], endpoint=ep, remaining=1, byte_budget=1048577),
        dict(
            argv=["docker", "--host", "unix:///var/run/docker.sock", "build"],
            endpoint=ep,
            remaining=1,
            byte_budget=1024,
        ),
    ):
        with pytest.raises(m.P4BuildUnknown):
            m.bounded_native_command(**args)
