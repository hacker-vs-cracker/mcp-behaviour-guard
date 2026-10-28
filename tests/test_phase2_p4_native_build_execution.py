from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import time
from dataclasses import replace
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
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n")
    (context / "candidate_server.py").write_text("print('synthetic')\n")

    def digest(name):
        return hashlib.sha256((context / name).read_bytes()).hexdigest()

    base = "ghcr.io/example/fixed@sha256:" + "d" * 64
    tag = "mcpbg-p4-test:stage"
    argv = m.stage.plan_private_native_build(
        admission=admission,
        expected_worker_source="a" * 40,
        lease_scope="c" * 64,
        context=context,
        trusted_dockerfile_sha256=digest("Dockerfile"),
        candidate_source_sha256=digest("candidate_server.py"),
        base_image=base,
        owned_tag=tag,
        policy=policy,
    )
    spec = m.ReviewedBuildSpec(
        admission=admission,
        worker_source="a" * 40,
        lease_scope="c" * 64,
        context=context,
        dockerfile_sha256=digest("Dockerfile"),
        source_sha256=digest("candidate_server.py"),
        base_image=base,
        owned_tag=tag,
        reviewed_argv=tuple(argv),
        source_commit="a" * 40,
        source_tree="b" * 40,
    )
    return admission, policy, spec


def test_build_requires_private_journal_and_bounds(tmp_path):
    m = module()
    admission, policy, spec = _params(m, tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "owned-build.jsonl"
    records = []

    def fake(argv, **kw):
        records.append((argv, kw))
        return m.BuildCommandResult(0, b"ok", b"", 2)

    with m.DurableBuildJournal(path) as journal:
        result = m.run_reviewed_private_build(
            spec=spec,
            expected_source_commit="a" * 40,
            expected_source_tree="b" * 40,
            expected_worker_source="a" * 40,
            expected_lease_scope="c" * 64,
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
    admission, policy, spec = _params(m, tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    with (
        m.DurableBuildJournal(private / "owned-build.jsonl") as journal,
        pytest.raises(m.P4BuildUnknown),
    ):
        m.run_reviewed_private_build(
            spec=spec,
            expected_source_commit="a" * 40,
            expected_source_tree="b" * 40,
            expected_worker_source="a" * 40,
            expected_lease_scope="c" * 64,
            journal=journal,
            policy=policy,
            deadline=float(time.monotonic() + 5),
            run=lambda *_a, **_kw: m.BuildCommandResult(1, b"", b"fail", 4),
        )
    assert '"BUILD_UNKNOWN"' in (private / "owned-build.jsonl").read_text()


def test_native_build_disallows_cli_or_privileged_shortcuts(tmp_path):
    m = module()
    admission, policy, spec = _params(m, tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    with m.DurableBuildJournal(private / "owned-build.jsonl") as journal:
        for invalid in (
            replace(spec, reviewed_argv=(*spec.reviewed_argv, "--allow=network.host")),
            replace(spec, context=tmp_path),
            replace(spec, base_image="ghcr.io/other/base@sha256:" + "e" * 64),
            replace(spec, owned_tag="mcpbg-p4-foreign:stage"),
            replace(spec, source_commit="f" * 40),
            replace(spec, source_sha256="e" * 64),
            replace(spec, dockerfile_sha256="e" * 64),
            replace(spec, worker_source="f" * 40),
        ):
            with pytest.raises(m.P4BuildUnknown):
                m.run_reviewed_private_build(
                    spec=invalid,
                    expected_source_commit="a" * 40,
                    expected_source_tree="b" * 40,
                    expected_worker_source="a" * 40,
                    expected_lease_scope="c" * 64,
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


def test_build_rechecks_input_bytes_before_fake_runner(tmp_path):
    m = module()
    admission, policy, spec = _params(m, tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    with m.DurableBuildJournal(state / "intent.jsonl") as journal:
        (spec.context / "candidate_server.py").write_text("# swapped after planning\n")
        with pytest.raises(m.P4BuildUnknown, match="inputs changed"):
            m.run_reviewed_private_build(
                spec=spec,
                expected_source_commit="a" * 40,
                expected_source_tree="b" * 40,
                expected_worker_source="a" * 40,
                expected_lease_scope="c" * 64,
                journal=journal,
                policy=policy,
                deadline=float(time.monotonic() + 5),
                run=lambda *_a, **_k: pytest.fail("changed context reached runner"),
            )


def test_build_journal_rejects_replaced_file_and_parent(tmp_path):
    m = module()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "owned-build.jsonl"
    with m.DurableBuildJournal(path) as journal:
        journal.append("BUILD_SUBMITTED", attempt="first")
        path.rename(private / "retired")
        path.write_text("substituted\n")
        with pytest.raises(m.P4BuildUnknown, match="identity"):
            journal.append("BUILD_CLI_RETURNED", attempt="swapped")
        assert (private / "retired").read_text().count("BUILD_SUBMITTED") == 1
        assert path.read_text() == "substituted\n"

    second = tmp_path / "separate"
    second.mkdir(mode=0o700)
    with m.DurableBuildJournal(second / "owned-build.jsonl") as journal:
        second.rename(tmp_path / "moved")
        second.mkdir(mode=0o700)
        with pytest.raises(m.P4BuildUnknown, match="identity"):
            journal.append("BUILD_UNKNOWN", attempt="renamed")
        assert (second / "owned-build.jsonl").exists() is False


def test_build_journal_rejects_permissions_linking_and_removed_path(tmp_path):
    m = module()
    for variant in ("directory_mode", "file_mode", "hardlink", "unlink"):
        root = tmp_path / variant
        root.mkdir(mode=0o700)
        path = root / "journal.jsonl"
        with m.DurableBuildJournal(path) as journal:
            if variant == "directory_mode":
                root.chmod(0o755)
            elif variant == "file_mode":
                path.chmod(0o644)
            elif variant == "hardlink":
                import os

                os.link(path, root / "alias")
            else:
                path.unlink()
            with pytest.raises(m.P4BuildUnknown):
                journal.append("BUILD_UNKNOWN")
