from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
MODULE = CI / "p4_staged_pipeline.py"


def pipeline():
    spec = importlib.util.spec_from_file_location("test_p4_staged_pipeline", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_profile_keeps_distinct_privileged_build_and_relay_source_scope(tmp_path):
    module = pipeline()
    frozen = json.loads((CI / "p4-resource-policy.json").read_text())
    profile = CI / "p4-build-stage-profile.json"
    accepted = module.load_build_profile(profile, frozen)
    assert accepted["build_execution_authorized"] is False
    assert accepted["hard_daemon_data_root_bytes"] == 1073741824
    assert accepted["default_shared_builder_forbidden"] is True
    assert accepted["candidate_dockerfile_forbidden"] is True
    for field, value in (
        ("build_execution_authorized", True),
        ("default_shared_builder_forbidden", False),
        ("hard_daemon_data_root_bytes", 1073741825),
        ("driver", "shared-docker-container"),
        ("max_context_bytes", 2097153),
    ):
        altered = dict(accepted)
        altered[field] = value
        alternate = tmp_path / "profile.json"
        alternate.write_text(json.dumps(altered))
        with pytest.raises(module.P4StageError):
            module.load_build_profile(alternate, frozen)

    relay = json.loads((CI / "p4-relay-role-profile.json").read_text())
    assert relay["p3_evaluator_role_inheritance"] is False
    assert relay["runtime_execution_enabled"] is False
    assert relay["candidate_can_contact_fixture_directly"] is False
    assert relay["control_endpoints_reachable_from_subject_or_relay"] is False
    assert (
        relay["network_topology"]["max_networks"]
        == frozen["limits"]["docker_runtime"]["max_owned_networks_per_attempt"]
    )


def test_native_admission_rejects_shared_daemon_unbounded_disk_and_wrong_scope():
    module = pipeline()
    props = dict(
        worker_source="a" * 40,
        platform="linux/amd64",
        daemon_endpoint="unix:///run/mcpbg-p4-9/engine.sock",
        daemon_id="b" * 64,
        daemon_data_root="/mnt/mcpbg-p4-9/docker",
        dedicated_block_device_bytes=1073741824,
        disk_hard_limited=True,
        all_docker_writes_contained=True,
        owner_lease_scope="c" * 64,
    )
    module.NativeBuildAdmission(**props).require_bound_stage(
        expected_worker_source="a" * 40, lease_scope="c" * 64
    )
    for field, value in (
        ("platform", "linux/arm64"),
        ("daemon_endpoint", "unix:///var/run/docker.sock"),
        ("daemon_endpoint", "unix:///run/mcpbg-p4-9/../../docker.sock"),
        ("daemon_endpoint", "unix:///run/mcpbg-p4-9/engine.sock/../../shared.sock"),
        ("daemon_data_root", "/mnt/mcpbg-p4-9/../../var/lib/docker"),
        ("daemon_data_root", "/var/lib/docker"),
        ("dedicated_block_device_bytes", 1073741825),
        ("dedicated_block_device_bytes", True),
        ("disk_hard_limited", False),
        ("all_docker_writes_contained", False),
        ("owner_lease_scope", "d" * 64),
    ):
        invalid = dict(props, **{field: value})
        with pytest.raises(module.P4StageError):
            module.NativeBuildAdmission(**invalid).require_bound_stage(
                expected_worker_source="a" * 40, lease_scope="c" * 64
            )


def test_handoff_never_claims_p3_equivalence_and_requires_clean_build():
    module = pipeline()
    params = dict(
        source_commit="a" * 40,
        source_tree="b" * 40,
        source_sha256="c" * 64,
        trusted_dockerfile_sha256="d" * 64,
        image_identity="sha256:" + "e" * 64,
        producer_code_sha256="f" * 64,
        native_admission_sha256="a" * 64,
        reference_authority_sha256="b" * 64,
        policy_sha256="c" * 64,
        build_stage_clean=True,
        image_transfer_identity_verified=True,
    )
    handoff = module.bind_stage_handoff(**params)
    assert handoff["runtime_enforcement_proven"] is False
    assert handoff["p3_equivalence_claimed"] is False
    assert handoff["pipeline_image_dependency_retained"] is True
    for change in (
        {"build_stage_clean": False},
        {"image_transfer_identity_verified": False},
        {"source_commit": "bad"},
        {"image_identity": "candidate:latest"},
    ):
        with pytest.raises(module.P4StageError):
            module.bind_stage_handoff(**dict(params, **change))


def test_pipeline_profile_bytes_are_bound_to_trust():
    trust = json.loads((CI / "trust-boundary.json").read_text())
    marker = trust["p4_stage_contracts"]
    assert marker["privileged_build_execution_authorized"] is False
    assert marker["hostile_execution_authorized"] is False
    assert marker["p3_reference_mutation_enabled"] is False
    assert marker["verdict_publication_enabled"] is False
    for path, digest in marker["source_sha256"].items():
        assert trust["consumed_trusted_inputs"].count(path) == 1
        import hashlib

        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest


def test_native_disk_preflight_cannot_accept_a_report_without_real_mount(tmp_path):
    module = pipeline()
    props = dict(
        worker_source="a" * 40,
        platform="linux/amd64",
        daemon_endpoint="unix:///run/mcpbg-p4-1/engine.sock",
        daemon_id="b" * 64,
        daemon_data_root=str(tmp_path),
        dedicated_block_device_bytes=1073741824,
        disk_hard_limited=True,
        all_docker_writes_contained=True,
        owner_lease_scope="c" * 64,
    )
    admission = module.NativeBuildAdmission(**props)
    # On developer Macs the native-worker gate rejects before reading Linux mount data.
    native = module.platform.system() == "Linux" and module.platform.machine() in {
        "x86_64",
        "amd64",
    }
    expected = "dedicated non-aliased filesystem" if native else "build requires native AMD64 Linux"
    with pytest.raises(module.P4StageError, match=expected):
        module.verify_native_data_root(
            daemon_data_root=tmp_path,
            docker_info={
                "OSType": "linux",
                "Architecture": "x86_64",
                "DockerRootDir": str(tmp_path),
            },
            admission=admission,
        )


def test_native_build_plan_only_targets_exact_private_engine_and_context(tmp_path):
    module = pipeline()
    import hashlib

    directory = tmp_path / "context"
    directory.mkdir()
    dockerfile, subject = directory / "Dockerfile", directory / "candidate_server.py"
    dockerfile.write_text(
        "FROM ${BASE_IMAGE}\nCOPY candidate_server.py /candidate/candidate_server.py\n"
    )
    subject.write_text('print("synthetic")\n')
    admission = module.NativeBuildAdmission(
        worker_source="a" * 40,
        platform="linux/amd64",
        daemon_endpoint="unix:///run/mcpbg-p4-9/engine.sock",
        daemon_id="b" * 64,
        daemon_data_root="/mnt/mcpbg-p4-9/docker",
        dedicated_block_device_bytes=1073741824,
        disk_hard_limited=True,
        all_docker_writes_contained=True,
        owner_lease_scope="c" * 64,
    )
    args = dict(
        admission=admission,
        expected_worker_source="a" * 40,
        lease_scope="c" * 64,
        context=directory,
        trusted_dockerfile_sha256=hashlib.sha256(dockerfile.read_bytes()).hexdigest(),
        candidate_source_sha256=hashlib.sha256(subject.read_bytes()).hexdigest(),
        base_image="ghcr.io/test/fixture@sha256:" + "d" * 64,
        owned_tag="mcpbg-p4-owned-build:stage",
        policy=json.loads((CI / "p4-resource-policy.json").read_text()),
    )
    command = module.plan_private_native_build(**args)
    assert command[:4] == ["docker", "--host", "unix:///run/mcpbg-p4-9/engine.sock", "build"]
    assert "--network=none" in command and "--pull=false" in command
    assert "buildx" not in command and "--no-cache" in command
    # No CLI, builder, image or Docker service is launched by this source test.
    import pytest

    for key, replacement in (
        ("base_image", "fixture:latest"),
        ("owned_tag", "candidate:latest"),
        ("candidate_source_sha256", "0" * 64),
        ("lease_scope", "e" * 64),
    ):
        with pytest.raises(module.P4StageError):
            module.plan_private_native_build(**dict(args, **{key: replacement}))
    (directory / "untrusted.env").write_text("X=secret\n")
    with pytest.raises(module.P4StageError, match="undeclared"):
        module.plan_private_native_build(**args)
