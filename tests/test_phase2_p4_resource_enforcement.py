from __future__ import annotations

import importlib.util
import io
import json
import stat
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
MODULE = CI / "p4_resource_enforcement.py"
POLICY = CI / "p4-resource-policy.json"
TRUST = CI / "trust-boundary.json"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase2_p4_resource_enforcement_test", MODULE)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load P4 resource enforcement module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _policy(module: ModuleType) -> dict[str, object]:
    return module.load_policy(POLICY)


def _tight_policy(module: ModuleType) -> dict[str, object]:
    value = json.loads(json.dumps(_policy(module)))
    value["limits"]["artifacts"] = {
        "total_bytes": 4096,
        "per_file_bytes": 2048,
        "max_files": 4,
        "max_depth": 3,
    }
    value["archive_extraction"].update(
        {
            "compressed_bytes": 4096,
            "expanded_bytes": 4096,
            "max_files": 4,
            "max_depth": 3,
            "max_expansion_ratio": 20,
        }
    )
    value["json_intake"].update(
        {
            "max_bytes": 1024,
            "max_depth": 4,
            "max_string_bytes": 64,
            "max_array_items": 4,
            "max_object_members": 8,
        }
    )
    value["limits"]["fixture_traffic"] = {
        "request_bytes": 64,
        "response_bytes": 128,
        "max_requests": 2,
        "aggregate_bytes": 200,
    }
    value["limits"]["execution"] = {
        "attempt_timeout_seconds": 10,
        "cleanup_timeout_seconds": 3,
        "max_concurrent_attempts": 1,
    }
    value["limits"]["docker_runtime"].update(
        {
            "max_owned_containers_per_attempt": 2,
            "max_owned_networks_per_attempt": 1,
            "max_owned_volumes_per_attempt": 1,
        }
    )
    return value


def test_binding_is_implementation_only_and_non_executing() -> None:
    module = _module()
    binding = module.validate_trust_binding(ROOT, TRUST, POLICY)
    assert binding["status"] == "IMPLEMENTED_NOT_RUNTIME_PROVEN"
    assert binding["candidate_execution_enabled"] is False
    assert binding["hostile_execution_authorized"] is False
    assert binding["runtime_enforcement_proven"] is False
    source = MODULE.read_text(encoding="utf-8")
    assert "subprocess.Popen" not in source
    assert "docker run" not in source
    assert "gh api" not in source


def test_bounded_json_rejects_duplicate_depth_schema_and_type() -> None:
    module = _module()
    policy = _tight_policy(module)
    with pytest.raises(module.P4ResourceEnforcementError, match="duplicate JSON key"):
        module.load_bounded_json(
            b'{"schema_version":1,"a":1,"a":2}', policy, expected_schema_version=1
        )
    with pytest.raises(module.P4ResourceEnforcementError, match="nesting depth"):
        module.load_bounded_json(
            b'{"schema_version":1,"a":{"b":{"c":{"d":1}}}}',
            policy,
            expected_schema_version=1,
        )
    with pytest.raises(module.P4ResourceEnforcementError, match="schema_version"):
        module.load_bounded_json(b'{"schema_version":2}', policy, expected_schema_version=1)
    with pytest.raises(module.P4ResourceEnforcementError, match="field type"):
        module.load_bounded_json(
            b'{"schema_version":1,"count":"1"}',
            policy,
            expected_schema_version=1,
            field_types={"count": int},
        )


def test_artifact_budget_rejects_symlink_size_count_and_depth(tmp_path: Path) -> None:
    module = _module()
    policy = _tight_policy(module)
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a").write_bytes(b"x" * 10)
    assert module.validate_artifact_tree(root, policy) == {"files": 1, "bytes": 10}
    (root / "link").symlink_to(root / "a")
    with pytest.raises(module.P4ResourceEnforcementError, match="non-regular|symlink"):
        module.validate_artifact_tree(root, policy)

    root2 = tmp_path / "oversize"
    root2.mkdir()
    (root2 / "big").write_bytes(b"x" * 2049)
    with pytest.raises(module.P4ResourceEnforcementError, match="file exceeds"):
        module.validate_artifact_tree(root2, policy)


def test_zip_archive_rejects_traversal_symlink_duplicate_and_ratio(tmp_path: Path) -> None:
    module = _module()
    policy = _tight_policy(module)

    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape", b"x")
    with pytest.raises(module.P4ResourceEnforcementError, match="traversal"):
        module.safe_extract_archive(traversal, tmp_path / "out-traversal", policy)

    symlink = tmp_path / "symlink.zip"
    with zipfile.ZipFile(symlink, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target")
    with pytest.raises(module.P4ResourceEnforcementError, match="symlink"):
        module.safe_extract_archive(symlink, tmp_path / "out-symlink", policy)

    duplicate = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("a", b"1")
        archive.writestr("./a", b"2")
    with pytest.raises(module.P4ResourceEnforcementError, match="duplicate"):
        module.safe_extract_archive(duplicate, tmp_path / "out-duplicate", policy)

    ratio_policy = json.loads(json.dumps(policy))
    ratio_policy["archive_extraction"]["max_expansion_ratio"] = 1
    ratio = tmp_path / "ratio.zip"
    with zipfile.ZipFile(ratio, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a", b"0" * 2000)
    with pytest.raises(module.P4ResourceEnforcementError, match="expansion ratio"):
        module.safe_extract_archive(ratio, tmp_path / "out-ratio", ratio_policy)


def test_tar_archive_rejects_hardlink_device_and_collision(tmp_path: Path) -> None:
    module = _module()
    policy = _tight_policy(module)

    hardlink = tmp_path / "hard.tar.gz"
    with tarfile.open(hardlink, "w:gz") as archive:
        base = tarfile.TarInfo("a")
        base.size = 1
        archive.addfile(base, io.BytesIO(b"x"))
        link = tarfile.TarInfo("b")
        link.type = tarfile.LNKTYPE
        link.linkname = "a"
        archive.addfile(link)
    with pytest.raises(module.P4ResourceEnforcementError, match="hardlink"):
        module.safe_extract_archive(hardlink, tmp_path / "out-hard", policy)

    device = tmp_path / "device.tar.gz"
    with tarfile.open(device, "w:gz") as archive:
        node = tarfile.TarInfo("dev")
        node.type = tarfile.CHRTYPE
        archive.addfile(node)
    with pytest.raises(module.P4ResourceEnforcementError, match="device"):
        module.safe_extract_archive(device, tmp_path / "out-device", policy)

    collision = tmp_path / "collision.tar.gz"
    with tarfile.open(collision, "w:gz") as archive:
        parent = tarfile.TarInfo("a")
        parent.size = 1
        archive.addfile(parent, io.BytesIO(b"x"))
        child = tarfile.TarInfo("a/b")
        child.size = 1
        archive.addfile(child, io.BytesIO(b"y"))
    with pytest.raises(module.P4ResourceEnforcementError, match="collision"):
        module.safe_extract_archive(collision, tmp_path / "out-collision", policy)


def test_regular_zip_and_tar_extract_with_artifact_validation(tmp_path: Path) -> None:
    module = _module()
    policy = _tight_policy(module)
    good_zip = tmp_path / "good.zip"
    with zipfile.ZipFile(good_zip, "w") as archive:
        archive.writestr("dir/a.txt", b"hello")
    assert module.safe_extract_archive(good_zip, tmp_path / "zip-out", policy) == {
        "files": 1,
        "bytes": 5,
    }
    good_tar = tmp_path / "good.tar.gz"
    with tarfile.open(good_tar, "w:gz") as archive:
        payload = b"hello"
        info = tarfile.TarInfo("dir/a.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    assert module.safe_extract_archive(good_tar, tmp_path / "tar-out", policy) == {
        "files": 1,
        "bytes": 5,
    }


def test_docker_build_and_subprocess_limits_are_policy_derived() -> None:
    module = _module()
    policy = _policy(module)
    args = module.docker_resource_args(policy)
    assert "--log-driver" in args and "local" in args
    assert "max-size=1m" in args
    assert "max-file=2" in args
    assert module.build_command_limits(policy) == {
        "timeout_seconds": 300,
        "output_budget_bytes": 1048576,
        "context_bytes": 2097152,
    }
    assert module.subprocess_limits(policy) == {
        "timeout_seconds": 120,
        "output_budget_bytes": 1048576,
        "capture_limit_bytes": 131072,
    }


def test_fixture_and_owned_resource_budgets_fail_closed() -> None:
    module = _module()
    policy = _tight_policy(module)
    traffic = module.TrafficBudget.from_policy(policy)
    traffic.record(request_bytes=10, response_bytes=20)
    traffic.record(request_bytes=10, response_bytes=20)
    with pytest.raises(module.P4ResourceEnforcementError, match="request count"):
        traffic.record(request_bytes=1, response_bytes=1)

    resources = module.OwnedResourceBudget.from_policy(policy)
    resources.record_container()
    resources.record_container()
    with pytest.raises(module.P4ResourceEnforcementError, match="container count"):
        resources.record_container()
    resources.record_network()
    with pytest.raises(module.P4ResourceEnforcementError, match="network count"):
        resources.record_network()


def test_attempt_deadline_single_attempt_lock_and_cleanup_semantics(tmp_path: Path) -> None:
    module = _module()
    policy = _tight_policy(module)
    deadline = module.AttemptDeadline.from_policy(policy, now=10.0)
    assert deadline.remaining(now=11.0) == 9.0
    with pytest.raises(module.P4ResourceEnforcementError, match="attempt timeout"):
        deadline.remaining(now=21.0)

    lock = tmp_path / "attempt.lock"
    with (
        module.AttemptLease(lock, policy),
        pytest.raises(module.P4ResourceEnforcementError, match="concurrent attempt"),
        module.AttemptLease(lock, policy),
    ):
        pass

    assert module.classify_cleanup_evidence({}, policy) == {
        "outcome": "UNKNOWN",
        "recovery_required": True,
    }
    assert module.classify_cleanup_evidence(
        {"cleanup_complete": True, "owned_resources_remaining": 0}, policy
    ) == {"outcome": "CLEAN", "recovery_required": False}
