from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "assurance/phase2/ci/p4-resource-policy.json"
VALIDATOR = ROOT / "assurance/phase2/ci/p4_resource_policy.py"
TRUST = ROOT / "assurance/phase2/ci/trust-boundary.json"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("p4_resource_policy_test", VALIDATOR)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load P4 resource-policy validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_p4_resource_policy_foundation_validates_without_enabling_execution() -> None:
    module = _module()
    policy = module.validate(ROOT, POLICY, TRUST)
    assert policy["status"] == "PRE_P4_RESOURCE_POLICY_FROZEN"
    assert policy["stage"] == "POLICY_FOUNDATION_ONLY"
    assert policy["candidate_execution_enabled"] is False
    assert policy["runtime_enforcement_proven"] is False


def test_p4_resource_policy_covers_all_handoff_resource_surfaces() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert set(policy["limits"]) == {
        "subprocess",
        "candidate_source",
        "docker_runtime",
        "build",
        "artifacts",
        "fixture_traffic",
        "execution",
    }
    archive = policy["archive_extraction"]
    for key in (
        "reject_absolute_paths",
        "reject_parent_traversal",
        "reject_symlinks",
        "reject_hardlinks",
        "reject_device_entries",
        "reject_duplicate_names",
        "reject_type_collisions",
    ):
        assert archive[key] is True
    assert policy["json_intake"] == {
        "max_bytes": 1_048_576,
        "max_depth": 32,
        "max_string_bytes": 65_536,
        "max_array_items": 1024,
        "max_object_members": 1024,
        "duplicate_keys": "reject",
        "schema_version_required": True,
        "field_types": "strict",
    }
    assert policy["cleanup_semantics"] == {
        "malformed_or_missing_evidence_outcome": "UNKNOWN",
        "recovery_required": True,
        "fabricate_clean_state": False,
    }


def test_p4_resource_policy_binds_existing_q1_and_candidate_source_limits() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    subprocess_policy = policy["limits"]["subprocess"]
    assert subprocess_policy["aggregate_output_bytes"] == 1_048_576
    assert subprocess_policy["retained_bytes_per_stream"] == 131_072
    assert subprocess_policy["command_timeout_seconds"] == 120
    assert policy["limits"]["candidate_source"] == {
        "max_bytes": 524_288,
        "allowed_files": 1,
    }


def test_p4_resource_policy_keeps_controller_intake_only_and_publisher_unbootstrapped() -> None:
    trust = json.loads(TRUST.read_text(encoding="utf-8"))
    assert trust["controller"]["controller_stage"] == "INTAKE_ONLY"
    assert trust["controller"]["candidate_execution_enabled"] is False
    assert trust["publisher"]["bootstrap_status"] == "UNBOOTSTRAPPED"
    assert trust["publisher"]["integration_id"] is None
    assert trust["p4_resource_policy"]["candidate_execution_enabled"] is False
    assert trust["p4_resource_policy"]["runtime_enforcement_proven"] is False


def test_p4_resource_policy_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    module = _module()
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
    with pytest.raises(module.P4ResourcePolicyError, match="duplicate JSON key"):
        module.validate(ROOT, bad, TRUST)


def test_p4_resource_policy_rejects_runtime_enforcement_claim(tmp_path: Path) -> None:
    module = _module()
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    policy["runtime_enforcement_proven"] = True
    bad = tmp_path / "policy.json"
    bad.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(module.P4ResourcePolicyError, match="runtime enforcement proof"):
        module.validate(ROOT, bad, TRUST)


def test_p4_resource_policy_rejects_missing_archive_hardening(tmp_path: Path) -> None:
    module = _module()
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    policy["archive_extraction"]["reject_symlinks"] = False
    bad = tmp_path / "policy.json"
    bad.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(module.P4ResourcePolicyError, match="archive extraction policy"):
        module.validate(ROOT, bad, TRUST)


def test_p4_resource_policy_requires_all_runtime_proofs_before_hostile_execution() -> None:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert policy["required_before_hostile_execution"] == [
        "docker_log_budget_enforced",
        "build_log_budget_enforced",
        "artifact_budget_enforced",
        "archive_safe_extraction_enforced",
        "json_bounded_parser_enforced",
        "fixture_traffic_budget_enforced",
        "execution_concurrency_budget_enforced",
        "malformed_cleanup_maps_to_unknown",
    ]
