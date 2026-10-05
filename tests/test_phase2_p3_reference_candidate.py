from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
RUNNER = ROOT / "assurance/phase2/run_approval_demo.py"
WORKFLOW = ROOT / ".github/workflows/phase2-p3-reference-candidate.yml"
PROFILE = CI / "p3-runtime-candidate.json"
TRUST = CI / "trust-boundary.json"
P3_SCRIPT = CI / "p3_reference_candidate.py"


def _module():
    spec = importlib.util.spec_from_file_location("p3_reference_candidate_test", P3_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_p3_input_is_exact_accepted_p2_runtime_and_unpromoted() -> None:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    assert profile["status"] == "P3_REFERENCE_CONSTRUCTION_INPUT"
    assert profile["consumable"] is False
    assert profile["platform"] == "linux/amd64"
    assert profile["decision_scope"] == "phase2c_trusted_ci_gate_only"
    assert profile["reference"]["status"] == "UNPROMOTED"
    assert profile["publisher"]["status"] == "UNBOOTSTRAPPED"
    assert profile["proof"]["source_commit"] == "f21f4ef7afc5704eee36df888d7d7fc98e9677b9"
    assert profile["proof"]["source_tree"] == "644285bab85478ef44d609f2f278fee4f335f572"
    assert profile["p2_acceptance"]["native_proof_run_id"] == 37284672075
    assert profile["p2_acceptance"]["native_proof_run_conclusion"] == "success"
    assert profile["p3_reference_construction"]["promotion_enabled"] is False

    for role in ("evaluator", "fixture", "gate", "vertical_candidate", "candidate_probe"):
        ref = profile["images"][role]["execution_ref"]
        assert ref.startswith("ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-")
        assert "@sha256:" in ref
        assert profile["images"][role]["architecture"] == "amd64"


def test_p3_input_validator_rejects_promotion_and_tag_refs(tmp_path: Path) -> None:
    module = _module()
    payload = json.loads(PROFILE.read_text(encoding="utf-8"))

    promoted = json.loads(json.dumps(payload))
    promoted["reference"]["status"] = "PROMOTED"
    path = tmp_path / "promoted.json"
    path.write_text(json.dumps(promoted), encoding="utf-8")
    with pytest.raises(module.P3Error, match="promoted reference"):
        module.validate_input(path)

    tagged = json.loads(json.dumps(payload))
    tagged["images"]["evaluator"]["execution_ref"] = (
        "ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-evaluator:latest"
    )
    path.write_text(json.dumps(tagged), encoding="utf-8")
    with pytest.raises(module.P3Error, match="digest execution ref"):
        module.validate_input(path)

    drifted = json.loads(json.dumps(payload))
    drifted["images"]["evaluator"]["execution_ref"] = (
        "ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-evaluator@sha256:" + ("0" * 64)
    )
    drifted["images"]["evaluator"]["registry_digest"] = "sha256:" + ("0" * 64)
    drifted["images"]["evaluator"]["platform_manifest_digest"] = "sha256:" + ("0" * 64)
    path.write_text(json.dumps(drifted), encoding="utf-8")
    with pytest.raises(module.P3Error, match="inherited runtime differs"):
        module.validate_input(path)


def test_approval_runner_uses_digest_execution_refs_and_binds_selected_images() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert "def _image_ref(" in source
    assert '"execution_ref"' in source
    assert '_image_ref(images, "evaluator")' in source
    assert '_image_ref(images, "fixture")' in source
    assert '_image_ref(images, "gate")' in source
    assert '_image_ref(images, "vertical_candidate")' in source
    assert "selected gate image differs from runtime profile" in source
    assert "selected candidate image differs from runtime profile" in source
    assert '"scope": approval_scope' in source
    assert '"platform": platform' in source
    assert '"decision_scope": decision_scope' in source
    assert '"phase2c_reference_candidate_only"' in source


def test_p3_workflow_is_manual_exact_commit_packages_read_only_and_stops_before_promotion() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "expected_commit:" in text
    assert "EXPECTED_COMMIT: ${{ inputs.expected_commit }}" in text
    assert 'test "$GITHUB_SHA" = "$EXPECTED_COMMIT"' in text
    assert "runs-on: ubuntu-24.04" in text
    assert "packages: read" in text
    assert "packages: write" not in text
    assert "docker push" not in text
    assert "run_approval_demo.py" in text
    assert "p3_reference_candidate.py adjudicate" in text
    assert "trap cleanup_registry_auth EXIT" in text
    assert 'rglob("*.json")' in text
    assert 'rglob("*recovery*.json")' not in text
    assert "finish_only_evidence" in text
    assert "id: cleanup" in text
    assert "CLEANUP_OUTCOME: ${{ steps.cleanup.outcome }}" in text
    assert 'cleanup_problem=runtime_attempted and cleanup!="success"' in text
    assert 'and cleanup=="success"' in text
    assert "docker-baseline-cleanup:" in text
    assert "reference_promotion" not in text
    p3_source = P3_SCRIPT.read_text(encoding="utf-8")
    assert 'row.get("operation") == "record_write"' in p3_source
    assert 'good_decision.get("assessed_outcome")' in p3_source
    assert 'good_decision.get("outcome")' not in p3_source
    gate_source = (ROOT / "assurance/phase2/gate/gate.py").read_text(encoding="utf-8")
    assert '"assessed_outcome": outcome' in gate_source
    assert "gh pr " not in text
    assert "gh api " not in text
    assert "pull_request_target" not in text


def test_trust_boundary_records_p3_construction_without_publisher_or_promotion() -> None:
    boundary = json.loads(TRUST.read_text(encoding="utf-8"))
    p3 = boundary["p3_reference_candidate"]
    assert p3["stage"] == "REFERENCE_CONSTRUCTION_ONLY"
    assert p3["platform"] == "linux/amd64"
    assert p3["packages_permission"] == "read"
    assert p3["promotion_enabled"] is False
    assert p3["publisher_bootstrap_enabled"] is False
    assert p3["ruleset_mutation_enabled"] is False
    consumed = set(boundary["consumed_trusted_inputs"])
    assert {
        ".github/workflows/phase2-p3-reference-candidate.yml",
        "assurance/phase2/ci/p3-runtime-candidate.json",
        "assurance/phase2/ci/p3_reference_candidate.py",
    } <= consumed


def test_committed_bundle_manifest_validation_detects_tamper(tmp_path: Path) -> None:
    module = _module()
    bundle = tmp_path / "completed" / "candidate-good"
    bundle.mkdir(parents=True)
    decision = bundle / "decision.json"
    pointer = bundle / "authority-pointer.json"
    decision.write_text('{"assessed_outcome":"PASS"}\n', encoding="utf-8")
    pointer.write_text('{"approval_bundle_digest":"abc"}\n', encoding="utf-8")

    import hashlib

    files = {
        decision.name: hashlib.sha256(decision.read_bytes()).hexdigest(),
        pointer.name: hashlib.sha256(pointer.read_bytes()).hexdigest(),
    }
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "files": files,
                "manifest_self_hash": None,
            }
        ),
        encoding="utf-8",
    )
    module._validate_committed_bundle(bundle)

    decision.write_text('{"assessed_outcome":"BLOCK"}\n', encoding="utf-8")
    with pytest.raises(module.P3Error, match="manifest hash mismatch"):
        module._validate_committed_bundle(bundle)
