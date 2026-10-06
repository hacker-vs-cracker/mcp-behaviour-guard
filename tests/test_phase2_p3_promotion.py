from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
AUTHORITY = CI / "p3-promoted-authority.json"
TRUST = CI / "trust-boundary.json"
CONSTRUCTION_PROFILE = CI / "p3-runtime-candidate.json"
PROMOTION = CI / "p3_promotion.py"


def _module():
    spec = importlib.util.spec_from_file_location("p3_promotion_test", PROMOTION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_promoted_authority_validates_and_keeps_construction_input_immutable() -> None:
    module = _module()
    authority = module.validate_authority(ROOT, AUTHORITY, TRUST)
    assert authority["status"] == "PROMOTED"
    assert authority["consumable"] is True
    assert authority["generation"] == {
        "number": 1,
        "supersedes": None,
        "renewal_rule": "new-reference-requires-new-reviewed-construction-and-promotion",
    }

    construction = json.loads(CONSTRUCTION_PROFILE.read_text(encoding="utf-8"))
    assert construction["status"] == "P3_REFERENCE_CONSTRUCTION_INPUT"
    assert construction["consumable"] is False
    assert construction["reference"]["status"] == "UNPROMOTED"
    assert module._sha256(CONSTRUCTION_PROFILE) == module.EXPECTED_RUNTIME_PROFILE_SHA256


def test_promoted_authority_binds_exact_reviewed_construction_and_eight_case_matrix() -> None:
    authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    construction = authority["construction"]
    assert construction["source_commit"] == "cd1561d833b4918c3d2b082f2992a53a675481f8"
    assert construction["source_tree"] == "aa7b6d1997da9d0ffdcaa9ad481966f44b6a5570"
    assert construction["run_id"] == 37407853746
    assert construction["run_attempt"] == 1
    assert construction["artifact_digest"] == (
        "sha256:4cecd66755094546c2db096623a8e024f2243669176d97015c5a0805f27c38ae"
    )
    assert authority["reference"]["origin_attempt_id"] == "reference-36eba55f59"
    assert authority["reference"]["approval_bundle_digest"] == (
        "054304a1d9ad728e7a1fc2b656a0be42b8b05acbf26d8164d3f7747d328bdb5c"
    )
    assert authority["evidence"]["outcomes"] == {
        "candidate-good": "PASS",
        "candidate-write": "BLOCK",
        "candidate-review": "REVIEW",
        "candidate-missing": "INVALID",
        "tampered-context": "INVALID",
        "swapped-run": "INVALID",
        "stale-attempt": "INVALID",
        "tampered-approval": "INVALID",
    }
    assert authority["evidence"]["actual_gate_pass"] is True
    assert authority["evidence"]["whole_attempt_audit_complete"] is True
    assert authority["evidence"]["cleanup_complete"] is True
    assert authority["evidence"]["finish_only_recovery_required"] is False


def test_promotion_binds_durable_evidence_without_self_hash_cycle() -> None:
    module = _module()
    authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    trust = json.loads(TRUST.read_text(encoding="utf-8"))

    assert authority["retention"]["mode"] == "durable_hashed_local_archive"
    assert authority["retention"]["archive_sha256"] == (
        "0a70a9688ef72b47420aab2e2e9d5f3875d94bb722545c65ccbb1ab033750ef4"
    )
    assert authority["retention"]["workflow_evidence_manifest_sha256"] == (
        "d7d238a92a628adbe5bafe48249e1db6e3135db08a907d56fb49109aedcff339"
    )
    assert "authority_sha256" not in json.dumps(authority)
    assert trust["p3_promotion"]["authority_sha256"] == module._sha256(AUTHORITY)


def test_promotion_keeps_publisher_p4_and_ruleset_out_of_scope() -> None:
    authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    trust = json.loads(TRUST.read_text(encoding="utf-8"))
    assert authority["publisher"] == {"integration_id": None, "status": "UNBOOTSTRAPPED"}
    assert authority["ruleset_mutation_performed"] is False
    assert trust["publisher"]["bootstrap_status"] == "UNBOOTSTRAPPED"
    assert trust["publisher"]["integration_id"] is None
    assert trust["controller"]["candidate_execution_enabled"] is False
    assert trust["p3_reference_candidate"]["promotion_enabled"] is False
    assert trust["p3_promotion"]["publisher_bootstrap_enabled"] is False
    assert trust["p3_promotion"]["ruleset_mutation_enabled"] is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("generation", "authority generation"),
        ("approval", "approval bundle digest"),
        ("matrix", "eight-case outcome matrix"),
        ("archive", "retained archive digest"),
        ("finish-only", "finish-only recovery"),
    ],
)
def test_promotion_validator_rejects_authority_drift(
    tmp_path: Path, mutation: str, message: str
) -> None:
    module = _module()
    authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    trust = json.loads(TRUST.read_text(encoding="utf-8"))

    if mutation == "generation":
        authority["generation"]["number"] = 2
    elif mutation == "approval":
        authority["reference"]["approval_bundle_digest"] = "0" * 64
    elif mutation == "matrix":
        authority["evidence"]["outcomes"]["candidate-good"] = "REVIEW"
    elif mutation == "archive":
        authority["retention"]["archive_sha256"] = "0" * 64
    elif mutation == "finish-only":
        authority["evidence"]["finish_only_recovery_required"] = True
    else:
        raise AssertionError(mutation)

    authority_path = tmp_path / "authority.json"
    trust_path = tmp_path / "trust.json"
    _write(authority_path, authority)
    trust["p3_promotion"]["authority_path"] = str(authority_path.relative_to(tmp_path))
    trust["p3_promotion"]["authority_sha256"] = module._sha256(authority_path)
    _write(trust_path, trust)

    with pytest.raises(module.PromotionError, match=message):
        module.validate_authority(ROOT, authority_path, trust_path)
