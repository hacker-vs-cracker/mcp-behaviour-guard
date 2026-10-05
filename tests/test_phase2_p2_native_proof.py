from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
PHASE2 = ROOT / "assurance/phase2"
CI = PHASE2 / "ci"
P2_SCRIPT = CI / "p2_native_proof.py"
BUILD_SPEC = CI / "build-adapter.json"
RUNTIME_TEMPLATE = CI / "runtime-profile-template.json"
TRUST_BOUNDARY = CI / "trust-boundary.json"
WORKFLOW = ROOT / ".github/workflows/phase2-native-amd64-proof.yml"
ISOLATION = PHASE2 / "run_isolation_check.py"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase2_p2_native_proof_test", P2_SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load P2 native proof module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_p2_source_freezes_distribution_without_promoting_runtime_or_reference() -> None:
    spec = json.loads(BUILD_SPEC.read_text(encoding="utf-8"))
    profile = json.loads(RUNTIME_TEMPLATE.read_text(encoding="utf-8"))
    boundary = json.loads(TRUST_BOUNDARY.read_text(encoding="utf-8"))

    assert spec["status"] == "P2_PROOF_PREP_FROZEN"
    assert spec["runtime_execution_enabled"] is True
    assert spec["promotion_enabled"] is False
    assert spec["wheelhouse"]["status"] == "SEALED_AT_PROOF_RUNTIME"

    distribution = spec["image_distribution"]
    assert distribution["decision_status"] == "P2_FROZEN"
    assert distribution["primary"] == "ghcr_immutable_digest"
    assert distribution["package_visibility"] == "repository_inherited"
    assert distribution["retained_oci_layout_role"] == "reviewed_alternative_not_selected"
    assert distribution["retained_oci_layout_generated"] is False
    assert distribution["retained_oci_layout_recovery_available"] is False
    assert distribution["trusted_image_publication_auth"] == (
        "github_token_packages_write_build_job_only"
    )
    assert distribution["trusted_controller_pull_auth"] == (
        "github_token_packages_read_pull_step_only"
    )
    assert distribution["credentials_removed_before_candidate_runtime"] is True
    assert distribution["moving_tag_fallback_allowed"] is False

    assert profile["status"] == "UNPROMOTED"
    assert profile["consumable"] is False
    assert profile["base_image"]["platform_manifest_digest"] is None
    assert all(value is None for value in profile["images"].values())
    assert profile["reference"]["status"] == "UNPROMOTED"

    assert boundary["runtime_adapter"]["status"] == "P2_PROOF_PREP_FROZEN"
    assert boundary["runtime_adapter"]["runtime_execution_enabled"] is True
    assert boundary["runtime_adapter"]["promotion_enabled"] is False


def test_p2_consumed_inputs_include_new_workflow_and_probe_assets() -> None:
    boundary = json.loads(TRUST_BOUNDARY.read_text(encoding="utf-8"))
    consumed = set(boundary["consumed_trusted_inputs"])
    assert {
        ".github/workflows/phase2-native-amd64-proof.yml",
        "assurance/phase2/ci/p2_native_proof.py",
        "assurance/phase2/candidate-probe/Dockerfile",
        "assurance/phase2/candidate-probe/probe.py",
    } <= consumed
    assert set(boundary["retained_historical_evidence"]).isdisjoint(consumed)


def test_p2_workflow_is_manual_native_amd64_and_separates_registry_permissions() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in text
    assert "expected_commit:" in text
    assert "EXPECTED_COMMIT: ${{ inputs.expected_commit }}" in text
    assert 'test "$GITHUB_SHA" = "$EXPECTED_COMMIT"' in text
    assert "pull_request:" not in text
    assert "workflow_run:" not in text
    assert text.count("runs-on: ubuntu-24.04") == 2

    build = text.split("  build-and-freeze:", 1)[1].split("  native-proof:", 1)[0]
    proof = text.split("  native-proof:", 1)[1]

    assert "packages: write" in build
    assert "packages: read" not in build
    assert "packages: read" in proof
    assert "packages: write" not in proof
    assert "docker logout ghcr.io" in build
    assert "docker logout ghcr.io" in proof
    assert 'rm -f "$HOME/.docker/config.json"' in proof

    assert "--require-hashes" in text
    assert "--only-binary=:all:" in text
    assert "--no-deps" in text
    assert "linux/amd64" in text
    assert "@sha256:fa7a862d74b4decf68fb7d3a85147efc14dbcd3779c0abd56c071d27a1ffee04" in text
    assert "run_isolation_check.py" in text
    assert "candidate-smoke" in text
    assert "negative-controls" in text
    assert "Classify P2 build/freeze outcome" in text
    assert "partial_ghcr_publication_requires_review" in text
    assert "automatic_ghcr_deletion_permitted" in text
    assert "trap cleanup_registry_auth EXIT" in text
    assert "! -path 'p2-proof/evidence-sha256.txt'" in text

    for forbidden in (
        "pull_request_target",
        "secrets.GITHUB_TOKEN",
        "--privileged",
        "/var/run/docker.sock:",
    ):
        assert forbidden not in text


def test_lock_coverage_requires_exact_package_version_wheels(tmp_path: Path) -> None:
    module = _module()
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "\n".join(
            [
                "alpha-pkg==1.2.3 --hash=sha256:" + ("a" * 64),
                "beta_pkg==2.0 --hash=sha256:" + ("b" * 64),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    good = [
        tmp_path / "alpha_pkg-1.2.3-py3-none-any.whl",
        tmp_path / "beta_pkg-2.0-py3-none-any.whl",
    ]
    for path in good:
        path.write_bytes(b"synthetic")

    module._validate_wheelhouse_coverage(lock, good)

    wrong = [good[0], tmp_path / "beta_pkg-2.1-py3-none-any.whl"]
    wrong[1].write_bytes(b"synthetic")
    with pytest.raises(module.P2ProofError, match="coverage mismatch"):
        module._validate_wheelhouse_coverage(lock, wrong)


def test_p2_profile_validation_requires_digest_refs_and_unpromoted_reference(
    tmp_path: Path,
) -> None:
    module = _module()
    profile = {
        "status": "P2_PROOF_ONLY",
        "consumable": False,
        "platform": "linux/amd64",
        "decision_scope": "phase2c_trusted_ci_gate_only",
        "base_image": {
            "platform_manifest_digest": (
                "sha256:fa7a862d74b4decf68fb7d3a85147efc14dbcd3779c0abd56c071d27a1ffee04"
            )
        },
        "reference": {"status": "UNPROMOTED"},
        "images": {},
    }
    for name in module.EXPECTED_IMAGES:
        profile["images"][name] = {
            "execution_ref": (
                f"ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-{name.replace('_', '-')}@"
                "sha256:" + ("a" * 64)
            ),
            "os": "linux",
            "architecture": "amd64",
            "registry_digest": "sha256:" + ("a" * 64),
            "platform_manifest_digest": "sha256:" + ("b" * 64),
            "config_digest": "sha256:" + ("c" * 64),
        }

    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")
    assert module.validate_profile(path)["reference"]["status"] == "UNPROMOTED"

    profile["images"]["evaluator"]["execution_ref"] = (
        "ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-evaluator:latest"
    )
    path.write_text(json.dumps(profile), encoding="utf-8")
    with pytest.raises(Exception, match="must be ghcr.io"):
        module.validate_profile(path)


def test_isolation_runner_supports_digest_execution_refs_and_positive_control() -> None:
    source = ISOLATION.read_text(encoding="utf-8")
    assert "def _image_ref(" in source
    assert '"execution_ref"' in source
    assert "positive_control" in source
    assert "p2-positive-" in source
    assert '"write_state": write["state"]' in source
    assert '"final_audit_complete": final["audit_complete"]' in source
    assert "expected_uid=10003" in source
