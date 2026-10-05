from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
PHASE2 = ROOT / "assurance/phase2"
CI = PHASE2 / "ci"
BUILD_ADAPTER = CI / "build_adapter.py"
BUILD_SPEC = CI / "build-adapter.json"
RUNTIME_TEMPLATE = CI / "runtime-profile-template.json"
TRUST_BOUNDARY = CI / "trust-boundary.json"
GATE = PHASE2 / "gate/gate.py"
APPROVAL = PHASE2 / "run_approval_demo.py"

AMD64_LOCK_SHA = "a18436b0d48f7eacf5b8f4142685a12b11eed3105039e4d3a0eab2b42a3ec22b"
ARM64_LOCK_SHA = "7f135a827bad87dc89e5a359824d0abe727f376f213865330b4da8c14cead267"
AMD64_BASE_MANIFEST = "sha256:fa7a862d74b4decf68fb7d3a85147efc14dbcd3779c0abd56c071d27a1ffee04"


def _load(path: Path, name: str, *, phase2_path: bool = False) -> ModuleType:
    if phase2_path:
        sys.path.insert(0, str(PHASE2))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise AssertionError(f"could not load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        if phase2_path:
            sys.path.pop(0)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_current_adapter_preserves_p1b_authority_split_for_p2_proof() -> None:
    spec = json.loads(BUILD_SPEC.read_text(encoding="utf-8"))
    boundary = json.loads(TRUST_BOUNDARY.read_text(encoding="utf-8"))
    template = json.loads(RUNTIME_TEMPLATE.read_text(encoding="utf-8"))

    assert spec["status"] == "P2_PROOF_PREP_FROZEN"
    assert spec["platform"] == "linux/amd64"
    assert spec["decision_scope"] == "phase2c_trusted_ci_gate_only"
    assert spec["runtime_execution_enabled"] is True
    assert spec["promotion_enabled"] is False

    assert boundary["runtime_adapter"] == {
        "profile_id": "phase2c-ci-amd64-v1",
        "spec_path": "assurance/phase2/ci/build-adapter.json",
        "platform": "linux/amd64",
        "decision_scope": "phase2c_trusted_ci_gate_only",
        "status": "P2_PROOF_PREP_FROZEN",
        "runtime_execution_enabled": True,
        "promotion_enabled": False,
    }
    assert "trusted_inputs" not in boundary
    assert set(boundary["consumed_trusted_inputs"]).isdisjoint(
        boundary["retained_historical_evidence"]
    )
    assert boundary["retained_historical_evidence"] == [
        "assurance/phase2/runtime-profile.json",
        "assurance/phase2/evaluator/requirements.lock",
    ]

    assert template["platform"] == "linux/amd64"
    assert template["decision_scope"] == "phase2c_trusted_ci_gate_only"
    assert template["status"] == "UNPROMOTED"
    assert template["consumable"] is False
    assert template["base_image"]["platform_manifest_digest"] is None
    assert spec["base_image"]["characterized_platform_manifest_digest"] == AMD64_BASE_MANIFEST
    assert spec["base_image"]["runtime_profile_binding_status"] == (
        "UNPROMOTED_UNTIL_P2_P3_EVIDENCE"
    )
    assert spec["image_distribution"]["decision_status"] == "P2_FROZEN"
    assert spec["image_distribution"]["primary"] == "ghcr_immutable_digest"
    assert spec["image_distribution"]["package_visibility"] == "repository_inherited"
    assert spec["image_distribution"]["alternatives_reviewed"] == [
        "ghcr_immutable_digest",
        "retained_oci_layout",
    ]
    assert all(value is None for value in template["images"].values())


def test_build_adapter_stages_amd64_lock_under_evaluator_expected_filename(
    tmp_path: Path,
) -> None:
    module = _load(BUILD_ADAPTER, "phase2_p1b_adapter_materialize")
    manifest = module.materialize_evaluator_context(ROOT, tmp_path / "context")
    context = tmp_path / "context"

    assert (context / "Dockerfile").read_bytes() == (
        ROOT / "assurance/phase2/evaluator/Dockerfile"
    ).read_bytes()
    assert (context / "requirements.lock").read_bytes() == (
        ROOT / "assurance/phase2/ci/evaluator-requirements-amd64.lock"
    ).read_bytes()
    assert _sha(context / "requirements.lock") == AMD64_LOCK_SHA
    assert manifest["platform"] == "linux/amd64"
    assert manifest["decision_scope"] == "phase2c_trusted_ci_gate_only"
    assert manifest["runtime_execution_enabled"] is True
    assert manifest["promotion_enabled"] is False
    assert manifest["named_contexts"]["wheelhouse"]["manifest_required"] is True


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("platform", "linux/arm64", "platform must be linux/amd64"),
        (
            "decision_scope",
            "phase2b4_local_synthetic_gate_only",
            "decision_scope mismatch",
        ),
    ],
)
def test_build_adapter_refuses_wrong_platform_or_scope(
    tmp_path: Path,
    field: str,
    value: str,
    match: str,
) -> None:
    module = _load(BUILD_ADAPTER, f"phase2_p1b_adapter_refusal_{field}")
    payload = json.loads(BUILD_SPEC.read_text(encoding="utf-8"))
    payload[field] = value
    spec = tmp_path / "adapter.json"
    spec.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(module.BuildAdapterError, match=match):
        module.validate_spec(ROOT, spec)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        (
            "dockerfile_source",
            "tests/test_phase2_ci_foundation.py",
            "Dockerfile source mismatch",
        ),
        ("dockerfile_output_name", "../Dockerfile", "output name must be Dockerfile"),
    ],
)
def test_build_adapter_refuses_dockerfile_source_or_output_name(
    tmp_path: Path,
    field: str,
    value: str,
    match: str,
) -> None:
    module = _load(BUILD_ADAPTER, f"phase2_p1b_adapter_dockerfile_refusal_{field}")
    payload = json.loads(BUILD_SPEC.read_text(encoding="utf-8"))
    payload["evaluator_build_context"][field] = value
    spec = tmp_path / "adapter.json"
    spec.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(module.BuildAdapterError, match=match):
        module.validate_spec(ROOT, spec)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        (
            "characterized_platform_manifest_digest",
            "sha256:" + ("0" * 64),
            "characterized AMD64 base platform manifest mismatch",
        ),
        (
            "runtime_profile_binding_status",
            "PROMOTED",
            "base runtime-profile binding status mismatch",
        ),
    ],
)
def test_build_adapter_refuses_characterized_base_binding_drift(
    tmp_path: Path,
    field: str,
    value: str,
    match: str,
) -> None:
    module = _load(BUILD_ADAPTER, f"phase2_p1b_base_binding_refusal_{field}")
    payload = json.loads(BUILD_SPEC.read_text(encoding="utf-8"))
    payload["base_image"][field] = value
    spec = tmp_path / "adapter.json"
    spec.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(module.BuildAdapterError, match=match):
        module.validate_spec(ROOT, spec)


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (
            lambda payload: payload["image_distribution"].__setitem__("decision_status", "FROZEN"),
            "decision status mismatch",
        ),
        (
            lambda payload: payload["image_distribution"].__setitem__(
                "primary", "retained_oci_layout"
            ),
            "primary image distribution",
        ),
        (
            lambda payload: payload["image_distribution"].__setitem__(
                "retrieval_credentials_available_to_candidate_execution", True
            ),
            "retrieval credentials",
        ),
    ],
)
def test_build_adapter_refuses_distribution_boundary_drift(
    tmp_path: Path,
    mutator,
    match: str,
) -> None:
    module = _load(BUILD_ADAPTER, "phase2_p1b_distribution_refusal")
    payload = json.loads(BUILD_SPEC.read_text(encoding="utf-8"))
    mutator(payload)
    spec = tmp_path / "adapter.json"
    spec.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(module.BuildAdapterError, match=match):
        module.validate_spec(ROOT, spec)


def test_build_adapter_refuses_lock_hash_mismatch(tmp_path: Path) -> None:
    module = _load(BUILD_ADAPTER, "phase2_p1b_adapter_lock_refusal")
    payload = json.loads(BUILD_SPEC.read_text(encoding="utf-8"))
    payload["evaluator_build_context"]["dependency_lock_sha256"] = "0" * 64
    spec = tmp_path / "adapter.json"
    spec.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(module.BuildAdapterError, match="expected SHA256 mismatch"):
        module.validate_spec(ROOT, spec)


def test_historical_arm64_lock_is_retained_not_reused() -> None:
    spec = json.loads(BUILD_SPEC.read_text(encoding="utf-8"))
    historical = spec["historical_evidence"]
    assert historical["arm64_lock_reuse_allowed"] is False
    assert historical["arm64_dependency_lock_sha256"] == ARM64_LOCK_SHA
    assert _sha(ROOT / historical["arm64_dependency_lock"]) == ARM64_LOCK_SHA
    assert _sha(ROOT / spec["evaluator_build_context"]["dependency_lock_source"]) == AMD64_LOCK_SHA


def test_wheelhouse_manifest_is_exact_and_fail_closed(tmp_path: Path) -> None:
    module = _load(BUILD_ADAPTER, "phase2_p1b_adapter_wheelhouse")
    wheels = tmp_path / "wheelhouse"
    wheels.mkdir()
    wheel = wheels / "example-1.0.0-py3-none-any.whl"
    wheel.write_bytes(b"synthetic-wheel")
    manifest = {
        "schema_version": 1,
        "platform": "linux/amd64",
        "decision_scope": "phase2c_trusted_ci_gate_only",
        "files": [
            {
                "name": wheel.name,
                "size": wheel.stat().st_size,
                "sha256": _sha(wheel),
            }
        ],
    }
    manifest_path = tmp_path / "wheelhouse-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert module.validate_wheelhouse_manifest(manifest_path, wheels) == manifest

    extra = wheels / "unexpected.whl"
    extra.write_bytes(b"extra")
    with pytest.raises(module.BuildAdapterError, match="file-set mismatch"):
        module.validate_wheelhouse_manifest(manifest_path, wheels)
    extra.unlink()

    nested = wheels / "nested"
    nested.mkdir()
    with pytest.raises(module.BuildAdapterError, match="regular non-symlink"):
        module.validate_wheelhouse_manifest(manifest_path, wheels)
    nested.rmdir()

    manifest["files"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(module.BuildAdapterError, match="SHA256 mismatch"):
        module.validate_wheelhouse_manifest(manifest_path, wheels)


def test_execution_image_reference_requires_ghcr_digest_not_tag() -> None:
    module = _load(BUILD_ADAPTER, "phase2_p1b_adapter_ghcr")
    good = "ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-evaluator@sha256:" + ("a" * 64)
    assert module.validate_ghcr_digest_reference(good) == good
    with pytest.raises(module.BuildAdapterError, match="must be ghcr.io"):
        module.validate_ghcr_digest_reference(
            "ghcr.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-evaluator:latest"
        )
    with pytest.raises(module.BuildAdapterError, match="must be ghcr.io"):
        module.validate_ghcr_digest_reference(
            "ghcr.io/other/mcp-behaviour-guard-phase2-evaluator@sha256:" + ("b" * 64)
        )


def test_gate_accepts_only_explicit_supported_platform_scope_pairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _load(GATE, "phase2_p1b_gate")
    policy_path = tmp_path / "policy.json"

    def fake_sha(path: Path) -> str:
        if path == gate.EXPECTED_PATH:
            return "expected"
        if path == gate.RULES_PATH:
            return "rules"
        if path == gate.GATE_PATH:
            return "gate-source"
        return "policy-digest"

    monkeypatch.setattr(gate, "_sha", fake_sha)

    def policy(platform: str, scope: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "platform": platform,
            "decision_scope": scope,
            "images": {"gate": "gate-image"},
            "expected_checks_sha256": "expected",
            "gate_rules_sha256": "rules",
            "gate_source_sha256": "gate-source",
            "guard": {"version": "0.6.2"},
        }

    for platform, scope in (
        ("linux/arm64", "phase2b4_local_synthetic_gate_only"),
        ("linux/amd64", "phase2c_trusted_ci_gate_only"),
    ):
        policy_path.write_text(json.dumps(policy(platform, scope)), encoding="utf-8")
        loaded, digest = gate._validate_policy(policy_path, "gate-image")
        assert loaded["platform"] == platform
        assert loaded["decision_scope"] == scope
        assert digest == "policy-digest"

    policy_path.write_text(
        json.dumps(policy("linux/amd64", "phase2b4_local_synthetic_gate_only")),
        encoding="utf-8",
    )
    with pytest.raises(gate.GateError, match="decision scope"):
        gate._validate_policy(policy_path, "gate-image")

    policy_path.write_text(
        json.dumps(policy("linux/s390x", "phase2c_trusted_ci_gate_only")),
        encoding="utf-8",
    )
    with pytest.raises(gate.GateError, match="unsupported"):
        gate._validate_policy(policy_path, "gate-image")


def test_approval_policy_and_context_selection_preserve_arm64_and_enable_explicit_amd64(
    tmp_path: Path,
) -> None:
    approval = _load(APPROVAL, "phase2_p1b_approval", phase2_path=True)

    assert approval._selected_platform_scope({"platform": "linux/arm64"}) == (
        "linux/arm64",
        "phase2b4_local_synthetic_gate_only",
    )
    assert approval._selected_platform_scope(
        {
            "platform": "linux/amd64",
            "decision_scope": "phase2c_trusted_ci_gate_only",
        }
    ) == ("linux/amd64", "phase2c_trusted_ci_gate_only")

    with pytest.raises(approval.IsolationError, match="must select"):
        approval._selected_platform_scope(
            {
                "platform": "linux/amd64",
                "decision_scope": "phase2b4_local_synthetic_gate_only",
            }
        )

    inputs = {}
    for name in (
        "contract",
        "expected",
        "rules",
        "gate",
        "orchestrator",
        "runtime",
        "fixture",
    ):
        path = tmp_path / name
        path.write_text(name, encoding="utf-8")
        inputs[name] = path

    output = tmp_path / "policy.json"
    approval._make_policy(
        output=output,
        contract=inputs["contract"],
        expected_checks=inputs["expected"],
        rules=inputs["rules"],
        gate_source=inputs["gate"],
        orchestrator=inputs["orchestrator"],
        runtime_profile=inputs["runtime"],
        fixture_profile=inputs["fixture"],
        platform="linux/amd64",
        decision_scope="phase2c_trusted_ci_gate_only",
        evaluator_image="sha256:evaluator",
        fixture_image="sha256:fixture",
        gate_image="sha256:gate",
        guard_wheel_sha="a" * 64,
    )
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["platform"] == "linux/amd64"
    assert written["decision_scope"] == "phase2c_trusted_ci_gate_only"


def test_gate_decision_scope_is_selected_policy_scope_not_hardcoded() -> None:
    source = GATE.read_text(encoding="utf-8")
    assert '"scope": "phase2b4_local_synthetic_gate_only"' not in source
    assert '"scope": policy.get("decision_scope") or "unavailable"' in source
