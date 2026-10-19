from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"


def load():
    spec = importlib.util.spec_from_file_location(
        "p4_reference_bridge_test", CI / "p4_reference_bridge.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixture(tmp_path):
    m = load()
    authority = (CI / "p3-promoted-authority.json").read_bytes()
    policy = (CI / "p4-resource-policy.json").read_bytes()
    expected = json.loads(authority)["reference"]["reference_receipt_sha256"]
    # Synthetic reference material cannot match the real promoted receipt.
    # A positive unit test must not replace or weaken that immutable identity.
    ref, run = tmp_path / "reference", tmp_path / "run"
    ref.mkdir()
    run.mkdir()
    (ref / "receipt.json").write_bytes(b"{}")
    for name in ("report.json", "receipt.json", "tool-inventory.json"):
        (run / name).write_bytes(b'{"schema_version":1}')
    image = "sha256:" + "a" * 64
    stage = {
        "schema_version": 1,
        "kind": "p4_stage_handoff_source_only",
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "candidate_source_sha256": "c" * 64,
        "trusted_dockerfile_sha256": "d" * 64,
        "build_producer_sha256": "e" * 64,
        "native_admission_sha256": "f" * 64,
        "candidate_image": image,
        "reference_authority_sha256": m.PROMOTED_SHA256,
        "p4_policy_sha256": m.POLICY_SHA256,
        "build_stage_clean": True,
        "pipeline_image_dependency_retained": True,
        "p3_equivalence_claimed": False,
        "runtime_enforcement_proven": False,
    }
    subject = {
        "schema_version": 1,
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "candidate_source_sha256": "c" * 64,
        "trusted_dockerfile_sha256": "d" * 64,
        "build_producer_sha256": "e" * 64,
        "native_admission_sha256": "f" * 64,
        "candidate_image": image,
        "platform": "linux/amd64",
        "attempt_id": "p4-run-1",
        "p4_runtime_adapter_sha256": "b" * 64,
    }
    evidence = {
        "attempt_id": "p4-run-1",
        "writer_fenced": True,
        "fixture_finalized": True,
        "positive_control_observed": True,
        "artifact_publication_durable": True,
        "owned_cleanup_verified": True,
        "transport_counters_verified": True,
    }
    args = dict(
        authority_raw=authority,
        policy_raw=policy,
        reference_dir=ref,
        candidate_dir=run,
        stage_handoff=stage,
        subject=subject,
        runtime_evidence=evidence,
        comparator=lambda *_: pytest.fail("should not compare unverified reference"),
    )
    return m, args, expected


def test_missing_real_reference_refuses_to_compare(tmp_path):
    m, args, expected = fixture(tmp_path)
    assert expected != hashlib.sha256(b"{}").hexdigest()
    with pytest.raises(m.P4BridgeError, match="retained reference receipt"):
        m.compare_p4_saved_run(**args)


def test_unsafe_p3_aliases_or_incomplete_evidence_reject_early(tmp_path):
    m, args, _ = fixture(tmp_path)
    for value in (None, "bad", "a" * 40):
        altered = dict(args, subject=dict(args["subject"], orchestrator_sha256=value))
        with pytest.raises(m.P4BridgeError, match="old P3 orchestrator"):
            m.compare_p4_saved_run(**altered)
    for name in (
        "writer_fenced",
        "fixture_finalized",
        "positive_control_observed",
        "artifact_publication_durable",
        "owned_cleanup_verified",
        "transport_counters_verified",
    ):
        altered = dict(args, runtime_evidence={**args["runtime_evidence"], name: False})
        with pytest.raises(m.P4BridgeError, match="incomplete"):
            m.compare_p4_saved_run(**altered)
    altered = dict(args, stage_handoff={**args["stage_handoff"], "p3_equivalence_claimed": True})
    with pytest.raises(m.P4BridgeError):
        m.compare_p4_saved_run(**altered)


def test_reference_bytes_and_reused_p3_attempt_reject(tmp_path):
    m, args, _ = fixture(tmp_path)
    with pytest.raises(m.P4BridgeError):
        m.compare_p4_saved_run(**dict(args, authority_raw=b"{}"))
    authority = json.loads(args["authority_raw"])
    altered = dict(
        args, subject={**args["subject"], "attempt_id": authority["reference"]["origin_attempt_id"]}
    )
    with pytest.raises(m.P4BridgeError):
        m.compare_p4_saved_run(**altered)


def test_no_nullable_or_relabelled_p4_image_before_any_comparison(tmp_path):
    m, args, _ = fixture(tmp_path)
    for subject, stage in (
        (
            {**args["subject"], "candidate_image": None},
            {**args["stage_handoff"], "candidate_image": None},
        ),
        ({**args["subject"], "candidate_image": "sha256:" + "e" * 64}, args["stage_handoff"]),
        (args["subject"], {**args["stage_handoff"], "source_tree": "not-a-git-tree"}),
    ):
        with pytest.raises(m.P4BridgeError):
            m.compare_p4_saved_run(**{**args, "subject": subject, "stage_handoff": stage})


def test_versioned_context_binds_legacy_receipt_and_each_evidence_file(tmp_path):
    m = load()
    image = "sha256:" + "a" * 64
    receipt = {"run": {"run_id": "saved-run-1", "attempt_id": None}}
    (tmp_path / "receipt.json").write_text(json.dumps(receipt))
    stage = {"source_commit": "b" * 40, "source_tree": "c" * 40}
    subject = {
        "attempt_id": "p4-test-1",
        "candidate_image": image,
        "p4_runtime_adapter_sha256": "d" * 64,
    }
    evidence = {}
    context = {
        "schema_version": 1,
        "kind": "p4_trusted_execution_context_v1",
        "receipt_sha256": hashlib.sha256((tmp_path / "receipt.json").read_bytes()).hexdigest(),
        "run_id": "saved-run-1",
        "attempt_id": subject["attempt_id"],
        "candidate_image": image,
        "source_commit": stage["source_commit"],
        "source_tree": stage["source_tree"],
        "runtime_adapter_sha256": subject["p4_runtime_adapter_sha256"],
    }
    for key in ("audit", "transport", "export", "cleanup"):
        target = tmp_path / f"p4-{key}-evidence.json"
        target.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "attempt_id": "p4-test-1",
                    "candidate_image": image,
                    "status": "VERIFIED",
                }
            )
        )
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        evidence[f"{key}_sha256"] = digest
        context[f"{key}_sha256"] = digest
    (tmp_path / "p4-execution-context.json").write_text(json.dumps(context))
    digest, run_id = m._validated_context(
        tmp_path, subject=subject, stage_handoff=stage, runtime_evidence=evidence
    )
    assert digest == context["receipt_sha256"] and run_id == "saved-run-1"
    with pytest.raises(m.P4BridgeError):
        m._validated_context(
            tmp_path,
            subject={**subject, "attempt_id": "relabelled"},
            stage_handoff=stage,
            runtime_evidence=evidence,
        )
    (tmp_path / "p4-audit-evidence.json").write_text("{}")
    with pytest.raises(m.P4BridgeError):
        m._validated_context(
            tmp_path, subject=subject, stage_handoff=stage, runtime_evidence=evidence
        )
