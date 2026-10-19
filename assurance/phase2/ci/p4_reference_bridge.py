"""Versioned P4 comparison against a separately verified immutable P3 reference.

The legacy gate binds a different orchestrator and cannot approve a P4 run by
copying its orchestrator hash. Comparison and approval remain separate decisions.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any


class P4BridgeError(ValueError):
    pass


PROMOTED_SHA256 = "54ddd04418211add290a597b2e775fb05953d7599b4e78014e57b24b105b6f09"
POLICY_SHA256 = "cd321216217fbc11034e0aeb0a4afaca7ae42607142cd9158e31d094f54a707f"
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def _read_file(path: Path, *, ceiling: int) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= ceiling:
        raise P4BridgeError("comparison input missing, linked or oversized")
    return path.read_bytes()


def _sha(path: Path) -> str:
    return hashlib.sha256(_read_file(path, ceiling=4_194_304)).hexdigest()


def _json_file(path: Path) -> dict[str, Any]:
    raw = _read_file(path, ceiling=4_194_304)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_bad_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise P4BridgeError("comparison sidecar is invalid strict JSON") from exc
    if type(value) is not dict:
        raise P4BridgeError("comparison sidecar is not an object")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise P4BridgeError("comparison JSON duplicate key")
        value[key] = item
    return value


def _bad_constant(_value: str) -> None:
    raise P4BridgeError("comparison JSON non-finite constant")


def _validated_context(
    candidate_dir: Path,
    *,
    subject: dict[str, Any],
    stage_handoff: dict[str, Any],
    runtime_evidence: dict[str, Any],
) -> tuple[str, str]:
    """Bind legacy null receipt.attempt_id through an external trusted sidecar.

    This is an integrity check, not producer authentication. Controller provenance
    and sealed storage remain required before a run can be considered trusted.
    """
    receipt_digest = _sha(candidate_dir / "receipt.json")
    receipt = _json_file(candidate_dir / "receipt.json")
    run = receipt.get("run")
    if (
        not isinstance(run, dict)
        or not isinstance(run.get("run_id"), str)
        or not run["run_id"]
        or run.get("attempt_id") is not None
    ):
        raise P4BridgeError("legacy candidate receipt run identity invalid")
    context = _json_file(candidate_dir / "p4-execution-context.json")
    if (
        context.get("schema_version") != 1
        or context.get("kind") != "p4_trusted_execution_context_v1"
        or context.get("receipt_sha256") != receipt_digest
        or context.get("run_id") != run["run_id"]
        or context.get("attempt_id") != subject["attempt_id"]
        or context.get("candidate_image") != subject["candidate_image"]
        or context.get("source_commit") != stage_handoff["source_commit"]
        or context.get("source_tree") != stage_handoff.get("source_tree")
        or context.get("runtime_adapter_sha256") != subject["p4_runtime_adapter_sha256"]
    ):
        raise P4BridgeError("candidate saved run not bound to trusted execution context")
    for key in ("audit", "transport", "export", "cleanup"):
        name = f"p4-{key}-evidence.json"
        raw_hash = _sha(candidate_dir / name)
        if context.get(f"{key}_sha256") != raw_hash:
            raise P4BridgeError("candidate evidence digest substitution")
        payload = _json_file(candidate_dir / name)
        if (
            payload.get("schema_version") != 1
            or payload.get("attempt_id") != subject["attempt_id"]
            or payload.get("candidate_image") != subject["candidate_image"]
            or payload.get("status") != "VERIFIED"
            or runtime_evidence.get(f"{key}_sha256") != raw_hash
        ):
            raise P4BridgeError("candidate evidence identity or outcome invalid")
    return receipt_digest, run["run_id"]


def compare_p4_saved_run(
    *,
    authority_raw: bytes,
    policy_raw: bytes,
    reference_dir: Path,
    candidate_dir: Path,
    stage_handoff: dict[str, Any],
    subject: dict[str, Any],
    runtime_evidence: dict[str, Any],
    comparator: Callable[[Path, Path], dict[str, Any]],
) -> dict[str, Any]:
    """Compare only after independently verified scope and evidence handover.

    This is not a verdict publisher and intentionally has no PASS outcome.
    A caller may later evaluate complete P4 evidence with a separately reviewed
    adjudicator. Source-only comparisons cannot bypass that authority boundary.
    """
    if (
        type(authority_raw) is not bytes
        or hashlib.sha256(authority_raw).hexdigest() != PROMOTED_SHA256
        or type(policy_raw) is not bytes
        or hashlib.sha256(policy_raw).hexdigest() != POLICY_SHA256
    ):
        raise P4BridgeError("frozen reference or resource policy bytes differ")
    try:
        authority = json.loads(authority_raw)
    except (ValueError, UnicodeError) as exc:
        raise P4BridgeError("promoted authority invalid") from exc
    if (
        not isinstance(authority, dict)
        or authority.get("status") != "PROMOTED"
        or authority.get("consumable") is not True
        or authority.get("generation", {}).get("number") != 1
        or authority.get("platform") != "linux/amd64"
        or authority.get("publisher") != {"integration_id": None, "status": "UNBOOTSTRAPPED"}
    ):
        raise P4BridgeError("promoted authority is not the accepted reference")
    ref = authority.get("reference", {})
    if not isinstance(ref, dict) or not SHA.fullmatch(ref.get("reference_receipt_sha256", "")):
        raise P4BridgeError("promoted reference receipt missing")
    if (
        not isinstance(stage_handoff, dict)
        or stage_handoff.get("schema_version") != 1
        or stage_handoff.get("kind") != "p4_stage_handoff_source_only"
        or stage_handoff.get("reference_authority_sha256") != PROMOTED_SHA256
        or stage_handoff.get("p4_policy_sha256") != POLICY_SHA256
        or stage_handoff.get("build_stage_clean") is not True
        or stage_handoff.get("pipeline_image_dependency_retained") is not True
        or stage_handoff.get("p3_equivalence_claimed") is not False
        or stage_handoff.get("runtime_enforcement_proven") is not False
        or not COMMIT.fullmatch(stage_handoff.get("source_commit", ""))
        or not COMMIT.fullmatch(stage_handoff.get("source_tree", ""))
        or not SHA.fullmatch(stage_handoff.get("candidate_source_sha256", ""))
        or not SHA.fullmatch(stage_handoff.get("trusted_dockerfile_sha256", ""))
        or not SHA.fullmatch(stage_handoff.get("build_producer_sha256", ""))
        or not SHA.fullmatch(stage_handoff.get("native_admission_sha256", ""))
        or not isinstance(stage_handoff.get("candidate_image"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", stage_handoff["candidate_image"])
    ):
        raise P4BridgeError("P4 build handover not an independently bound source")
    if (
        not isinstance(subject, dict)
        or subject.get("schema_version") != 1
        or subject.get("source_commit") != stage_handoff["source_commit"]
        or subject.get("candidate_image") != stage_handoff.get("candidate_image")
        or not isinstance(subject.get("candidate_image"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", subject["candidate_image"]) is None
        or subject.get("platform") != "linux/amd64"
        or subject.get("attempt_id") in (None, "", ref.get("origin_attempt_id"))
        or not SHA.fullmatch(subject.get("p4_runtime_adapter_sha256", ""))
        or "orchestrator_sha256" in subject
    ):
        raise P4BridgeError("new runtime subject confused with old P3 orchestrator")
    if (
        not isinstance(runtime_evidence, dict)
        or runtime_evidence.get("attempt_id") != subject["attempt_id"]
        or runtime_evidence.get("writer_fenced") is not True
        or runtime_evidence.get("fixture_finalized") is not True
        or runtime_evidence.get("positive_control_observed") is not True
        or runtime_evidence.get("artifact_publication_durable") is not True
        or runtime_evidence.get("owned_cleanup_verified") is not True
        or runtime_evidence.get("transport_counters_verified") is not True
    ):
        raise P4BridgeError("P4 effects, transport, publication or cleanup evidence incomplete")
    # This verification depends on the retained P3 artifact, not its filename alone.
    if _sha(reference_dir / "receipt.json") != ref["reference_receipt_sha256"]:
        raise P4BridgeError("retained reference receipt does not match promoted generation")
    for filename in ("receipt.json", "report.json", "tool-inventory.json"):
        _read_file(candidate_dir / filename, ceiling=4_194_304)
    receipt_digest, run_id = _validated_context(
        candidate_dir,
        subject=subject,
        stage_handoff=stage_handoff,
        runtime_evidence=runtime_evidence,
    )
    # Reject a substituted comparator; only the reviewed shipped saved-run
    # comparator may be invoked. The caller may not supply an approving stub.
    from mcp_behaviour_guard.baseline import compare_saved_runs  # type: ignore[import-untyped]

    if comparator is not compare_saved_runs:
        raise P4BridgeError("unreviewed saved-run comparator")
    preflight = {
        name: _sha(candidate_dir / name)
        for name in (
            "receipt.json",
            "report.json",
            "tool-inventory.json",
            "p4-execution-context.json",
            "p4-audit-evidence.json",
            "p4-transport-evidence.json",
            "p4-export-evidence.json",
            "p4-cleanup-evidence.json",
        )
    }
    outcome = comparator(reference_dir, candidate_dir)
    if any(_sha(candidate_dir / name) != digest for name, digest in preflight.items()):
        raise P4BridgeError("candidate evidence mutated during comparison")
    if (
        not isinstance(outcome, dict)
        or outcome.get("schema_version") != 1
        or not isinstance(outcome.get("comparability"), dict)
        or not isinstance(outcome.get("regression"), dict)
        or not isinstance(outcome.get("coverage"), dict)
    ):
        raise P4BridgeError("saved-run comparator result malformed")
    return {
        "schema_version": 1,
        "kind": "p4_to_p3_versioned_comparison_v1",
        "source_commit": stage_handoff["source_commit"],
        "subject_attempt": subject["attempt_id"],
        "subject_image": subject["candidate_image"],
        "reference_authority_sha256": PROMOTED_SHA256,
        "reference_generation": 1,
        "reference_receipt_sha256": ref["reference_receipt_sha256"],
        "subject_receipt_sha256": receipt_digest,
        "subject_run_id": run_id,
        "subject_context_sha256": preflight["p4-execution-context.json"],
        "comparison": outcome,
        "approval_outcome": "NOT_EVALUATED",
        "runtime_proof_completed": False,
        "publisher_authorized": False,
        "p3_equivalence_claimed": False,
    }
