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
    ):
        raise P4BridgeError("P4 build handover not an independently bound source")
    if (
        not isinstance(subject, dict)
        or subject.get("schema_version") != 1
        or subject.get("source_commit") != stage_handoff["source_commit"]
        or subject.get("candidate_image") != stage_handoff.get("candidate_image")
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
    outcome = comparator(reference_dir, candidate_dir)
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
        "subject_receipt_sha256": _sha(candidate_dir / "receipt.json"),
        "comparison": outcome,
        "approval_outcome": "NOT_EVALUATED",
        "runtime_proof_completed": False,
        "publisher_authorized": False,
        "p3_equivalence_claimed": False,
    }
