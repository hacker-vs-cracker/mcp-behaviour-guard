"""Versioned P4 comparison against a separately verified immutable P3 reference.

The legacy gate binds a different orchestrator and cannot approve a P4 run by
copying its orchestrator hash. Comparison and approval remain separate decisions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import p4_resource_enforcement as bounds


class P4BridgeError(ValueError):
    pass


PROMOTED_SHA256 = "54ddd04418211add290a597b2e775fb05953d7599b4e78014e57b24b105b6f09"
POLICY_SHA256 = "cd321216217fbc11034e0aeb0a4afaca7ae42607142cd9158e31d094f54a707f"
SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def _read_file(path: Path, *, ceiling: int) -> bytes:
    """Read an exact, regular, single-linked input via an O_NOFOLLOW fd.

    File-level atomic identity is not producer provenance. The controller must
    stage inputs inside a trusted private directory before invoking this bridge.
    """
    if type(ceiling) is not int or not 0 < ceiling <= 4_194_304:
        raise P4BridgeError("comparison read ceiling invalid")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or not 0 < before.st_size <= ceiling
            ):
                raise P4BridgeError("comparison input missing, linked or oversized")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(65_536, remaining))
                if not chunk:
                    raise P4BridgeError("comparison input changed or truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(fd)
            named = path.lstat()

            def identity(st: os.stat_result) -> tuple[int, int, int, int, int]:
                return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

            if (
                identity(before) != identity(after)
                or identity(before) != identity(named)
                or not stat.S_ISREG(named.st_mode)
            ):
                raise P4BridgeError("comparison input changed during read")
            return b"".join(chunks)
        finally:
            os.close(fd)
    except OSError as exc:
        raise P4BridgeError("comparison input inaccessible or changed") from exc


def _sha(path: Path) -> str:
    return hashlib.sha256(_read_file(path, ceiling=4_194_304)).hexdigest()


def _json_bytes(raw: bytes, *, schema_version: int | None = 1) -> dict[str, Any]:
    """Validate exact bytes under frozen P4 JSON limits and legacy receipt rules."""
    shape = {
        "max_depth": 32,
        "max_array_items": 1024,
        "max_object_members": 1024,
        "max_string_bytes": 65536,
    }
    try:
        value = bounds._load_object_bytes(
            raw, max_bytes=1_048_576, label="comparison sidecar", shape=shape
        )
        bounds._validate_json_shape(value, shape)
    except bounds.P4ResourceEnforcementError as exc:
        raise P4BridgeError("comparison sidecar is not bounded strict JSON") from exc
    version = value.get("schema_version")
    if schema_version is None:
        if version is not None and (type(version) is not int or version != 1):
            raise P4BridgeError("unsupported legacy receipt version")
    elif type(version) is not int or version != schema_version:
        raise P4BridgeError("comparison sidecar schema_version invalid")
    return value


def _json_file(path: Path, *, schema_version: int | None = 1) -> dict[str, Any]:
    return _json_bytes(_read_file(path, ceiling=1_048_576), schema_version=schema_version)


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
    receipt_bytes = _read_file(candidate_dir / "receipt.json", ceiling=1_048_576)
    receipt_digest = hashlib.sha256(receipt_bytes).hexdigest()
    receipt = _json_bytes(receipt_bytes, schema_version=None)
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
        evidence_bytes = _read_file(candidate_dir / name, ceiling=1_048_576)
        raw_hash = hashlib.sha256(evidence_bytes).hexdigest()
        if context.get(f"{key}_sha256") != raw_hash:
            raise P4BridgeError("candidate evidence digest substitution")
        payload = _json_bytes(evidence_bytes)
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
