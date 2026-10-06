from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

EXPECTED_PLATFORM = "linux/amd64"
EXPECTED_SCOPE = "phase2c_trusted_ci_gate_only"
EXPECTED_P2_SOURCE = "f21f4ef7afc5704eee36df888d7d7fc98e9677b9"
EXPECTED_P2_TREE = "644285bab85478ef44d609f2f278fee4f335f572"
EXPECTED_P2_RUN_ID = 37284672075
EXPECTED_P2_RUN_ATTEMPT = 1
EXPECTED_P2_RUNTIME_SHA = "297e93331c7b92cf2f3e8f4c34ab03da4f33b48cb17c9a8ef22de3df32f98ad1"
EXPECTED_P2_ARCHIVE_SHA = "390e4f1650b5c70bfdcba1592151243456ba7dde198ba7f29dc6df69c97c9876"
EXPECTED_P2_BUILD_ARTIFACT_DIGEST = (
    "sha256:d7b44b16ba4d75a2137da1afa65763329a23577349086b2712c57006a288a549"
)
EXPECTED_P2_NATIVE_ARTIFACT_DIGEST = (
    "sha256:cea14adbf611041fea5f20057402796b6ac5c9a8d9b35c7362e00a792cd7c13e"
)
EXPECTED_P2_LOCAL_ADJUDICATION_SHA = (
    "16fc0bf7fb1e639f7084adef48853abc0f0492189cfe03d65a25e7905a95dd1b"
)
EXPECTED_BASE = "sha256:fa7a862d74b4decf68fb7d3a85147efc14dbcd3779c0abd56c071d27a1ffee04"
EXPECTED_LOCK = "a18436b0d48f7eacf5b8f4142685a12b11eed3105039e4d3a0eab2b42a3ec22b"
EXPECTED_IMAGES = {"evaluator", "fixture", "gate", "vertical_candidate", "candidate_probe"}
EXPECTED_OUTCOMES = {
    "candidate-good": "PASS",
    "candidate-write": "BLOCK",
    "candidate-review": "REVIEW",
    "candidate-missing": "INVALID",
    "tampered-context": "INVALID",
    "swapped-run": "INVALID",
    "stale-attempt": "INVALID",
    "tampered-approval": "INVALID",
}
PRIMARY_CANDIDATE_CASES = (
    "candidate-good",
    "candidate-write",
    "candidate-review",
    "candidate-missing",
)
DIGEST_REF = re.compile(
    r"^ghcr\.io/hacker-vs-cracker/mcp-behaviour-guard-phase2-[a-z0-9-]+@sha256:[0-9a-f]{64}$"
)


class P3Error(RuntimeError):
    pass


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise P3Error(f"JSON must be an object: {path}")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json_sha(value: Any) -> str:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _accepted_p2_projection(profile: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(profile)
    value.pop("p2_acceptance", None)
    value.pop("p3_reference_construction", None)
    value["status"] = "P2_PROOF_ONLY"
    return value


def _validate_committed_bundle(bundle_dir: Path) -> None:
    manifest = _load(bundle_dir / "manifest.json")
    if manifest.get("schema_version") != 1:
        raise P3Error("committed result manifest schema mismatch")
    if manifest.get("manifest_self_hash") is not None:
        raise P3Error("committed result manifest_self_hash must remain null")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise P3Error("committed result manifest file map missing")
    if not all(isinstance(name, str) and isinstance(digest, str) for name, digest in files.items()):
        raise P3Error("committed result manifest file map invalid")
    actual_names = {
        path.name
        for path in bundle_dir.iterdir()
        if path.is_file() and path.name != "manifest.json"
    }
    if set(files) != actual_names:
        raise P3Error(
            f"committed result manifest file set mismatch: expected={sorted(files)} "
            f"actual={sorted(actual_names)}"
        )
    for name, expected in files.items():
        if _sha(bundle_dir / name) != expected:
            raise P3Error(f"committed result manifest hash mismatch: {name}")


def _nonempty_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value)


def _source_validation_has_errors(decision: dict[str, Any]) -> bool:
    sources = decision.get("source_validation")
    if not isinstance(sources, dict):
        return False
    return any(
        isinstance(entry, dict) and _nonempty_list(entry.get("errors"))
        for entry in sources.values()
    )


def _validate_case_semantics(case: str, decision: dict[str, Any]) -> None:
    outcome = decision.get("assessed_outcome")
    expected = EXPECTED_OUTCOMES[case]
    if outcome != expected:
        raise P3Error(
            f"committed result outcome mismatch for {case}: expected={expected} actual={outcome!r}"
        )

    if case == "candidate-good":
        if (
            decision.get("authority_binding") != "valid"
            or decision.get("subject_binding") != "valid"
            or decision.get("evidence_completeness") != "complete"
        ):
            raise P3Error("candidate-good committed decision lacks valid complete bindings")
    elif case == "candidate-review":
        if not _nonempty_list(decision.get("review_reasons")):
            raise P3Error("candidate-review committed decision lacks a structured review cause")
    elif case == "candidate-missing":
        if not (
            decision.get("evidence_completeness") == "invalid"
            or _nonempty_list(decision.get("completion_errors"))
            or _source_validation_has_errors(decision)
        ):
            raise P3Error("candidate-missing committed decision lacks structured invalid evidence")
    elif case == "tampered-context":
        if not (
            decision.get("subject_binding") == "invalid"
            or _nonempty_list(decision.get("binding_errors"))
        ):
            raise P3Error("tampered-context committed decision lacks subject/binding invalidity")
    elif case == "swapped-run":
        if not (
            decision.get("subject_binding") == "invalid"
            or _nonempty_list(decision.get("binding_errors"))
            or decision.get("evidence_completeness") == "invalid"
            or _nonempty_list(decision.get("completion_errors"))
            or _source_validation_has_errors(decision)
        ):
            raise P3Error("swapped-run committed decision lacks structural mismatch evidence")
    elif case == "stale-attempt":
        if not (
            decision.get("subject_binding") == "invalid"
            or _nonempty_list(decision.get("binding_errors"))
        ):
            raise P3Error("stale-attempt committed decision lacks attempt/binding invalidity")
    elif case == "tampered-approval" and not (
        decision.get("authority_binding") == "invalid"
        or _nonempty_list(decision.get("authority_errors"))
    ):
        raise P3Error("tampered-approval committed decision lacks authority invalidity")


def _validate_committed_matrix(
    *,
    output_dir: Path,
    summary: dict[str, Any],
    candidate_ids: dict[str, Any],
    approval_digest: str,
    policy_digest: str,
) -> dict[str, dict[str, Any]]:
    completed = output_dir / "results" / "completed"
    if not completed.is_dir():
        raise P3Error("committed result directory missing")

    expected_cases = set(EXPECTED_OUTCOMES)
    actual_cases = {path.name for path in completed.iterdir()}
    if actual_cases != expected_cases:
        raise P3Error(
            "committed result case set mismatch: "
            f"expected={sorted(expected_cases)} actual={sorted(actual_cases)}"
        )

    decisions: dict[str, dict[str, Any]] = {}
    for case, expected_outcome in EXPECTED_OUTCOMES.items():
        bundle_dir = completed / case
        if bundle_dir.is_symlink() or not bundle_dir.is_dir():
            raise P3Error(f"committed result case is not a real directory: {case}")
        _validate_committed_bundle(bundle_dir)
        decision = _load(bundle_dir / "decision.json")
        pointer = _load(bundle_dir / "authority-pointer.json")
        if decision.get("assessed_outcome") != expected_outcome:
            raise P3Error(
                f"committed result outcome mismatch for {case}: "
                f"expected={expected_outcome} actual={decision.get('assessed_outcome')!r}"
            )
        if summary["outcomes"].get(case) != decision.get("assessed_outcome"):
            raise P3Error(f"summary/committed decision mismatch for {case}")
        if pointer.get("approval_bundle_digest") != approval_digest:
            raise P3Error(f"committed result points to wrong approval authority: {case}")
        if pointer.get("policy_profile_digest") != policy_digest:
            raise P3Error(f"committed result points to wrong policy: {case}")
        if case in PRIMARY_CANDIDATE_CASES:
            context = _load(bundle_dir / "execution-context.json")
            if context.get("attempt_id") != candidate_ids[case]:
                raise P3Error(f"committed result attempt binding mismatch: {case}")
        if case == "candidate-write":
            committed_snapshot = _load(bundle_dir / "final-snapshot.json")
            committed_rows = [
                row
                for row in committed_snapshot.get("requests", [])
                if isinstance(row, dict) and row.get("state") == "COMMITTED"
            ]
            audit_rows = [
                row
                for row in committed_snapshot.get("audit", [])
                if isinstance(row, dict) and row.get("operation") == "record_write"
            ]
            committed_request_ids = {
                str(row.get("request_id"))
                for row in committed_rows
                if row.get("request_id") is not None
            }
            audited_request_ids = {
                str(row.get("request_id"))
                for row in audit_rows
                if row.get("request_id") is not None
            }
            if (
                not committed_rows
                or not audit_rows
                or not (committed_request_ids & audited_request_ids)
                or committed_snapshot.get("audit_complete") is not True
            ):
                raise P3Error(
                    "candidate-write committed bundle lacks matching committed/audited write"
                )
        _validate_case_semantics(case, decision)
        decisions[case] = decision
    return decisions


def validate_input(path: Path) -> dict[str, Any]:
    profile = _load(path)
    if profile.get("status") != "P3_REFERENCE_CONSTRUCTION_INPUT":
        raise P3Error("P3 input status mismatch")
    if profile.get("consumable") is not False:
        raise P3Error("P3 input must remain non-consumable")
    if profile.get("platform") != EXPECTED_PLATFORM:
        raise P3Error("P3 input platform mismatch")
    if profile.get("decision_scope") != EXPECTED_SCOPE:
        raise P3Error("P3 input decision scope mismatch")
    if profile.get("reference", {}).get("status") != "UNPROMOTED":
        raise P3Error("P3 input must not contain a promoted reference")
    if profile.get("publisher", {}).get("status") != "UNBOOTSTRAPPED":
        raise P3Error("P3 must not bootstrap publisher authority")
    proof = profile.get("proof") or {}
    if (
        proof.get("source_commit") != EXPECTED_P2_SOURCE
        or proof.get("source_tree") != EXPECTED_P2_TREE
    ):
        raise P3Error("P3 input is not bound to the accepted P2 source")
    if profile.get("base_image", {}).get("platform_manifest_digest") != EXPECTED_BASE:
        raise P3Error("P3 input base manifest mismatch")
    if profile.get("evaluator_lock", {}).get("requirements_sha256") != EXPECTED_LOCK:
        raise P3Error("P3 input AMD64 lock mismatch")
    acceptance = profile.get("p2_acceptance") or {}
    if acceptance.get("native_proof_run_id") != EXPECTED_P2_RUN_ID:
        raise P3Error("P3 input P2 run identity mismatch")
    if acceptance.get("native_proof_run_attempt") != EXPECTED_P2_RUN_ATTEMPT:
        raise P3Error("P3 input P2 run-attempt identity mismatch")
    if acceptance.get("native_proof_run_conclusion") != "success":
        raise P3Error("P3 input does not point to a successful P2 run")
    if acceptance.get("runtime_profile_sha256") != EXPECTED_P2_RUNTIME_SHA:
        raise P3Error("P3 input accepted P2 runtime-profile digest mismatch")
    if acceptance.get("native_run_archive_sha256") != EXPECTED_P2_ARCHIVE_SHA:
        raise P3Error("P3 input accepted P2 archive digest mismatch")
    if acceptance.get("build_artifact_digest") != EXPECTED_P2_BUILD_ARTIFACT_DIGEST:
        raise P3Error("P3 input accepted P2 build-artifact digest mismatch")
    if acceptance.get("native_proof_artifact_digest") != EXPECTED_P2_NATIVE_ARTIFACT_DIGEST:
        raise P3Error("P3 input accepted P2 proof-artifact digest mismatch")
    if acceptance.get("local_adjudication_sha256") != EXPECTED_P2_LOCAL_ADJUDICATION_SHA:
        raise P3Error("P3 input accepted P2 adjudication digest mismatch")
    stage = profile.get("p3_reference_construction") or {}
    if stage.get("promotion_enabled") is not False:
        raise P3Error("P3 construction input must not enable promotion")
    if (
        stage.get("publisher_enabled") is not False
        or stage.get("ruleset_mutation_enabled") is not False
    ):
        raise P3Error("P3 construction input crosses publisher/enforcement boundary")
    images = profile.get("images")
    if not isinstance(images, dict) or set(images) != EXPECTED_IMAGES:
        raise P3Error("P3 input image set mismatch")
    for name, identity in images.items():
        if not isinstance(identity, dict):
            raise P3Error(f"invalid image identity: {name}")
        ref = identity.get("execution_ref")
        if not isinstance(ref, str) or not DIGEST_REF.fullmatch(ref):
            raise P3Error(f"invalid digest execution ref for {name}")
        if identity.get("os") != "linux" or identity.get("architecture") != "amd64":
            raise P3Error(f"wrong image platform for {name}")
    if _canonical_json_sha(_accepted_p2_projection(profile)) != EXPECTED_P2_RUNTIME_SHA:
        raise P3Error("P3 input inherited runtime differs from accepted P2 runtime profile")
    return profile


def image_ref(profile: dict[str, Any], name: str) -> str:
    identity = profile["images"].get(name)
    if not isinstance(identity, dict):
        raise P3Error(f"missing image identity: {name}")
    ref = identity.get("execution_ref")
    if not isinstance(ref, str) or not DIGEST_REF.fullmatch(ref):
        raise P3Error(f"invalid execution ref: {name}")
    return ref


def execution_refs(path: Path) -> None:
    profile = validate_input(path)
    for name in ("evaluator", "fixture", "gate", "vertical_candidate"):
        print(image_ref(profile, name))


def named_ref(path: Path, name: str) -> None:
    profile = validate_input(path)
    if name not in {"evaluator", "fixture", "gate", "vertical_candidate"}:
        raise P3Error(f"unsupported image role: {name}")
    print(image_ref(profile, name))


def _terminal_request_states(final_snapshot: dict[str, Any]) -> bool:
    terminal = {"COMMITTED", "REJECTED", "ROLLED_BACK", "FAILED"}
    rows = final_snapshot.get("requests")
    return isinstance(rows, list) and all(
        isinstance(row, dict) and row.get("state") in terminal for row in rows
    )


def adjudicate(*, repo: Path, profile_path: Path, output_dir: Path, result: Path) -> dict[str, Any]:
    profile = validate_input(profile_path)
    summary = _load(output_dir / "approval-summary.json")
    if summary.get("scope") != "phase2c_reference_candidate_only":
        raise P3Error(f"unexpected P3 approval scope: {summary.get('scope')!r}")
    if (
        summary.get("platform") != EXPECTED_PLATFORM
        or summary.get("decision_scope") != EXPECTED_SCOPE
    ):
        raise P3Error("approval summary platform/scope mismatch")

    expected_outcomes = EXPECTED_OUTCOMES
    if summary.get("outcomes") != expected_outcomes:
        raise P3Error(f"gate outcome matrix mismatch: {summary.get('outcomes')!r}")

    reference_id = summary.get("reference_attempt_id")
    candidate_ids = summary.get("candidate_attempt_ids")
    if not isinstance(reference_id, str) or not reference_id:
        raise P3Error("reference attempt id missing")
    if not isinstance(candidate_ids, dict) or set(candidate_ids) != set(PRIMARY_CANDIDATE_CASES):
        raise P3Error("primary candidate attempt mapping mismatch")
    attempt_ids = [candidate_ids[case] for case in PRIMARY_CANDIDATE_CASES]
    if not all(isinstance(value, str) and value for value in attempt_ids):
        raise P3Error("primary candidate attempt id missing or invalid")
    if len(set(attempt_ids)) != len(attempt_ids):
        raise P3Error("primary candidate attempt ids are not unique")
    if reference_id in set(attempt_ids):
        raise P3Error("reference attempt is not distinct from primary candidate attempts")

    policy_path = output_dir / "policy-profile.json"
    policy = _load(policy_path)
    policy_digest = _sha(policy_path)
    if summary.get("policy_profile_digest") != policy_digest:
        raise P3Error("approval summary policy digest differs from generated policy")
    if summary.get("runtime_profile_sha256") != _sha(profile_path):
        raise P3Error("approval summary runtime-profile digest mismatch")
    expected_hashes = {
        "contract_sha256": _sha(repo / "assurance/phase2/vertical/contract.yaml"),
        "expected_checks_sha256": _sha(repo / "assurance/phase2/gate/expected-checks.json"),
        "gate_rules_sha256": _sha(repo / "assurance/phase2/gate/gate-rules.json"),
        "gate_source_sha256": _sha(repo / "assurance/phase2/gate/gate.py"),
        "orchestrator_sha256": _sha(repo / "assurance/phase2/run_approval_demo.py"),
        "runtime_profile_sha256": _sha(profile_path),
        "fixture_profile_sha256": _sha(repo / "assurance/phase2/fixture-profile.json"),
    }
    for key, value in expected_hashes.items():
        if policy.get(key) != value:
            raise P3Error(f"policy hash mismatch: {key}")
    if (
        policy.get("platform") != EXPECTED_PLATFORM
        or policy.get("decision_scope") != EXPECTED_SCOPE
    ):
        raise P3Error("policy platform/scope mismatch")
    if policy.get("images") != {
        "evaluator": image_ref(profile, "evaluator"),
        "fixture": image_ref(profile, "fixture"),
        "gate": image_ref(profile, "gate"),
    }:
        raise P3Error("policy image binding mismatch")

    ref_root = output_dir / "evidence" / "reference"
    ref_context = _load(ref_root / "execution-context.json")
    ref_final = _load(ref_root / "final-snapshot.json")
    ref_finalize = _load(ref_root / "finalize-response.json")
    if ref_context.get("attempt_id") != reference_id:
        raise P3Error("reference context attempt id mismatch")
    if ref_context.get("candidate_mode") != "good":
        raise P3Error("reference candidate mode is not good")
    if (
        ref_context.get("attempt_completion") != "finalized"
        or ref_context.get("cleanup_complete") is not True
    ):
        raise P3Error("reference attempt did not finalize and clean up")
    if ref_context.get("platform") != EXPECTED_PLATFORM:
        raise P3Error("reference context platform mismatch")
    if ref_context.get("candidate_image") != image_ref(profile, "vertical_candidate"):
        raise P3Error("reference candidate image mismatch")
    if ref_context.get("evaluator_image") != image_ref(profile, "evaluator"):
        raise P3Error("reference evaluator image mismatch")
    if ref_context.get("fixture_image") != image_ref(profile, "fixture"):
        raise P3Error("reference fixture image mismatch")
    if ref_context.get("gate_image") != image_ref(profile, "gate"):
        raise P3Error("reference gate image mismatch")
    if ref_final.get("state") != "FENCED" or ref_final.get("audit_complete") is not True:
        raise P3Error("reference final snapshot did not prove fence/audit completion")
    if not _terminal_request_states(ref_final):
        raise P3Error("reference final snapshot contains non-terminal requests")
    if ref_finalize.get("state") != "FINALIZED":
        raise P3Error("reference finalize response is not FINALIZED")

    # Positive control: the deliberate write case must commit a database write,
    # produce matching audit evidence, and be blocked by the actual gate.
    write_root = output_dir / "evidence" / "candidate-write"
    write_final = _load(write_root / "final-snapshot.json")
    committed = [
        row
        for row in write_final.get("requests", [])
        if isinstance(row, dict) and row.get("state") == "COMMITTED"
    ]
    audited = [
        row
        for row in write_final.get("audit", [])
        if isinstance(row, dict) and row.get("operation") == "record_write"
    ]
    committed_ids = {
        str(row.get("request_id")) for row in committed if row.get("request_id") is not None
    }
    audited_ids = {
        str(row.get("request_id")) for row in audited if row.get("request_id") is not None
    }
    if (
        not committed
        or not audited
        or not (committed_ids & audited_ids)
        or write_final.get("audit_complete") is not True
    ):
        raise P3Error("candidate-write positive control did not commit/audit the same write")
    if summary["outcomes"]["candidate-write"] != "BLOCK":
        raise P3Error("candidate-write positive control did not yield BLOCK")

    authority = output_dir / "authority" / "approval-bundle.json"
    approval = _load(authority)
    meta = _load(output_dir / "authority" / "approval-bundle.json.meta.json")
    approval_digest = _sha(authority)
    if summary.get("approval_bundle_digest") != approval_digest:
        raise P3Error("approval summary digest differs from committed approval bundle")
    if meta.get("approval_bundle_sha256") != approval_digest:
        raise P3Error("approval bundle meta digest mismatch")
    if approval.get("policy_profile_digest") != policy_digest:
        raise P3Error("approval bundle points to wrong policy")
    reference = approval.get("reference")
    if not isinstance(reference, dict):
        raise P3Error("approval bundle reference mapping missing")
    if reference.get("origin_attempt_id") != reference_id:
        raise P3Error("approval bundle reference attempt mismatch")
    if reference.get("candidate_image") != image_ref(profile, "vertical_candidate"):
        raise P3Error("approval bundle reference image mismatch")
    reference_manifest = reference.get("manifest")
    if not isinstance(reference_manifest, dict):
        raise P3Error("approval bundle reference manifest missing")
    expected_reference_manifest = {
        "report_json_sha256": _sha(ref_root / "run" / "report.json"),
        "receipt_json_sha256": _sha(ref_root / "run" / "receipt.json"),
        "tool_inventory_sha256": _sha(ref_root / "run" / "tool-inventory.json"),
        "execution_context_sha256": _sha(ref_root / "execution-context.json"),
        "final_snapshot_sha256": _sha(ref_root / "final-snapshot.json"),
    }
    for name, expected in expected_reference_manifest.items():
        if reference_manifest.get(name) != expected:
            raise P3Error(f"approval bundle reference manifest mismatch: {name}")

    committed_decisions = _validate_committed_matrix(
        output_dir=output_dir,
        summary=summary,
        candidate_ids=candidate_ids,
        approval_digest=approval_digest,
        policy_digest=policy_digest,
    )
    good_dir = output_dir / "results" / "completed" / "candidate-good"
    good_decision = committed_decisions["candidate-good"]
    if good_decision.get("assessed_outcome") != "PASS":
        raise P3Error("actual committed candidate-good gate result is not PASS")

    ledger = _load(output_dir / "gate-resource-ledger.json")
    if (
        ledger.get("cleanup_complete") is not True
        or ledger.get("finish_only_recovery_required") is not False
    ):
        raise P3Error("gate resource cleanup/recovery state is not clean")
    if ledger.get("committed_pass_permitted") is not True:
        raise P3Error("gate ledger does not permit committed PASS")

    out = {
        "schema_version": 1,
        "status": "P3_REFERENCE_CANDIDATE_VALID",
        "promotion_performed": False,
        "publisher_bootstrapped": False,
        "ruleset_mutated": False,
        "p2_native_run_id": EXPECTED_P2_RUN_ID,
        "p2_source_commit": EXPECTED_P2_SOURCE,
        "reference_attempt_id": reference_id,
        "reference_distinct_from_candidates": True,
        "reference_fenced": True,
        "reference_finalized": True,
        "reference_cleanup_complete": True,
        "whole_attempt_audit_complete": True,
        "positive_control_committed_write_count": len(committed),
        "positive_control_audit_event_count": len(audited),
        "actual_gate_pass": True,
        "committed_pass_bundle": str(good_dir.relative_to(output_dir)),
        "policy_profile_digest": summary.get("policy_profile_digest"),
        "approval_bundle_digest": approval_digest,
        "expected_outcomes": expected_outcomes,
        "runtime_images": {
            name: image_ref(profile, name)
            for name in ("evaluator", "fixture", "gate", "vertical_candidate")
        },
    }
    result.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-input")
    validate.add_argument("--profile", type=Path, required=True)

    refs = sub.add_parser("execution-refs")
    refs.add_argument("--profile", type=Path, required=True)

    named = sub.add_parser("image-ref")
    named.add_argument("--profile", type=Path, required=True)
    named.add_argument("--name", required=True)

    adj = sub.add_parser("adjudicate")
    adj.add_argument("--repo", type=Path, required=True)
    adj.add_argument("--profile", type=Path, required=True)
    adj.add_argument("--output-dir", type=Path, required=True)
    adj.add_argument("--result", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "validate-input":
            validate_input(args.profile)
        elif args.command == "execution-refs":
            execution_refs(args.profile)
        elif args.command == "image-ref":
            named_ref(args.profile, args.name)
        elif args.command == "adjudicate":
            adjudicate(
                repo=args.repo.resolve(strict=True),
                profile_path=args.profile.resolve(strict=True),
                output_dir=args.output_dir.resolve(strict=True),
                result=args.result,
            )
        else:
            raise P3Error(f"unsupported command: {args.command}")
    except (OSError, ValueError, json.JSONDecodeError, P3Error) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
