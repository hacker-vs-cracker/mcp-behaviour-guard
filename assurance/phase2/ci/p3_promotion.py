from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_PLATFORM = "linux/amd64"
EXPECTED_SCOPE = "phase2c_trusted_ci_gate_only"
EXPECTED_CONSTRUCTION_COMMIT = "cd1561d833b4918c3d2b082f2992a53a675481f8"
EXPECTED_CONSTRUCTION_TREE = "aa7b6d1997da9d0ffdcaa9ad481966f44b6a5570"
EXPECTED_RUN_ID = 37407853746
EXPECTED_RUN_ATTEMPT = 1
EXPECTED_ARTIFACT_ID = 11388250431
EXPECTED_ARTIFACT_DIGEST = "sha256:4cecd66755094546c2db096623a8e024f2243669176d97015c5a0805f27c38ae"
EXPECTED_ARCHIVE_SHA256 = "0a70a9688ef72b47420aab2e2e9d5f3875d94bb722545c65ccbb1ab033750ef4"
EXPECTED_EVIDENCE_MANIFEST_SHA256 = (
    "d7d238a92a628adbe5bafe48249e1db6e3135db08a907d56fb49109aedcff339"
)
EXPECTED_RUNTIME_PROFILE_SHA256 = "e8a48a406cceb23050a7708338bdde625a9ea21b3e0e707056752eefab279ac4"
EXPECTED_BASE_MANIFEST = "sha256:fa7a862d74b4decf68fb7d3a85147efc14dbcd3779c0abd56c071d27a1ffee04"
EXPECTED_LOCK_SHA256 = "a18436b0d48f7eacf5b8f4142685a12b11eed3105039e4d3a0eab2b42a3ec22b"
EXPECTED_POLICY_DIGEST = "c30e6cd7d80b382ee479f178c77b3ff3e117be6f822e6af3e2eac0a3084f0d2b"
EXPECTED_APPROVAL_DIGEST = "054304a1d9ad728e7a1fc2b656a0be42b8b05acbf26d8164d3f7747d328bdb5c"
EXPECTED_REFERENCE_ATTEMPT = "reference-36eba55f59"
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
EXPECTED_SOURCE_BLOBS = {
    ".github/workflows/phase2-p3-reference-candidate.yml": "26f877a82348f6ee0db5c2eace0f38bfe4578cca",
    "assurance/phase2/run_approval_demo.py": "62bc1e362fb506493f27530516b9446a0900fa84",
    "assurance/phase2/gate/gate.py": "de05aff564c367dc59daeede09018adf5554551f",
    "assurance/phase2/ci/p3_reference_candidate.py": "b7a638f0d0a08bcf5ac683db0f1ccd637dd638ed",
}
AUTHORITY_REL = "assurance/phase2/ci/p3-promoted-authority.json"
VALIDATOR_REL = "assurance/phase2/ci/p3_promotion.py"


class PromotionError(RuntimeError):
    pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError(f"invalid JSON {path}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise PromotionError(f"JSON must be an object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_blob_oid(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def _require(value: bool, message: str) -> None:
    if not value:
        raise PromotionError(message)


def _mapping(value: Any, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PromotionError(message)
    return value


def _list(value: Any, message: str) -> list[Any]:
    if not isinstance(value, list):
        raise PromotionError(message)
    return value


def validate_authority(repo: Path, authority_path: Path, trust_path: Path) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    authority_path = authority_path.resolve(strict=True)
    trust_path = trust_path.resolve(strict=True)
    authority = _load(authority_path)
    trust = _load(trust_path)

    _require(authority.get("schema_version") == 1, "authority schema_version mismatch")
    _require(
        authority.get("authority_type") == "phase2c_promoted_runtime_reference_approval",
        "authority type mismatch",
    )
    _require(authority.get("status") == "PROMOTED", "authority status is not PROMOTED")
    _require(authority.get("consumable") is True, "promoted authority must be consumable")
    _require(authority.get("profile_id") == "phase2c-ci-amd64-v1", "profile_id mismatch")
    _require(authority.get("platform") == EXPECTED_PLATFORM, "platform mismatch")
    _require(authority.get("decision_scope") == EXPECTED_SCOPE, "decision scope mismatch")
    _require(
        authority.get("activation") == "effective_only_after_protected_main_merge",
        "activation semantics mismatch",
    )

    generation = _mapping(authority.get("generation"), "generation mapping missing")
    _require(generation.get("number") == 1, "authority generation must be 1")
    _require(generation.get("supersedes") is None, "generation 1 must not supersede authority")
    _require(
        generation.get("renewal_rule")
        == "new-reference-requires-new-reviewed-construction-and-promotion",
        "renewal rule mismatch",
    )

    construction = _mapping(authority.get("construction"), "construction mapping missing")
    _require(
        construction.get("source_commit") == EXPECTED_CONSTRUCTION_COMMIT,
        "construction source commit mismatch",
    )
    _require(
        construction.get("source_tree") == EXPECTED_CONSTRUCTION_TREE,
        "construction source tree mismatch",
    )
    _require(construction.get("run_id") == EXPECTED_RUN_ID, "construction run id mismatch")
    _require(
        construction.get("run_attempt") == EXPECTED_RUN_ATTEMPT,
        "construction run attempt mismatch",
    )
    _require(construction.get("run_conclusion") == "success", "construction was not successful")
    _require(
        construction.get("artifact_id") == EXPECTED_ARTIFACT_ID,
        "construction artifact id mismatch",
    )
    _require(
        construction.get("artifact_digest") == EXPECTED_ARTIFACT_DIGEST,
        "construction artifact digest mismatch",
    )

    source_fields = {
        ".github/workflows/phase2-p3-reference-candidate.yml": "workflow_blob_oid",
        "assurance/phase2/run_approval_demo.py": "runner_blob_oid",
        "assurance/phase2/gate/gate.py": "gate_blob_oid",
        "assurance/phase2/ci/p3_reference_candidate.py": "adjudicator_blob_oid",
    }
    for rel, field in source_fields.items():
        path = repo / rel
        _require(path.is_file() and not path.is_symlink(), f"trusted source missing: {rel}")
        actual = _git_blob_oid(path)
        expected = EXPECTED_SOURCE_BLOBS[rel]
        _require(actual == expected, f"trusted source blob drift: {rel}")
        _require(construction.get(field) == expected, f"authority source blob mismatch: {rel}")

    retention = _mapping(authority.get("retention"), "retention mapping missing")
    _require(
        retention.get("mode") == "durable_hashed_local_archive",
        "retention mode mismatch",
    )
    _require(
        retention.get("archive_sha256") == EXPECTED_ARCHIVE_SHA256,
        "retained archive digest mismatch",
    )
    _require(
        retention.get("workflow_evidence_manifest_sha256") == EXPECTED_EVIDENCE_MANIFEST_SHA256,
        "workflow evidence manifest digest mismatch",
    )
    _require(
        retention.get("retention_requirement") == "retain_for_promoted_authority_lifetime",
        "authority-lifetime retention requirement missing",
    )

    runtime = _mapping(authority.get("runtime"), "runtime mapping missing")
    profile_rel = runtime.get("construction_profile_path")
    _require(
        profile_rel == "assurance/phase2/ci/p3-runtime-candidate.json",
        "construction profile path mismatch",
    )
    profile_path = repo / str(profile_rel)
    _require(_sha256(profile_path) == EXPECTED_RUNTIME_PROFILE_SHA256, "construction profile drift")
    _require(
        runtime.get("construction_profile_sha256") == EXPECTED_RUNTIME_PROFILE_SHA256,
        "authority construction profile digest mismatch",
    )
    profile = _load(profile_path)
    _require(
        profile.get("status") == "P3_REFERENCE_CONSTRUCTION_INPUT",
        "construction input status changed",
    )
    _require(profile.get("consumable") is False, "construction input became consumable")
    _require(
        (profile.get("reference") or {}).get("status") == "UNPROMOTED",
        "construction input reference was mutated in place",
    )
    _require(
        runtime.get("base_manifest_digest") == EXPECTED_BASE_MANIFEST,
        "base manifest mismatch",
    )
    _require(
        runtime.get("amd64_dependency_lock_sha256") == EXPECTED_LOCK_SHA256,
        "AMD64 dependency lock digest mismatch",
    )
    lock_path = repo / str(runtime.get("amd64_dependency_lock_path"))
    _require(lock_path.is_file() and not lock_path.is_symlink(), "AMD64 dependency lock missing")
    _require(_sha256(lock_path) == EXPECTED_LOCK_SHA256, "AMD64 dependency lock drift")

    profile_images = _mapping(profile.get("images"), "construction profile image mapping missing")
    authority_images = _mapping(runtime.get("images"), "authority image mapping missing")
    _require(set(authority_images) == set(profile_images), "authority image role set mismatch")
    for role, value in authority_images.items():
        _require(isinstance(value, str) and "@sha256:" in value, f"non-digest image ref: {role}")
        identity = _mapping(profile_images.get(role), f"profile image identity missing: {role}")
        _require(identity.get("execution_ref") == value, f"image ref drift: {role}")

    policy = _mapping(authority.get("policy"), "policy mapping missing")
    _require(
        policy.get("policy_profile_digest") == EXPECTED_POLICY_DIGEST,
        "policy profile digest mismatch",
    )
    profile_authority = _mapping(profile.get("authority"), "construction authority mapping missing")
    _require(
        policy.get("contract_sha256") == profile_authority.get("contract_sha256"),
        "contract digest mismatch",
    )
    _require(
        policy.get("expected_checks_sha256") == profile_authority.get("expected_checks_sha256"),
        "expected-check digest mismatch",
    )
    _require(
        policy.get("gate_rules_sha256") == profile_authority.get("gate_rules_sha256"),
        "gate-rules digest mismatch",
    )

    reference = _mapping(authority.get("reference"), "reference mapping missing")
    _require(
        reference.get("origin_attempt_id") == EXPECTED_REFERENCE_ATTEMPT,
        "reference attempt mismatch",
    )
    _require(
        reference.get("approval_bundle_digest") == EXPECTED_APPROVAL_DIGEST,
        "approval bundle digest mismatch",
    )

    evidence = _mapping(authority.get("evidence"), "evidence mapping missing")
    _require(evidence.get("outcomes") == EXPECTED_OUTCOMES, "eight-case outcome matrix mismatch")
    for field in (
        "actual_gate_pass",
        "reference_distinct_from_candidates",
        "reference_fenced",
        "reference_finalized",
        "whole_attempt_audit_complete",
        "cleanup_complete",
    ):
        _require(evidence.get(field) is True, f"required evidence flag is not true: {field}")
    _require(
        evidence.get("finish_only_recovery_required") is False,
        "promotion cannot bind finish-only recovery state",
    )
    _require(
        isinstance(evidence.get("positive_control_committed_write_count"), int)
        and evidence["positive_control_committed_write_count"] > 0,
        "positive committed-write evidence missing",
    )
    _require(
        isinstance(evidence.get("positive_control_audit_event_count"), int)
        and evidence["positive_control_audit_event_count"] > 0,
        "positive write-audit evidence missing",
    )

    publisher = _mapping(authority.get("publisher"), "publisher mapping missing")
    _require(publisher.get("status") == "UNBOOTSTRAPPED", "publisher was bootstrapped in P3")
    _require(publisher.get("integration_id") is None, "publisher integration unexpectedly set")
    _require(
        authority.get("ruleset_mutation_performed") is False,
        "ruleset mutation must remain outside promotion",
    )

    # The authority does not hash itself. The trust-boundary projection is the one-way pointer.
    _require("authority_sha256" not in json.dumps(authority), "authority self-hash cycle detected")
    actual_authority_sha = _sha256(authority_path)
    platform = _mapping(trust.get("platform"), "trust platform mapping missing")
    _require(platform.get("runtime_profile_status") == "PROMOTED", "trust status is not promoted")
    p3_promotion = _mapping(trust.get("p3_promotion"), "trust p3_promotion mapping missing")
    _require(p3_promotion.get("status") == "PROMOTED", "trust promotion status mismatch")
    _require(p3_promotion.get("authority_generation") == 1, "trust authority generation mismatch")
    _require(p3_promotion.get("supersedes_generation") is None, "trust supersession mismatch")
    _require(p3_promotion.get("authority_path") == AUTHORITY_REL, "trust authority path mismatch")
    _require(
        p3_promotion.get("authority_sha256") == actual_authority_sha,
        "trust authority digest mismatch",
    )
    _require(
        p3_promotion.get("construction_run_id") == EXPECTED_RUN_ID,
        "trust construction run mismatch",
    )
    _require(
        p3_promotion.get("construction_artifact_digest") == EXPECTED_ARTIFACT_DIGEST,
        "trust construction artifact mismatch",
    )
    _require(
        p3_promotion.get("reference_origin_attempt_id") == EXPECTED_REFERENCE_ATTEMPT,
        "trust reference attempt mismatch",
    )
    _require(
        p3_promotion.get("approval_bundle_digest") == EXPECTED_APPROVAL_DIGEST,
        "trust approval digest mismatch",
    )
    _require(
        p3_promotion.get("publisher_bootstrap_enabled") is False,
        "promotion must not bootstrap publisher",
    )
    _require(
        p3_promotion.get("ruleset_mutation_enabled") is False,
        "promotion must not mutate ruleset",
    )

    trust_publisher = _mapping(trust.get("publisher"), "trust publisher mapping missing")
    _require(
        trust_publisher.get("bootstrap_status") == "UNBOOTSTRAPPED",
        "trust publisher status changed",
    )
    _require(
        trust_publisher.get("integration_id") is None,
        "trust publisher integration unexpectedly set",
    )
    controller = _mapping(trust.get("controller"), "trust controller mapping missing")
    _require(
        controller.get("candidate_execution_enabled") is False,
        "P4 candidate execution was enabled during P3 promotion",
    )
    p3_construction = _mapping(
        trust.get("p3_reference_candidate"), "P3 construction trust mapping missing"
    )
    _require(
        p3_construction.get("promotion_enabled") is False,
        "construction workflow must remain non-promoting",
    )

    consumed = _list(trust.get("consumed_trusted_inputs"), "consumed trusted inputs missing")
    _require(AUTHORITY_REL in consumed, "promoted authority not listed as trusted input")
    _require(VALIDATOR_REL in consumed, "promotion validator not listed as trusted input")

    return authority


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--trust-boundary", type=Path, required=True)
    args = parser.parse_args()
    try:
        authority = validate_authority(args.repo, args.authority, args.trust_boundary)
    except PromotionError as exc:
        print(json.dumps({"status": "INVALID", "error": str(exc)}, sort_keys=True))
        return 70
    print(
        json.dumps(
            {
                "status": "P3_PROMOTED_AUTHORITY_VALID",
                "authority_generation": authority["generation"]["number"],
                "construction_run_id": authority["construction"]["run_id"],
                "approval_bundle_digest": authority["reference"]["approval_bundle_digest"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
