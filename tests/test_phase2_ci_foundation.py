from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = ROOT / "assurance/phase2/ci/extract_candidate_context.py"
BOUNDARY = ROOT / "assurance/phase2/ci/trust-boundary.json"
PROFILE = ROOT / "assurance/phase2/ci/runtime-profile-template.json"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("phase2_ci_candidate_context_test", EXTRACTOR)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Phase 2C candidate-context extractor")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _git_bytes(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )
    return result.stdout


def _init_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "phase2c@example.invalid")
    _git(repo, "config", "user.name", "Phase 2C Test")

    (repo / "assurance/phase2/ci").mkdir(parents=True)
    (repo / "assurance/phase2/vertical").mkdir(parents=True)
    (repo / "assurance/phase2/ci/trust-boundary.json").write_text(
        BOUNDARY.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (repo / "assurance/phase2/vertical/Dockerfile").write_text(
        "FROM scratch\nCOPY candidate_server.py /candidate/candidate_server.py\n",
        encoding="utf-8",
    )
    (repo / "assurance/phase2/vertical/candidate_server.py").write_text(
        "print('trusted baseline candidate')\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "trusted baseline")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_trust_boundary_freezes_candidate_and_publisher_separation() -> None:
    payload = json.loads(BOUNDARY.read_text(encoding="utf-8"))
    assert payload["status"] == "DESIGN_FROZEN"
    assert payload["controller"]["preferred_trigger"] == "workflow_run"
    assert payload["controller"]["expected_upstream_workflow_id"] == 316477065
    assert payload["controller"]["upstream_conclusion_is_authoritative"] is False
    assert payload["candidate"]["allowed_paths"] == [
        "assurance/phase2/vertical/candidate_server.py"
    ]
    assert payload["candidate"]["candidate_supplied_dockerfile_allowed"] is False
    assert payload["candidate"]["candidate_receives_publisher_credentials"] is False
    assert payload["candidate"]["candidate_receives_repository_write_token"] is False
    assert payload["platform"] == {
        "architecture": "amd64",
        "os": "linux",
        "phase2b_arm64_image_identity_reuse_allowed": False,
        "runtime_profile_status": "PROMOTED",
    }
    assert payload["publisher"]["identity"] == "dedicated-github-app"
    assert payload["publisher"]["integration_id"] is None
    assert payload["publisher"]["credential_available_to_candidate_execution"] is False


def test_amd64_runtime_profile_is_explicitly_non_consumable_until_promotion() -> None:
    payload = json.loads(PROFILE.read_text(encoding="utf-8"))
    assert payload["profile_id"] == "phase2c-ci-amd64-v1"
    assert payload["status"] == "UNPROMOTED"
    assert payload["consumable"] is False
    assert payload["platform"] == "linux/amd64"
    assert payload["base_image"]["platform_manifest_digest"] is None
    assert set(payload["images"]) == {"evaluator", "fixture", "gate", "vertical_candidate"}
    assert all(value is None for value in payload["images"].values())
    assert payload["reference"]["approval_bundle_digest"] is None
    assert payload["publisher"]["integration_id"] is None


def test_amd64_evaluator_lock_is_separate_exact_and_bound() -> None:
    amd64_path = ROOT / "assurance/phase2/ci/evaluator-requirements-amd64.lock"
    arm64_path = ROOT / "assurance/phase2/evaluator/requirements.lock"

    amd64_bytes = amd64_path.read_bytes()
    arm64_bytes = arm64_path.read_bytes()
    assert hashlib.sha256(amd64_bytes).hexdigest() == (
        "a18436b0d48f7eacf5b8f4142685a12b11eed3105039e4d3a0eab2b42a3ec22b"
    )
    assert hashlib.sha256(arm64_bytes).hexdigest() == (
        "7f135a827bad87dc89e5a359824d0abe727f376f213865330b4da8c14cead267"
    )
    assert amd64_bytes != arm64_bytes

    def parse_lock(raw: bytes) -> dict[str, tuple[str, str]]:
        records: dict[str, tuple[str, str]] = {}
        for line in raw.decode("utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            spec, separator, digest = stripped.partition(" --hash=sha256:")
            assert separator
            name, version = spec.split("==", 1)
            assert name not in records
            assert len(digest) == 64
            records[name] = (version, digest)
        return records

    amd64 = parse_lock(amd64_bytes)
    arm64 = parse_lock(arm64_bytes)
    assert len(amd64) == 41
    assert set(amd64) == set(arm64)
    assert {name: version for name, (version, _digest) in amd64.items()} == {
        name: version for name, (version, _digest) in arm64.items()
    }

    changed = sorted(name for name in amd64 if amd64[name][1] != arm64[name][1])
    assert changed == [
        "cffi",
        "cryptography",
        "markupsafe",
        "pydantic-core",
        "pyyaml",
        "rpds-py",
    ]

    expected_binding = {
        "path": "assurance/phase2/ci/evaluator-requirements-amd64.lock",
        "requirements_sha256": ("a18436b0d48f7eacf5b8f4142685a12b11eed3105039e4d3a0eab2b42a3ec22b"),
        "target_platform": "linux/amd64",
        "historical_arm64_path": "assurance/phase2/evaluator/requirements.lock",
        "historical_arm64_requirements_sha256": (
            "7f135a827bad87dc89e5a359824d0abe727f376f213865330b4da8c14cead267"
        ),
        "historical_arm64_reuse_allowed": False,
    }

    boundary = json.loads(BOUNDARY.read_text(encoding="utf-8"))
    assert boundary["evaluator_lock"] == expected_binding
    assert boundary["retained_historical_evidence"] == [
        "assurance/phase2/runtime-profile.json",
        "assurance/phase2/evaluator/requirements.lock",
    ]
    assert "assurance/phase2/evaluator/requirements.lock" not in boundary["consumed_trusted_inputs"]
    assert (
        boundary["consumed_trusted_inputs"].count(
            "assurance/phase2/ci/evaluator-requirements-amd64.lock"
        )
        == 1
    )
    assert "assurance/phase2/ci/build-adapter.json" in boundary["consumed_trusted_inputs"]
    assert "assurance/phase2/ci/build_adapter.py" in boundary["consumed_trusted_inputs"]

    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    assert profile["status"] == "UNPROMOTED"
    assert profile["consumable"] is False
    assert profile["evaluator_lock"] == expected_binding
    assert profile["base_image"]["platform_manifest_digest"] is None
    assert all(value is None for value in profile["images"].values())


def test_candidate_materialization_uses_only_allowlisted_blob_and_trusted_dockerfile(
    tmp_path: Path,
) -> None:
    module = _module()
    repo, trusted = _init_repo(tmp_path)

    candidate_path = repo / "assurance/phase2/vertical/candidate_server.py"
    candidate_path.write_text("print('untrusted PR candidate')\n", encoding="utf-8")
    (repo / "assurance/phase2/vertical/Dockerfile").write_text(
        "FROM attacker-controlled\n",
        encoding="utf-8",
    )
    malicious_boundary = json.loads(BOUNDARY.read_text(encoding="utf-8"))
    malicious_boundary["candidate"]["allowed_paths"].append("pyproject.toml")
    (repo / "assurance/phase2/ci/trust-boundary.json").write_text(
        json.dumps(malicious_boundary),
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "untrusted candidate changes")
    candidate = _git(repo, "rev-parse", "HEAD")

    output = tmp_path / "context"
    manifest_path = tmp_path / "evidence" / "candidate-context.json"
    manifest = module.materialize(
        repo=repo,
        candidate_commit=candidate,
        trusted_commit=trusted,
        output_dir=output,
        manifest_path=manifest_path,
    )

    assert sorted(path.name for path in output.iterdir()) == ["candidate_server.py"]
    assert (output / "candidate_server.py").read_text(encoding="utf-8") == (
        "print('untrusted PR candidate')\n"
    )
    assert manifest["candidate_commit_sha"] == candidate
    assert manifest["trusted_commit_sha"] == trusted
    assert manifest["candidate_dockerfile_ignored"] is True
    assert manifest["candidate_workflow_ignored_as_authority"] is True

    expected_dockerfile = _git_bytes(
        repo,
        "show",
        f"{trusted}:assurance/phase2/vertical/Dockerfile",
    )
    assert manifest["trusted_dockerfile_sha256"] == module._sha256(expected_dockerfile)


def test_candidate_materialization_rejects_symlink_source(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _init_repo(tmp_path)

    source = repo / "assurance/phase2/vertical/candidate_server.py"
    source.unlink()
    source.symlink_to("../../ci/trust-boundary.json")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "symlink candidate")
    candidate = _git(repo, "rev-parse", "HEAD")

    with pytest.raises(module.CandidateContextError, match="regular 100644 blob"):
        module.materialize(
            repo=repo,
            candidate_commit=candidate,
            trusted_commit=trusted,
            output_dir=tmp_path / "context",
            manifest_path=tmp_path / "manifest.json",
        )


def test_candidate_materialization_rejects_non_exact_commit_sha(tmp_path: Path) -> None:
    module = _module()
    repo, trusted = _init_repo(tmp_path)
    with pytest.raises(module.CandidateContextError, match="exact 40-hex"):
        module.materialize(
            repo=repo,
            candidate_commit="HEAD",
            trusted_commit=trusted,
            output_dir=tmp_path / "context",
            manifest_path=tmp_path / "manifest.json",
        )


def test_candidate_materialization_rejects_oversize_before_blob_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    repo, trusted = _init_repo(tmp_path)

    source = repo / "assurance/phase2/vertical/candidate_server.py"
    source.write_bytes(b"x" * (524288 + 1))
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "oversize candidate")
    candidate = _git(repo, "rev-parse", "HEAD")
    entry = module._tree_entry(repo, candidate, "assurance/phase2/vertical/candidate_server.py")

    original_blob = module._blob

    def guarded_blob(repo_path: Path, oid: str) -> bytes:
        if oid == entry.oid:
            raise AssertionError("oversized candidate blob must not be read")
        return original_blob(repo_path, oid)

    monkeypatch.setattr(module, "_blob", guarded_blob)
    with pytest.raises(module.CandidateContextError, match="exceeds max_source_bytes"):
        module.materialize(
            repo=repo,
            candidate_commit=candidate,
            trusted_commit=trusted,
            output_dir=tmp_path / "context",
            manifest_path=tmp_path / "manifest.json",
        )
    assert not (tmp_path / "context").exists()


def test_trust_boundary_freezes_same_repository_controller_intake() -> None:
    payload = json.loads(BOUNDARY.read_text(encoding="utf-8"))
    controller = payload["controller"]
    candidate = payload["candidate"]
    assert controller["expected_repository"] == "hacker-vs-cracker/mcp-behaviour-guard"
    assert controller["expected_upstream_workflow_name"] == "ci"
    assert controller["require_workflow_run_action"] == "completed"
    assert controller["require_workflow_run_status"] == "completed"
    assert controller["event_pull_requests_are_authority"] is False
    assert controller["pull_request_lookup_source"] == "trusted-github-rest-commit-pulls"
    assert controller["pull_request_lookup_endpoint"] == (
        "repos/{repository}/commits/{head_sha}/pulls"
    )
    assert controller["require_exactly_one_current_matching_pull_request"] is True
    assert controller["require_current_pull_request_state"] == "open"
    assert candidate["source_scope"] == "same-repository-pull-request-only"
    assert candidate["fork_pull_requests_supported"] is False
