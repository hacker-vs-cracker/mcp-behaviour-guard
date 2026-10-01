from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW_DIR = Path(".github/workflows")
ACTION_MANIFEST = Path(".github/action-pins.yml")
CI_WORKFLOW = WORKFLOW_DIR / "ci.yml"
CI_TEXT = CI_WORKFLOW.read_text(encoding="utf-8")

FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")
DOCKER_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def _load_yaml(path: Path) -> Any:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _load_manifest(path: Path = ACTION_MANIFEST) -> dict[str, Any]:
    raw = _load_yaml(path)
    assert isinstance(raw, dict), "action pin manifest root must be a mapping"
    assert raw.get("version") == "1", "action pin manifest version must be 1"

    external = raw.get("external")
    local = raw.get("local")
    docker = raw.get("docker")
    assert isinstance(external, dict), "manifest external must be a mapping"
    assert isinstance(local, list), "manifest local must be a list"
    assert isinstance(docker, list), "manifest docker must be a list"
    assert all(isinstance(key, str) and isinstance(value, str) for key, value in external.items())
    assert all(isinstance(item, str) for item in local)
    assert all(isinstance(item, str) for item in docker)
    return {"external": external, "local": local, "docker": docker}


def _workflow_paths(directory: Path = WORKFLOW_DIR) -> list[Path]:
    return sorted({*directory.glob("*.yml"), *directory.glob("*.yaml")})


def _extract_uses(document: Any, path: Path) -> list[str]:
    assert isinstance(document, dict), f"{path}: workflow root must be a mapping"
    jobs = document.get("jobs")
    assert isinstance(jobs, dict), f"{path}: jobs must be a mapping"

    uses: list[str] = []
    for job_name, job in jobs.items():
        assert isinstance(job, dict), f"{path}: job {job_name!r} must be a mapping"
        if "uses" in job:
            value = job["uses"]
            assert isinstance(value, str) and value.strip(), (
                f"{path}: job {job_name!r} uses must be a non-empty string"
            )
            uses.append(value.strip())

        steps = job.get("steps", [])
        assert isinstance(steps, list), f"{path}: job {job_name!r} steps must be a list"
        for index, step in enumerate(steps):
            assert isinstance(step, dict), (
                f"{path}: job {job_name!r} step {index} must be a mapping"
            )
            if "uses" not in step:
                continue
            value = step["uses"]
            assert isinstance(value, str) and value.strip(), (
                f"{path}: job {job_name!r} step {index} uses must be a non-empty string"
            )
            uses.append(value.strip())
    return uses


def _validate_uses(uses: list[str], manifest: dict[str, Any]) -> None:
    approved_external: dict[str, str] = manifest["external"]
    approved_local = set(manifest["local"])
    approved_docker = set(manifest["docker"])
    observed_external: set[str] = set()
    observed_local: set[str] = set()
    observed_docker: set[str] = set()

    for value in uses:
        if value.startswith("./"):
            assert value in approved_local, f"unapproved local action/reusable workflow: {value}"
            observed_local.add(value)
            continue

        if value.startswith("docker://"):
            reference = value.removeprefix("docker://")
            assert "@" in reference, f"docker reference is not digest pinned: {value}"
            _image, digest = reference.rsplit("@", 1)
            assert DOCKER_DIGEST_RE.fullmatch(digest), (
                f"docker reference is not pinned to an immutable sha256 digest: {value}"
            )
            assert value in approved_docker, f"unapproved docker reference: {value}"
            observed_docker.add(value)
            continue

        assert "@" in value, f"external action/reusable workflow is missing @ref: {value}"
        identity, ref = value.rsplit("@", 1)
        assert identity and ref, f"malformed external action/reusable workflow: {value}"
        assert FULL_SHA_RE.fullmatch(ref), (
            f"{identity} is not pinned to an immutable full commit SHA: {ref}"
        )
        assert identity in approved_external, (
            f"unapproved external action/reusable workflow identity: {identity}"
        )
        expected_ref = approved_external[identity]
        assert ref == expected_ref, (
            f"{identity} uses unapproved ref {ref}; reviewed ref is {expected_ref}"
        )
        observed_external.add(identity)

    assert observed_external == set(approved_external), (
        "action pin manifest contains stale/unused external entries: "
        f"{sorted(set(approved_external) - observed_external)}"
    )
    assert observed_local == approved_local, (
        "action pin manifest contains stale/unused local entries: "
        f"{sorted(approved_local - observed_local)}"
    )
    assert observed_docker == approved_docker, (
        "action pin manifest contains stale/unused docker entries: "
        f"{sorted(approved_docker - observed_docker)}"
    )


def _validate_workflows(
    directory: Path = WORKFLOW_DIR,
    manifest_path: Path = ACTION_MANIFEST,
) -> None:
    paths = _workflow_paths(directory)
    assert paths, "expected at least one GitHub Actions workflow"
    uses: list[str] = []
    for path in paths:
        uses.extend(_extract_uses(_load_yaml(path), path))
    assert uses, "expected GitHub Actions uses entries"
    _validate_uses(uses, _load_manifest(manifest_path))


def _write_workflow(path: Path, uses_values: list[str]) -> None:
    steps = [{"name": f"step-{index}", "uses": value} for index, value in enumerate(uses_values)]
    path.write_text(
        yaml.safe_dump(
            {"name": "test", "on": ["push"], "jobs": {"test": {"steps": steps}}},
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _manifest(
    external: dict[str, str], local: list[str] | None = None, docker: list[str] | None = None
) -> dict[str, Any]:
    return {
        "external": external,
        "local": local or [],
        "docker": docker or [],
    }


def test_all_workflows_use_only_reviewed_immutable_references() -> None:
    _validate_workflows()


def test_named_step_with_mutable_ref_is_rejected() -> None:
    approved = "1" * 40
    with pytest.raises(AssertionError, match="immutable full commit SHA"):
        _validate_uses(["owner/action@main"], _manifest({"owner/action": approved}))


def test_comment_cannot_satisfy_reviewed_ref_policy(tmp_path: Path) -> None:
    approved = "1" * 40
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        "name: test\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - name: mutable named step\n"
        "        uses: owner/action@main\n"
        f"        # owner/action@{approved}\n",
        encoding="utf-8",
    )
    uses = _extract_uses(_load_yaml(workflow), workflow)
    with pytest.raises(AssertionError, match="immutable full commit SHA"):
        _validate_uses(uses, _manifest({"owner/action": approved}))


def test_approved_action_only_in_comment_is_rejected(tmp_path: Path) -> None:
    approved = "1" * 40
    other = "2" * 40
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        "name: test\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        f"      # uses: owner/action@{approved}\n"
        f"      - uses: other/action@{other}\n",
        encoding="utf-8",
    )
    uses = _extract_uses(_load_yaml(workflow), workflow)
    with pytest.raises(AssertionError):
        _validate_uses(uses, _manifest({"owner/action": approved}))


def test_unapproved_action_with_valid_sha_is_rejected() -> None:
    approved = "1" * 40
    unapproved = "2" * 40
    with pytest.raises(AssertionError, match="unapproved external"):
        _validate_uses(
            [f"owner/action@{approved}", f"other/action@{unapproved}"],
            _manifest({"owner/action": approved}),
        )


def test_same_action_with_approved_and_unapproved_ref_is_rejected() -> None:
    approved = "1" * 40
    other = "2" * 40
    with pytest.raises(AssertionError, match="unapproved ref"):
        _validate_uses(
            [f"owner/action@{approved}", f"owner/action@{other}"],
            _manifest({"owner/action": approved}),
        )


@pytest.mark.parametrize("workflow_name", ["security.yml", "release.yml"])
def test_unapproved_reference_in_other_workflow_is_rejected(
    tmp_path: Path,
    workflow_name: str,
) -> None:
    approved = "1" * 40
    unapproved = "2" * 40
    workflow_dir = tmp_path / "workflows"
    workflow_dir.mkdir()
    _write_workflow(workflow_dir / "ci.yml", [f"owner/action@{approved}"])
    _write_workflow(workflow_dir / workflow_name, [f"other/action@{unapproved}"])
    manifest = tmp_path / "pins.yml"
    manifest.write_text(
        yaml.safe_dump(
            {"version": 1, "external": {"owner/action": approved}, "local": [], "docker": []},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="unapproved external"):
        _validate_workflows(workflow_dir, manifest)


def test_new_workflow_with_unapproved_action_is_rejected(tmp_path: Path) -> None:
    approved = "1" * 40
    workflow_dir = tmp_path / "workflows"
    workflow_dir.mkdir()
    _write_workflow(workflow_dir / "ci.yml", [f"owner/action@{approved}"])
    _write_workflow(workflow_dir / "new.yml", [f"new/action@{'2' * 40}"])
    manifest = tmp_path / "pins.yml"
    manifest.write_text(
        yaml.safe_dump(
            {"version": 1, "external": {"owner/action": approved}, "local": [], "docker": []},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="unapproved external"):
        _validate_workflows(workflow_dir, manifest)


def test_malformed_uses_is_rejected(tmp_path: Path) -> None:
    workflow = tmp_path / "bad.yml"
    workflow.write_text(
        "name: test\non: [push]\njobs:\n  test:\n    steps:\n      - uses: []\n",
        encoding="utf-8",
    )
    with pytest.raises(AssertionError, match="non-empty string"):
        _extract_uses(_load_yaml(workflow), workflow)


def test_unreviewed_local_action_is_rejected() -> None:
    with pytest.raises(AssertionError, match="unapproved local"):
        _validate_uses(["./.github/actions/example"], _manifest({}))


def test_mutable_docker_reference_is_rejected() -> None:
    with pytest.raises(AssertionError, match="digest pinned"):
        _validate_uses(["docker://alpine:3.20"], _manifest({}))


def test_stale_manifest_entry_is_rejected() -> None:
    approved = "1" * 40
    stale = "2" * 40
    with pytest.raises(AssertionError, match="stale/unused external"):
        _validate_uses(
            [f"owner/action@{approved}"],
            _manifest({"owner/action": approved, "stale/action": stale}),
        )


def test_ci_verifies_each_demo_report_semantically() -> None:
    for profile in ("stdio", "temporal", "http"):
        assert f"python scripts/verify_demo_report.py {profile} reports-{profile}" in CI_TEXT

    assert "Verify reports exist" not in CI_TEXT


def test_ci_disables_checkout_credentials() -> None:
    lines = CI_TEXT.splitlines()
    checkout_indices = [
        index for index, line in enumerate(lines) if "uses: actions/checkout@" in line
    ]
    assert checkout_indices, "expected at least one checkout step"

    for index in checkout_indices:
        indent = len(lines[index]) - len(lines[index].lstrip())
        block = [lines[index]]
        for line in lines[index + 1 :]:
            stripped = line.lstrip()
            line_indent = len(line) - len(stripped)
            if line_indent == indent and stripped.startswith("- "):
                break
            block.append(line)

        assert "persist-credentials: false" in "\n".join(block)


def test_ci_covers_additional_supported_python_versions() -> None:
    assert "python-compatibility:" in CI_TEXT
    assert "python-version: ['3.12', '3.13', '3.14']" in CI_TEXT
    assert 'pytest -m "not integration"' in CI_TEXT


def test_ci_builds_and_smoke_tests_runner_image() -> None:
    assert "file: Dockerfile.runner" in CI_TEXT
    assert "docker build -f Dockerfile.runner -t mcp-guard-runner:ci ." in CI_TEXT
    assert "--entrypoint id mcp-guard-runner:ci -u" in CI_TEXT
    assert 'test "$uid" = "10001"' in CI_TEXT
    assert "docker run --rm mcp-guard-runner:ci --help" in CI_TEXT
    assert "platforms: linux/amd64,linux/arm64" in CI_TEXT
