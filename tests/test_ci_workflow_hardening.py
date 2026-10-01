from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = Path(".github/workflows/ci.yml")
TEXT = WORKFLOW.read_text(encoding="utf-8")

EXPECTED_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "docker/setup-buildx-action": "f87e5991a6d7451dcb8d9637bfbc97413f497069",
    "docker/build-push-action": "c3c9e263c25d99ce0380d002d59b67737d91b0dc",
}


def test_ci_uses_immutable_action_shas() -> None:
    uses = re.findall(r"^\s*-\s+uses:\s+([^@\s]+)@([^\s#]+)", TEXT, flags=re.MULTILINE)
    assert uses, "expected GitHub Actions uses entries"

    for action, ref in uses:
        assert re.fullmatch(r"[0-9a-f]{40}", ref), (
            f"{action} is not pinned to an immutable full commit SHA: {ref}"
        )


def test_ci_uses_current_approved_action_commits() -> None:
    for action, sha in EXPECTED_ACTIONS.items():
        assert f"{action}@{sha}" in TEXT, (
            f"{action} is not at the reviewed approved commit {sha}. "
            "For Dependabot action updates, verify the upstream version tag and "
            "review the new immutable SHA before updating EXPECTED_ACTIONS."
        )


def test_ci_verifies_each_demo_report_semantically() -> None:
    for profile in ("stdio", "temporal", "http"):
        assert f"python scripts/verify_demo_report.py {profile} reports-{profile}" in TEXT

    assert "Verify reports exist" not in TEXT


def test_ci_disables_checkout_credentials() -> None:
    lines = TEXT.splitlines()
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
    assert "python-compatibility:" in TEXT
    assert "python-version: ['3.12', '3.13', '3.14']" in TEXT
    assert 'pytest -m "not integration"' in TEXT


def test_ci_builds_and_smoke_tests_runner_image() -> None:
    assert "file: Dockerfile.runner" in TEXT
    assert "docker build -f Dockerfile.runner -t mcp-guard-runner:ci ." in TEXT
    assert "--entrypoint id mcp-guard-runner:ci -u" in TEXT
    assert 'test "$uid" = "10001"' in TEXT
    assert "docker run --rm mcp-guard-runner:ci --help" in TEXT
    assert "platforms: linux/amd64,linux/arm64" in TEXT
