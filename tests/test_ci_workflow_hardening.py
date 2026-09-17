from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = Path(".github/workflows/ci.yml")
TEXT = WORKFLOW.read_text(encoding="utf-8")

EXPECTED_ACTIONS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "docker/setup-buildx-action": "d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5",
    "docker/build-push-action": "f9f3042f7e2789586610d6e8b85c8f03e5195baf",
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
        assert f"{action}@{sha}" in TEXT


def test_ci_verifies_each_demo_report_semantically() -> None:
    for profile in ("stdio", "temporal", "http"):
        assert f"python scripts/verify_demo_report.py {profile} reports-{profile}" in TEXT

    assert "Verify reports exist" not in TEXT


def test_ci_disables_checkout_credentials() -> None:
    checkout_count = TEXT.count("actions/checkout@")
    assert checkout_count == 3
    assert TEXT.count("persist-credentials: false") >= checkout_count


def test_ci_builds_and_smoke_tests_runner_image() -> None:
    assert "file: Dockerfile.runner" in TEXT
    assert "docker build -f Dockerfile.runner -t mcp-guard-runner:ci ." in TEXT
    assert "--entrypoint id mcp-guard-runner:ci -u" in TEXT
    assert 'test "$uid" = "10001"' in TEXT
    assert "docker run --rm mcp-guard-runner:ci --help" in TEXT
    assert "platforms: linux/amd64,linux/arm64" in TEXT
