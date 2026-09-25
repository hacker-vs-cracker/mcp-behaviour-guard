from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path("scripts/verify_demo_report.py")


def _finding(
    test_id: str,
    status: str,
    severity: str,
    observation: str,
    *,
    after_call: int | None = None,
) -> dict:
    observed: dict = {}
    if after_call is not None:
        observed["first_drift"] = {"after_call": after_call}
    return {
        "test_id": test_id,
        "status": status,
        "severity": severity,
        "observation": observation,
        "observed": observed,
    }


def _temporal_findings() -> list[dict]:
    return [
        _finding(
            "BEHAVIOUR-FORMAT-TEXT",
            "error",
            "medium",
            "unavailable",
        ),
        _finding(
            "TEMPORAL-METADATA-001",
            "failed",
            "high",
            "not_required",
            after_call=3,
        ),
        _finding("AUTH-FORMAT-TEXT-REVIEWER", "passed", "info", "not_required"),
        _finding("INVENTORY-001", "passed", "info", "not_required"),
    ]


def _http_findings() -> list[dict]:
    findings = [
        _finding(
            "AUTH-CUSTOMER-UPDATE-READ-ONLY-USER",
            "failed",
            "critical",
            "complete",
        ),
        _finding(
            "AUTH-CUSTOMER-UPDATE-TENANT-A-USER",
            "failed",
            "critical",
            "complete",
        ),
        _finding(
            "AUTH-CUSTOMER-UPDATE-TENANT-B-USER",
            "failed",
            "critical",
            "complete",
        ),
        _finding("BEHAVIOUR-CUSTOMER-LOOKUP", "failed", "high", "partial"),
        _finding("BEHAVIOUR-GET-SESSION-NOTE", "error", "medium", "partial"),
        _finding("REPLAY-CUSTOMER-UPDATE", "failed", "high", "complete"),
        _finding("SESSION-ISOLATION-001", "failed", "high", "complete"),
        _finding(
            "TENANT-CUSTOMER-LOOKUP-TENANT-A-USER",
            "failed",
            "critical",
            "not_required",
        ),
    ]

    for test_id in (
        "AUTH-CUSTOMER-LOOKUP-ADMINISTRATOR",
        "AUTH-CUSTOMER-LOOKUP-ANONYMOUS",
        "AUTH-CUSTOMER-LOOKUP-INVALID-TOKEN",
        "AUTH-CUSTOMER-LOOKUP-READ-ONLY-USER",
        "AUTH-CUSTOMER-LOOKUP-TENANT-A-USER",
        "AUTH-CUSTOMER-LOOKUP-TENANT-B-USER",
        "AUTH-GET-SESSION-NOTE-ADMINISTRATOR",
        "AUTH-GET-SESSION-NOTE-ANONYMOUS",
        "AUTH-GET-SESSION-NOTE-INVALID-TOKEN",
        "AUTH-GET-SESSION-NOTE-READ-ONLY-USER",
        "AUTH-GET-SESSION-NOTE-TENANT-A-USER",
        "AUTH-GET-SESSION-NOTE-TENANT-B-USER",
    ):
        findings.append(_finding(test_id, "passed", "info", "not_required"))

    for test_id in (
        "AUTH-CUSTOMER-UPDATE-ADMINISTRATOR",
        "AUTH-CUSTOMER-UPDATE-ANONYMOUS",
        "AUTH-CUSTOMER-UPDATE-INVALID-TOKEN",
        "AUTH-SET-SESSION-NOTE-ADMINISTRATOR",
        "AUTH-SET-SESSION-NOTE-ANONYMOUS",
        "AUTH-SET-SESSION-NOTE-INVALID-TOKEN",
        "AUTH-SET-SESSION-NOTE-READ-ONLY-USER",
        "AUTH-SET-SESSION-NOTE-TENANT-A-USER",
        "AUTH-SET-SESSION-NOTE-TENANT-B-USER",
        "BEHAVIOUR-CUSTOMER-UPDATE",
        "BEHAVIOUR-SET-SESSION-NOTE",
    ):
        findings.append(_finding(test_id, "passed", "info", "complete"))

    findings.append(_finding("INVENTORY-001", "passed", "info", "not_required"))
    return findings


def _write_report(root: Path, findings: list[dict]) -> Path:
    run_dir = root / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "assessment": "fail",
                "findings": findings,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "index.html").write_text("<html></html>", encoding="utf-8")
    (run_dir / "junit.xml").write_text("<testsuite/>", encoding="utf-8")
    (run_dir / "results.sarif").write_text("{}", encoding="utf-8")
    return root


def _run(profile: str, root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), profile, str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_verifier_accepts_characterized_temporal_profile(tmp_path: Path) -> None:
    root = _write_report(tmp_path / "reports", _temporal_findings())

    result = _run("temporal", root)

    assert result.returncode == 0, result.stderr
    assert "REPORT_VERIFIED=temporal" in result.stdout


def test_verifier_accepts_characterized_http_profile(tmp_path: Path) -> None:
    root = _write_report(tmp_path / "reports", _http_findings())

    result = _run("http", root)

    assert result.returncode == 0, result.stderr
    assert "REPORT_VERIFIED=http" in result.stdout


def test_verifier_rejects_unexpected_non_pass_finding(tmp_path: Path) -> None:
    findings = _temporal_findings()
    findings.append(_finding("UNEXPECTED-ERROR", "error", "critical", "partial"))
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "unexpected non-pass finding" in result.stderr
    assert "UNEXPECTED-ERROR" in result.stderr


def test_verifier_rejects_missing_expected_finding(tmp_path: Path) -> None:
    findings = [item for item in _temporal_findings() if item["test_id"] != "TEMPORAL-METADATA-001"]
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "missing expected finding" in result.stderr
    assert "TEMPORAL-METADATA-001" in result.stderr


def test_verifier_rejects_wrong_temporal_drift_call(tmp_path: Path) -> None:
    findings = _temporal_findings()
    temporal = next(item for item in findings if item["test_id"] == "TEMPORAL-METADATA-001")
    temporal["observed"]["first_drift"]["after_call"] = 4
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "first drift after call 3" in result.stderr


def test_verifier_rejects_missing_required_pass(tmp_path: Path) -> None:
    findings = [
        item for item in _temporal_findings() if item["test_id"] != "AUTH-FORMAT-TEXT-REVIEWER"
    ]
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "AUTH-FORMAT-TEXT-REVIEWER" in result.stderr


def test_verifier_rejects_required_pass_changed_to_skipped(tmp_path: Path) -> None:
    findings = _temporal_findings()
    reviewer = next(item for item in findings if item["test_id"] == "AUTH-FORMAT-TEXT-REVIEWER")
    reviewer["status"] = "skipped"
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "AUTH-FORMAT-TEXT-REVIEWER" in result.stderr


def test_verifier_rejects_unexpected_skipped_finding(tmp_path: Path) -> None:
    findings = _temporal_findings()
    findings.append(
        _finding(
            "UNEXPECTED-SKIP",
            "skipped",
            "info",
            "not_required",
        )
    )
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "UNEXPECTED-SKIP" in result.stderr


def test_verifier_rejects_unexpected_passed_finding(tmp_path: Path) -> None:
    findings = _temporal_findings()
    findings.append(
        _finding(
            "UNEXPECTED-PASS",
            "passed",
            "info",
            "not_required",
        )
    )
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "UNEXPECTED-PASS" in result.stderr


def test_verifier_rejects_wrong_observation_for_required_pass(tmp_path: Path) -> None:
    findings = _temporal_findings()
    reviewer = next(item for item in findings if item["test_id"] == "AUTH-FORMAT-TEXT-REVIEWER")
    reviewer["observation"] = "complete"
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "AUTH-FORMAT-TEXT-REVIEWER" in result.stderr


def test_verifier_rejects_missing_report_artifact(tmp_path: Path) -> None:
    root = _write_report(tmp_path / "reports", _temporal_findings())
    (root / "run-1" / "results.sarif").unlink()

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "missing report artifacts" in result.stderr
    assert "results.sarif" in result.stderr


def test_verifier_rejects_duplicate_finding_id(tmp_path: Path) -> None:
    findings = _temporal_findings()
    findings.append(
        _finding(
            "AUTH-FORMAT-TEXT-REVIEWER",
            "passed",
            "info",
            "not_required",
        )
    )
    root = _write_report(tmp_path / "reports", findings)

    result = _run("temporal", root)

    assert result.returncode != 0
    assert "duplicate finding test_id" in result.stderr
    assert "AUTH-FORMAT-TEXT-REVIEWER" in result.stderr
