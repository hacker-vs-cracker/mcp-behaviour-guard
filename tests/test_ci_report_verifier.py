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
