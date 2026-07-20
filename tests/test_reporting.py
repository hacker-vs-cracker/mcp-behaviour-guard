from pathlib import Path

from mcp_behaviour_guard.models import Finding, FindingStatus, RunSummary, Severity
from mcp_behaviour_guard.reporting import write_reports


def test_report_writers(tmp_path: Path) -> None:
    finding = Finding(
        test_id="TENANT-1",
        category="tenant_isolation",
        title="tenant boundary",
        status=FindingStatus.FAILED,
        severity=Severity.CRITICAL,
        expected={"denied": True},
        observed={"allowed": True},
    )
    passed_high = Finding(
        test_id="HIGH-PASSED",
        category="runtime_behaviour",
        title="high-priority control passed",
        status=FindingStatus.PASSED,
        severity=Severity.HIGH,
        expected=True,
        observed=True,
    )
    summary = RunSummary(
        run_id="run-1",
        target="http://target/mcp",
        contract_path="contract.yaml",
        started_at="start",
        finished_at="finish",
        findings=[passed_high, finding],
        invocations=[],
    )

    paths = write_reports(summary, tmp_path, ["json", "html", "junit", "sarif"])

    assert {path.name for path in paths} == {
        "report.json",
        "index.html",
        "junit.xml",
        "results.sarif",
    }
    html = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "tenant boundary" in html
    assert "<details>" in html
    assert "Expand evidence" in html
    assert "Expand visible" in html
    assert "critical open" in html
    assert html.index("TENANT-1") < html.index("HIGH-PASSED")
    assert "<strong>0</strong>high open" in html
