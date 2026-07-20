from pathlib import Path

from mcp_behaviour_guard.alerts import finding_fingerprint, select_alert_findings
from mcp_behaviour_guard.models import Finding, FindingStatus, RunSummary, Severity
from mcp_behaviour_guard.storage import RunStore


def _summary() -> RunSummary:
    return RunSummary(
        run_id="run-1",
        target="stdio:python -m demo",
        contract_path="contract.yaml",
        started_at="start",
        finished_at="finish",
        findings=[
            Finding(
                test_id="HIGH-1",
                category="authorization",
                title="high failure",
                status=FindingStatus.FAILED,
                severity=Severity.HIGH,
                expected=False,
                observed=True,
            ),
            Finding(
                test_id="MEDIUM-1",
                category="behaviour",
                title="medium failure",
                status=FindingStatus.FAILED,
                severity=Severity.MEDIUM,
                expected=False,
                observed=True,
            ),
        ],
        invocations=[],
    )


def test_alert_filter_and_deduplication(tmp_path: Path) -> None:
    summary = _summary()
    selected = select_alert_findings(summary, Severity.HIGH)
    assert [item.test_id for item in selected] == ["HIGH-1"]

    store = RunStore(tmp_path / "guard.db")
    try:
        finding = selected[0]
        fingerprint = finding_fingerprint(summary, finding)
        assert store.alert_is_due(fingerprint, None)
        store.record_alert(fingerprint, summary.run_id, finding, "{}")
        assert not store.alert_is_due(fingerprint, None)

        changed = finding.model_copy(update={"observed": {"dynamic_count": 99}})
        assert finding_fingerprint(summary, changed) == fingerprint
    finally:
        store.close()
