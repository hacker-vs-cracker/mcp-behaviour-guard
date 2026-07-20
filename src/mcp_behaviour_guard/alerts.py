from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from .models import Finding, FindingStatus, RunSummary, Severity
from .storage import RunStore
from .util import stable_hash

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(slots=True)
class AlertResult:
    selected: list[Finding]
    sent: list[Finding]
    suppressed: list[Finding]


def select_alert_findings(summary: RunSummary, minimum: Severity) -> list[Finding]:
    return [
        finding
        for finding in summary.findings
        if finding.status in {FindingStatus.FAILED, FindingStatus.ERROR}
        and _SEVERITY_RANK[finding.severity] >= _SEVERITY_RANK[minimum]
    ]


def finding_fingerprint(summary: RunSummary, finding: Finding) -> str:
    return stable_hash(
        {
            "target": summary.target,
            "test_id": finding.test_id,
            "category": finding.category,
            "severity": finding.severity.value,
            "title": finding.title,
        }
    )


def send_alerts(
    summary: RunSummary,
    store: RunStore,
    webhook_url: str,
    minimum: Severity,
    only_new: bool = True,
    repeat_after_hours: float | None = None,
    timeout_seconds: float = 10,
) -> AlertResult:
    selected = select_alert_findings(summary, minimum)
    sent: list[Finding] = []
    suppressed: list[Finding] = []

    for finding in selected:
        fingerprint = finding_fingerprint(summary, finding)
        if only_new and not store.alert_is_due(fingerprint, repeat_after_hours):
            suppressed.append(finding)
            continue

        payload = {
            "text": (
                f"MCP Behaviour Guard: {finding.severity.value.upper()} "
                f"{finding.test_id} on {summary.target} — {finding.title}"
            ),
            "run_id": summary.run_id,
            "target": summary.target,
            "finding": finding.model_dump(mode="json"),
        }
        response = httpx.post(webhook_url, json=payload, timeout=timeout_seconds)
        response.raise_for_status()
        store.record_alert(fingerprint, summary.run_id, finding, json.dumps(payload))
        sent.append(finding)

    return AlertResult(selected=selected, sent=sent, suppressed=suppressed)
