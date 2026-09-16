from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

# Bandit B405 false positive: this module generates XML but never parses input.
from xml.etree.ElementTree import Element, SubElement, tostring  # nosec B405

from jinja2 import Environment, PackageLoader, select_autoescape

from . import __version__
from .models import Finding, FindingStatus, RunSummary, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_STATUS_ORDER = {
    FindingStatus.FAILED: 0,
    FindingStatus.ERROR: 1,
    FindingStatus.PASSED: 2,
    FindingStatus.SKIPPED: 3,
}


def finding_sort_key(finding: Finding) -> tuple[int, int, str]:
    return (
        _SEVERITY_ORDER[finding.severity],
        _STATUS_ORDER[finding.status],
        finding.test_id,
    )


def sorted_findings(summary: RunSummary) -> list[Finding]:
    return sorted(summary.findings, key=finding_sort_key)


def write_reports(summary: RunSummary, output_dir: Path, formats: Sequence[str]) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if "json" in formats:
        path = output_dir / "report.json"
        path.write_text(summary.model_dump_json(indent=2), encoding="utf-8")
        written.append(path)
    if "html" in formats:
        path = output_dir / "index.html"
        environment = Environment(
            loader=PackageLoader("mcp_behaviour_guard", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
        findings = sorted_findings(summary)
        open_findings = [
            item
            for item in summary.findings
            if item.status in {FindingStatus.FAILED, FindingStatus.ERROR}
        ]
        counts = {
            severity.value: sum(item.severity == severity for item in open_findings)
            for severity in Severity
        }
        html = environment.get_template("report.html").render(
            summary=summary,
            findings=findings,
            counts=counts,
        )
        path.write_text(html, encoding="utf-8")
        written.append(path)
    if "junit" in formats:
        path = output_dir / "junit.xml"
        path.write_bytes(_junit(summary))
        written.append(path)
    if "sarif" in formats:
        path = output_dir / "results.sarif"
        path.write_text(json.dumps(_sarif(summary), indent=2), encoding="utf-8")
        written.append(path)

    return written


def _junit(summary: RunSummary) -> bytes:
    suite = Element(
        "testsuite",
        name="mcp-behaviour-guard",
        tests=str(len(summary.findings)),
        failures=str(sum(f.status == FindingStatus.FAILED for f in summary.findings)),
        errors=str(sum(f.status == FindingStatus.ERROR for f in summary.findings)),
        skipped=str(sum(f.status == FindingStatus.SKIPPED for f in summary.findings)),
    )
    for finding in summary.findings:
        case = SubElement(suite, "testcase", name=finding.test_id, classname=finding.category)
        payload = json.dumps(finding.observed, indent=2, default=str)
        if finding.status == FindingStatus.FAILED:
            SubElement(case, "failure", message=finding.title).text = payload
        elif finding.status == FindingStatus.ERROR:
            SubElement(case, "error", message=finding.title).text = payload
        elif finding.status == FindingStatus.SKIPPED:
            SubElement(case, "skipped", message=finding.title)
    return tostring(suite, encoding="utf-8", xml_declaration=True)


def _sarif(summary: RunSummary) -> dict:
    failures = [
        finding
        for finding in summary.findings
        if finding.status in {FindingStatus.FAILED, FindingStatus.ERROR}
    ]
    rules = {
        finding.test_id: {
            "id": finding.test_id,
            "name": finding.category,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation or "Review the attached evidence."},
        }
        for finding in failures
    }
    results = [
        {
            "ruleId": finding.test_id,
            "level": _sarif_level(finding.severity.value),
            "message": {"text": finding.title},
            "properties": {
                "expected": finding.expected,
                "observed": finding.observed,
                "evidence": finding.evidence,
            },
        }
        for finding in failures
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-behaviour-guard",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
