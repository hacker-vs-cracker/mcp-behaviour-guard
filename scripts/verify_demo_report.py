#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ExpectedFinding:
    status: str
    severity: str
    observation: str


EXPECTED: dict[str, dict[str, ExpectedFinding]] = {
    "stdio": {
        "AUTH-DIAGNOSTICS-ANONYMOUS": ExpectedFinding("failed", "critical", "not_required"),
        "AUTH-GET-WORKSPACE-NOTE-ANONYMOUS": ExpectedFinding("failed", "critical", "not_required"),
        "AUTH-RUN-PROJECT-TASK-ANONYMOUS": ExpectedFinding("failed", "critical", "complete"),
        "AUTH-RUN-PROJECT-TASK-ANONYMOUS-EFFECTS": ExpectedFinding("failed", "high", "complete"),
        "AUTH-RUN-PROJECT-TASK-LOCAL-DEVELOPER-EFFECTS": ExpectedFinding(
            "failed", "high", "complete"
        ),
        "AUTH-RUN-PROJECT-TASK-RESTRICTED-AGENT": ExpectedFinding("failed", "critical", "complete"),
        "AUTH-RUN-PROJECT-TASK-RESTRICTED-AGENT-EFFECTS": ExpectedFinding(
            "failed", "high", "complete"
        ),
        "AUTH-SET-WORKSPACE-NOTE-ANONYMOUS": ExpectedFinding("failed", "critical", "complete"),
        "AUTH-WORKSPACE-READ-ANONYMOUS": ExpectedFinding("failed", "critical", "not_required"),
        "BEHAVIOUR-DIAGNOSTICS": ExpectedFinding("error", "medium", "partial"),
        "BEHAVIOUR-GET-WORKSPACE-NOTE": ExpectedFinding("error", "medium", "partial"),
        "BEHAVIOUR-RUN-PROJECT-TASK": ExpectedFinding("failed", "high", "complete"),
        "BEHAVIOUR-WORKSPACE-READ": ExpectedFinding("error", "medium", "partial"),
        "STDIO-ENV-LEAK-001": ExpectedFinding("failed", "critical", "not_required"),
        "STDIO-PATH-BOUNDARY-001": ExpectedFinding("failed", "critical", "not_required"),
        "STDIO-SESSION-ISOLATION-001": ExpectedFinding("failed", "high", "complete"),
    },
    "temporal": {
        "BEHAVIOUR-FORMAT-TEXT": ExpectedFinding("error", "medium", "unavailable"),
        "TEMPORAL-METADATA-001": ExpectedFinding("failed", "high", "not_required"),
    },
    "http": {
        "AUTH-CUSTOMER-UPDATE-READ-ONLY-USER": ExpectedFinding("failed", "critical", "complete"),
        "AUTH-CUSTOMER-UPDATE-TENANT-A-USER": ExpectedFinding("failed", "critical", "complete"),
        "AUTH-CUSTOMER-UPDATE-TENANT-B-USER": ExpectedFinding("failed", "critical", "complete"),
        "BEHAVIOUR-CUSTOMER-LOOKUP": ExpectedFinding("failed", "high", "partial"),
        "BEHAVIOUR-GET-SESSION-NOTE": ExpectedFinding("error", "medium", "partial"),
        "REPLAY-CUSTOMER-UPDATE": ExpectedFinding("failed", "high", "complete"),
        "SESSION-ISOLATION-001": ExpectedFinding("failed", "high", "complete"),
        "TENANT-CUSTOMER-LOOKUP-TENANT-A-USER": ExpectedFinding(
            "failed", "critical", "not_required"
        ),
    },
}

REQUIRED_REPORT_FILES = {
    "report.json",
    "index.html",
    "junit.xml",
    "results.sarif",
}


class VerificationError(ValueError):
    pass


def _load_report(root: Path) -> tuple[Path, dict[str, Any]]:
    if root.is_file():
        if root.name != "report.json":
            raise VerificationError(f"expected report.json, got {root}")
        report = root
    elif (root / "report.json").is_file():
        report = root / "report.json"
    else:
        reports = list(root.glob("*/report.json"))
        if len(reports) != 1:
            raise VerificationError(
                f"expected exactly one report.json below {root}, got {len(reports)}"
            )
        report = reports[0]

    payload = json.loads(report.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise VerificationError("report root must be a JSON object")
    return report, payload


def _verify_artifacts(report: Path) -> None:
    missing = sorted(name for name in REQUIRED_REPORT_FILES if not (report.parent / name).is_file())
    if missing:
        raise VerificationError(f"missing report artifacts: {missing}")


def _index_findings(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise VerificationError("report findings must be a list")

    indexed: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise VerificationError("every finding must be a JSON object")
        test_id = finding.get("test_id")
        if not isinstance(test_id, str) or not test_id:
            raise VerificationError("every finding must have a non-empty test_id")
        if test_id in indexed:
            raise VerificationError(f"duplicate finding test_id: {test_id}")
        indexed[test_id] = finding
    return indexed


def verify(profile: str, root: Path) -> Path:
    if profile not in EXPECTED:
        raise VerificationError(f"unknown profile: {profile}")

    report, payload = _load_report(root)
    _verify_artifacts(report)

    if payload.get("schema_version") != 2:
        raise VerificationError(f"expected schema_version=2, got {payload.get('schema_version')!r}")
    if payload.get("assessment") != "fail":
        raise VerificationError(
            f"expected assessment='fail' for vulnerable demo, got {payload.get('assessment')!r}"
        )

    findings = _index_findings(payload)
    inventory = findings.get("INVENTORY-001")
    if inventory is None:
        raise VerificationError("missing required finding: INVENTORY-001")
    if inventory.get("status") != "passed":
        raise VerificationError(f"INVENTORY-001 must pass, got {inventory.get('status')!r}")

    expected = EXPECTED[profile]
    for test_id, requirement in expected.items():
        finding = findings.get(test_id)
        if finding is None:
            raise VerificationError(f"missing expected finding: {test_id}")

        actual = (
            finding.get("status"),
            finding.get("severity"),
            finding.get("observation"),
        )
        wanted = (
            requirement.status,
            requirement.severity,
            requirement.observation,
        )
        if actual != wanted:
            raise VerificationError(
                f"{test_id}: expected status/severity/observation={wanted}, got {actual}"
            )

    for test_id, finding in findings.items():
        status = finding.get("status")
        if status not in {"passed", "skipped"} and test_id not in expected:
            raise VerificationError(
                f"unexpected non-pass finding: {test_id} "
                f"status={status!r} severity={finding.get('severity')!r}"
            )

    if profile == "temporal":
        temporal = findings["TEMPORAL-METADATA-001"]
        observed = temporal.get("observed")
        first_drift = observed.get("first_drift") if isinstance(observed, dict) else None
        after_call = first_drift.get("after_call") if isinstance(first_drift, dict) else None
        if after_call != 3:
            raise VerificationError(
                f"TEMPORAL-METADATA-001 must record first drift after call 3; got {after_call!r}"
            )

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify one deliberate demo report against its expected regression profile."
    )
    parser.add_argument("profile", choices=sorted(EXPECTED))
    parser.add_argument("report_root", type=Path)
    args = parser.parse_args()

    try:
        report = verify(args.profile, args.report_root)
    except (OSError, json.JSONDecodeError, VerificationError) as exc:
        print(f"REPORT_VERIFICATION_ERROR={exc}", file=sys.stderr)
        return 1

    print(f"REPORT_VERIFIED={args.profile}")
    print(f"REPORT_PATH={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
