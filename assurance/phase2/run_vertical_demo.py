from __future__ import annotations

import argparse
import json
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from run_isolation_check import (
    IsolationError,
    _assert_security,
    _resource_args,
    _run,
    _wait_exec,
)

CASES = ("good", "write", "missing_evidence")
REQUIRED_ORDINARY = {
    "INVENTORY-001",
    "AUTH-LOOKUP-RECORD-REVIEWER",
    "AUTH-LOOKUP-RECORD-ANONYMOUS",
    "BEHAVIOUR-LOOKUP-RECORD",
}

_CONTROL_CLIENT = r"""
import json
import sys
import urllib.request

method, url, payload = sys.argv[1], sys.argv[2], sys.argv[3]
body = None if payload == "" else json.dumps(json.loads(payload)).encode("utf-8")
request = urllib.request.Request(
    url,
    data=body,
    method=method,
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=3) as response:
    print(response.read().decode("utf-8"))
"""


@dataclass(frozen=True)
class CaseResult:
    name: str
    guard_exit_code: int
    assessment: str
    ordinary_findings: dict[str, str]
    audit_count: int
    final_watermark: int
    audit_complete: bool
    run_path: str


def _control(
    evaluator: str,
    control: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = _run(
        "docker",
        "exec",
        evaluator,
        "python",
        "-c",
        _CONTROL_CLIENT,
        method,
        f"http://{control}:9000{path}",
        "" if payload is None else json.dumps(payload, sort_keys=True),
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise IsolationError(f"control response for {path} was not an object")
    return value


def _find_run_dir(evaluator: str) -> str:
    code = (
        "from pathlib import Path; "
        "items=sorted({str(p.parent) for p in Path('/trusted-output/reports').glob('*/report.json')}); "
        "assert len(items)==1, items; print(items[0])"
    )
    result = _run("docker", "exec", evaluator, "python", "-c", code)
    return result.stdout.strip()


def _load_report(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "report.json"
    receipt = run_dir / "receipt.json"
    if not path.is_file() or not receipt.is_file():
        raise IsolationError("Guard run directory is missing report.json or receipt.json")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise IsolationError("report.json was not an object")
    return value


def _finding_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise IsolationError("report findings were missing")
    indexed: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise IsolationError("report contained a non-object finding")
        test_id = finding.get("test_id")
        if not isinstance(test_id, str) or not test_id:
            raise IsolationError("report contained a finding without test_id")
        if test_id in indexed:
            raise IsolationError(f"duplicate finding id in report: {test_id}")
        indexed[test_id] = finding
    return indexed


def _validate_case(
    name: str,
    guard_exit: int,
    report: dict[str, Any],
    final_snapshot: dict[str, Any],
) -> CaseResult:
    findings = _finding_map(report)
    ordinary = {
        test_id: str(findings[test_id].get("status"))
        for test_id in sorted(REQUIRED_ORDINARY)
        if test_id in findings
    }
    if set(ordinary) != REQUIRED_ORDINARY:
        raise IsolationError(f"{name}: ordinary required finding set is incomplete: {ordinary!r}")

    audit = final_snapshot.get("audit")
    if not isinstance(audit, list):
        raise IsolationError(f"{name}: final audit list missing")
    if final_snapshot.get("audit_complete") is not True:
        raise IsolationError(f"{name}: final audit did not report completeness")
    watermark = final_snapshot.get("final_watermark")
    if not isinstance(watermark, int) or watermark != len(audit):
        raise IsolationError(f"{name}: final watermark does not match audit size")
    if any(not isinstance(item, dict) or item.get("kind") != "database_write" for item in audit):
        raise IsolationError(f"{name}: unexpected whole-attempt audit event kind")

    assessment = str(report.get("assessment"))
    if name == "good":
        if guard_exit != 0 or assessment != "pass":
            raise IsolationError(f"good: expected Guard pass/0, got {assessment}/{guard_exit}")
        if any(status != "passed" for status in ordinary.values()):
            raise IsolationError(f"good: ordinary finding did not pass: {ordinary!r}")
        if audit:
            raise IsolationError("good: whole-attempt audit unexpectedly contains database writes")
    elif name == "write":
        if guard_exit != 1 or assessment != "fail":
            raise IsolationError(f"write: expected Guard fail/1, got {assessment}/{guard_exit}")
        if not audit:
            raise IsolationError(
                "write: forbidden candidate produced no authoritative DB audit event"
            )
        failed = {
            test_id for test_id, finding in findings.items() if finding.get("status") == "failed"
        }
        if "BEHAVIOUR-LOOKUP-RECORD" not in failed and not any(
            item.endswith("-EFFECTS") for item in failed
        ):
            raise IsolationError(f"write: no Guard side-effect failure was retained: {failed!r}")
    elif name == "missing_evidence":
        if guard_exit != 2 or assessment != "inconclusive":
            raise IsolationError(
                f"missing_evidence: expected Guard inconclusive/2, got {assessment}/{guard_exit}"
            )
        if audit:
            raise IsolationError("missing_evidence: protected mutation path unexpectedly wrote")
        invocations = report.get("invocations")
        if not isinstance(invocations, list):
            raise IsolationError("missing_evidence: invocation evidence missing")
        if any(
            isinstance(item, dict)
            and item.get("tool") == "lookup_record"
            and item.get("execution") == "succeeded"
            for item in invocations
        ):
            raise IsolationError(
                "missing_evidence: lookup_record executed despite unavailable required observation"
            )
        if not any(
            isinstance(finding, dict)
            and finding.get("status") == "error"
            and finding.get("observation") == "unavailable"
            for finding in findings.values()
        ):
            raise IsolationError(
                "missing_evidence: report did not preserve unavailable-observation evidence"
            )
    else:  # pragma: no cover
        raise IsolationError(f"unknown case: {name}")

    return CaseResult(
        name=name,
        guard_exit_code=guard_exit,
        assessment=assessment,
        ordinary_findings=ordinary,
        audit_count=len(audit),
        final_watermark=watermark,
        audit_complete=True,
        run_path=f"{name}/run",
    )


def _run_case(
    *,
    name: str,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output_root: Path,
) -> CaseResult:
    suffix = uuid.uuid4().hex[:10]
    net_ca = f"p2b3-ca-{name}-{suffix}"
    net_ec = f"p2b3-ec-{name}-{suffix}"
    net_ctrl = f"p2b3-ctrl-{name}-{suffix}"
    candidate = f"p2b3-candidate-{name}-{suffix}"
    app = f"p2b3-app-{name}-{suffix}"
    control = f"p2b3-control-{name}-{suffix}"
    evaluator = f"p2b3-evaluator-{name}-{suffix}"
    state_volume = f"p2b3-state-{name}-{suffix}"
    output_volume = f"p2b3-output-{name}-{suffix}"
    created_containers: list[str] = []
    created_networks: list[str] = []
    created_volumes: list[str] = []
    case_dir = output_root / name
    case_dir.mkdir(parents=True, exist_ok=True)
    cleanup_errors: list[str] = []
    evaluator_control_connected = True

    try:
        for network in (net_ca, net_ec, net_ctrl):
            _run(
                "docker",
                "network",
                "create",
                "--internal",
                "--opt",
                "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                network,
            )
            created_networks.append(network)
        _run("docker", "volume", "create", state_volume)
        created_volumes.append(state_volume)
        _run("docker", "volume", "create", output_volume)
        created_volumes.append(output_volume)

        common = _resource_args()
        _run(
            "docker",
            "run",
            "-d",
            "--name",
            app,
            "--network",
            net_ca,
            *common,
            "-v",
            f"{state_volume}:/state",
            fixture_image,
            "python",
            "app_service.py",
            "--db",
            "/state/fixture.db",
            "--host",
            "0.0.0.0",
            "--port",
            "8001",
        )
        created_containers.append(app)

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            control,
            "--network",
            net_ctrl,
            *common,
            "-v",
            f"{state_volume}:/state",
            fixture_image,
            "python",
            "control_service.py",
            "--db",
            "/state/fixture.db",
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
        )
        created_containers.append(control)

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            evaluator,
            "--network",
            net_ec,
            *common,
            "-v",
            f"{output_volume}:/trusted-output",
            "-v",
            f"{contract.resolve()}:/trusted-contract/contract.yaml:ro",
            "--entrypoint",
            "python",
            evaluator_image,
            "-c",
            "import time; time.sleep(180)",
        )
        created_containers.append(evaluator)
        _run("docker", "network", "connect", net_ctrl, evaluator)

        _wait_exec(
            evaluator,
            f"import urllib.request; urllib.request.urlopen('http://{control}:9000/health', timeout=1).read()",
        )

        attempt_id = f"{name}-{suffix}"
        created = _control(
            evaluator,
            control,
            "POST",
            "/attempts",
            {"attempt_id": attempt_id},
        )
        token = created.get("token")
        if not isinstance(token, str) or not token:
            raise IsolationError(f"{name}: control plane did not return an attempt credential")
        _control(evaluator, control, "POST", f"/attempts/{attempt_id}/open")

        mode = "write" if name == "write" else "good"
        _run(
            "docker",
            "run",
            "-d",
            "--name",
            candidate,
            "--network",
            net_ca,
            *common,
            "-e",
            f"PHASE2_CANDIDATE_MODE={mode}",
            "-e",
            f"PHASE2_ATTEMPT_TOKEN={token}",
            "-e",
            "PHASE2_REVIEWER_TOKEN=synthetic-phase2-reviewer-token",
            "-e",
            f"PHASE2_FIXTURE_APP=http://{app}:8001",
            candidate_image,
        )
        created_containers.append(candidate)
        _run("docker", "network", "connect", net_ec, candidate)

        _wait_exec(
            evaluator,
            f"import urllib.request; urllib.request.urlopen('http://{candidate}:7000/healthz', timeout=1).read()",
        )
        _wait_exec(
            candidate,
            f"import urllib.request; urllib.request.urlopen('http://{app}:8001/health', timeout=1).read()",
        )

        security = {
            candidate: _assert_security(
                candidate, [net_ca, net_ec], expected_uid=10002, candidate=True
            ),
            app: _assert_security(app, [net_ca], expected_uid=10001),
            control: _assert_security(control, [net_ctrl], expected_uid=10001),
            evaluator: _assert_security(evaluator, [net_ctrl, net_ec], expected_uid=10003),
        }
        (case_dir / "security.json").write_text(
            json.dumps(security, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        if name == "missing_evidence":
            _run("docker", "network", "disconnect", net_ctrl, evaluator)
            evaluator_control_connected = False

        guard = _run(
            "docker",
            "exec",
            "-e",
            f"PHASE2_CANDIDATE_HOST={candidate}",
            "-e",
            f"PHASE2_CONTROL_HOST={control}",
            evaluator,
            "mcp-guard",
            "run",
            "/trusted-contract/contract.yaml",
            "--output",
            "/trusted-output/reports",
            "--database",
            "/trusted-output/guard.db",
            "--lab-mode",
            check=False,
        )
        (case_dir / "guard-stdout.txt").write_text(guard.stdout, encoding="utf-8")
        (case_dir / "guard-stderr.txt").write_text(guard.stderr, encoding="utf-8")
        (case_dir / "guard-exit-code.txt").write_text(
            f"{guard.returncode}\n",
            encoding="utf-8",
        )

        if name == "missing_evidence":
            _run("docker", "network", "connect", net_ctrl, evaluator)
            evaluator_control_connected = True
            _wait_exec(
                evaluator,
                f"import urllib.request; urllib.request.urlopen('http://{control}:9000/health', timeout=1).read()",
            )

        _control(evaluator, control, "POST", f"/attempts/{attempt_id}/close")
        _run("docker", "stop", "-t", "2", candidate)
        final_snapshot = _control(
            evaluator,
            control,
            "POST",
            f"/attempts/{attempt_id}/final-snapshot",
        )
        (case_dir / "final-snapshot.json").write_text(
            json.dumps(final_snapshot, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        remote_run = _find_run_dir(evaluator)
        local_run = case_dir / "run"
        if local_run.exists():
            shutil.rmtree(local_run)
        _run("docker", "cp", f"{evaluator}:{remote_run}/.", str(local_run))
        report = _load_report(local_run)

        _control(evaluator, control, "POST", f"/attempts/{attempt_id}/finalize")
        return _validate_case(name, guard.returncode, report, final_snapshot)
    finally:
        if not evaluator_control_connected and evaluator in created_containers:
            _run("docker", "network", "connect", net_ctrl, evaluator, check=False)

        for resource in reversed(created_containers):
            result = _run("docker", "rm", "-f", resource, check=False)
            if result.returncode != 0:
                cleanup_errors.append(f"container {resource}: {result.stderr.strip()}")
        for resource in reversed(created_networks):
            result = _run("docker", "network", "rm", resource, check=False)
            if result.returncode != 0:
                cleanup_errors.append(f"network {resource}: {result.stderr.strip()}")
        for resource in reversed(created_volumes):
            result = _run("docker", "volume", "rm", resource, check=False)
            if result.returncode != 0:
                cleanup_errors.append(f"volume {resource}: {result.stderr.strip()}")

        for resource in created_containers:
            if _run("docker", "container", "inspect", resource, check=False).returncode == 0:
                cleanup_errors.append(f"container {resource}: still present after removal")
        for resource in created_networks:
            if _run("docker", "network", "inspect", resource, check=False).returncode == 0:
                cleanup_errors.append(f"network {resource}: still present after removal")
        for resource in created_volumes:
            if _run("docker", "volume", "inspect", resource, check=False).returncode == 0:
                cleanup_errors.append(f"volume {resource}: still present after removal")

        (case_dir / "cleanup.json").write_text(
            json.dumps(
                {"cleanup_complete": not cleanup_errors, "cleanup_errors": cleanup_errors},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        if cleanup_errors:
            raise IsolationError(f"{name}: runtime cleanup failed: {cleanup_errors!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    evaluator_image = str(profile["images"]["evaluator"]["oci_index_digest"])
    fixture_image = str(profile["images"]["fixture"]["oci_index_digest"])
    args.output.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {}
    for case in CASES:
        result = _run_case(
            name=case,
            evaluator_image=evaluator_image,
            fixture_image=fixture_image,
            candidate_image=args.candidate_image,
            contract=args.contract,
            output_root=args.output,
        )
        results[case] = {
            "guard_exit_code": result.guard_exit_code,
            "assessment": result.assessment,
            "ordinary_findings": result.ordinary_findings,
            "audit_count": result.audit_count,
            "final_watermark": result.final_watermark,
            "audit_complete": result.audit_complete,
            "run_path": result.run_path,
        }

    summary = {
        "schema_version": 1,
        "scope": "phase2b3_vertical_demonstration_only",
        "candidate_image": args.candidate_image,
        "evaluator_image": evaluator_image,
        "fixture_image": fixture_image,
        "cases": results,
        "gate_decision": None,
        "reference_promotion": None,
    }
    (args.output / "vertical-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
