from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from failure_evidence import cleanup_resources
from run_isolation_check import (
    IsolationError,
    _assert_security,
    _resource_args,
    _run,
    _wait_exec,
)

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


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _control(
    evaluator: str,
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
        f"http://fixture-control:9000{path}",
        "" if payload is None else json.dumps(payload, sort_keys=True),
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise IsolationError(f"control response for {path} was not an object")
    return value


def _best_effort_fence_attempt(evaluator: str, attempt_id: str) -> None:
    snapshot = _control(evaluator, "GET", f"/attempts/{attempt_id}")
    attempt = snapshot.get("attempt")
    if not isinstance(attempt, dict):
        raise IsolationError("failure fence could not read trusted attempt state")
    state = str(attempt.get("state") or "")
    if state == "OPEN":
        _control(evaluator, "POST", f"/attempts/{attempt_id}/close")
        return
    if state in {"PREPARED", "FENCED", "FINALIZED", "ABORTED", "RECOVERY_REQUIRED"}:
        return
    raise IsolationError(f"failure fence observed unexpected attempt state: {state!r}")


def _find_run_dir(evaluator: str) -> str:
    code = (
        "from pathlib import Path; "
        "items=sorted({str(p.parent) for p in Path('/trusted-output/reports').glob('*/report.json')}); "
        "assert len(items)==1, items; print(items[0])"
    )
    return _run("docker", "exec", evaluator, "python", "-c", code).stdout.strip()


def _copy_volume(image: str, volume: str, source: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    name = f"p2b4-copy-{uuid.uuid4().hex[:10]}"
    _run(
        "docker",
        "create",
        "--name",
        name,
        "-v",
        f"{volume}:{source}:ro",
        "--entrypoint",
        "/bin/true",
        image,
    )
    try:
        _run("docker", "cp", f"{name}:{source}/.", str(destination))
    finally:
        _run("docker", "rm", "-f", name, check=False)


def _init_gate_volume(image: str, volume: str, mount: str) -> None:
    _run(
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "0:0",
        "-v",
        f"{volume}:{mount}",
        "--entrypoint",
        "sh",
        image,
        "-c",
        f"chown 10003:10003 {mount} && chmod 700 {mount}",
    )


def _gate_run(
    *,
    gate_image: str,
    policy: Path,
    evidence_root: Path,
    authority_volume: str,
    results_volume: str | None,
    arguments: list[str],
) -> dict[str, Any]:
    authority_mount = (
        f"{authority_volume}:/authority"
        if arguments and arguments[0] == "promote"
        else f"{authority_volume}:/authority:ro"
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "256m",
        "--cpus",
        "0.5",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "-v",
        f"{policy.resolve()}:/selected/policy-profile.json:ro",
        "-v",
        f"{evidence_root.resolve()}:/evidence:ro",
        "-v",
        authority_mount,
    ]
    if results_volume is not None:
        command.extend(["-v", f"{results_volume}:/results"])
    command.extend([gate_image, *arguments])
    result = _run(*command)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise IsolationError("gate emitted no machine-readable result")
    value = json.loads(lines[-1])
    if not isinstance(value, dict):
        raise IsolationError("gate result was not an object")
    return value


def _run_attempt(
    *,
    label: str,
    mode: str,
    missing_evidence: bool,
    inject_rejected_after_close: bool,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    gate_image: str,
    policy_digest: str,
    contract: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:10]
    net_ca = f"p2b4-ca-{label}-{suffix}"
    net_ec = f"p2b4-ec-{label}-{suffix}"
    net_ctrl = f"p2b4-ctrl-{label}-{suffix}"
    candidate = f"p2b4-candidate-{label}-{suffix}"
    app = f"p2b4-app-{label}-{suffix}"
    control = f"p2b4-control-{label}-{suffix}"
    evaluator = f"p2b4-evaluator-{label}-{suffix}"
    state_volume = f"p2b4-state-{label}-{suffix}"
    output_volume = f"p2b4-output-{label}-{suffix}"
    created_containers: list[str] = []
    created_networks: list[str] = []
    created_volumes: list[str] = []
    evaluator_control_connected = True
    attempt_dir = evidence_root / label
    attempt_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC).isoformat()
    attempt_id = ""
    token = ""
    finalized = False
    guard_exit = -1
    failure_stage = "runtime_setup"
    primary_error: BaseException | None = None
    primary_tb = None
    cleanup_result = None
    context: dict[str, Any] | None = None
    physical = {
        "candidate_container": candidate,
        "fixture_app_container": app,
        "fixture_control_container": control,
        "evaluator_container": evaluator,
        "candidate_app_network": net_ca,
        "evaluator_candidate_network": net_ec,
        "evaluator_control_network": net_ctrl,
    }

    def failure_fence() -> None:
        if not evaluator_control_connected and evaluator in created_containers:
            _run(
                "docker",
                "network",
                "connect",
                "--alias",
                "evaluator",
                net_ctrl,
                evaluator,
                check=False,
            )
        _best_effort_fence_attempt(evaluator, attempt_id)

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
            "--network-alias",
            "fixture-app",
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
            "--network-alias",
            "fixture-control",
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
            "--network-alias",
            "evaluator",
            *common,
            "-v",
            f"{output_volume}:/trusted-output",
            "-v",
            f"{contract.resolve()}:/trusted-contract/contract.yaml:ro",
            "--entrypoint",
            "python",
            evaluator_image,
            "-c",
            "import time; time.sleep(240)",
        )
        created_containers.append(evaluator)
        _run("docker", "network", "connect", "--alias", "evaluator", net_ctrl, evaluator)
        _wait_exec(
            evaluator,
            "import urllib.request; urllib.request.urlopen('http://fixture-control:9000/health', timeout=1).read()",
        )

        attempt_id = f"{label}-{suffix}"
        created = _control(evaluator, "POST", "/attempts", {"attempt_id": attempt_id})
        token = str(created.get("token") or "")
        if not token:
            raise IsolationError("fixture did not return attempt token")
        _control(evaluator, "POST", f"/attempts/{attempt_id}/open")

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            candidate,
            "--network",
            net_ca,
            "--network-alias",
            "candidate",
            *common,
            "-e",
            f"PHASE2_CANDIDATE_MODE={mode}",
            "-e",
            f"PHASE2_ATTEMPT_TOKEN={token}",
            "-e",
            "PHASE2_REVIEWER_TOKEN=synthetic-phase2-reviewer-token",
            "-e",
            "PHASE2_FIXTURE_APP=http://fixture-app:8001",
            candidate_image,
        )
        created_containers.append(candidate)
        _run("docker", "network", "connect", "--alias", "candidate", net_ec, candidate)

        _wait_exec(
            evaluator,
            "import urllib.request; urllib.request.urlopen('http://candidate:7000/healthz', timeout=1).read()",
        )
        _wait_exec(
            candidate,
            "import urllib.request; urllib.request.urlopen('http://fixture-app:8001/health', timeout=1).read()",
        )

        security = {
            candidate: _assert_security(
                candidate, [net_ca, net_ec], expected_uid=10002, candidate=True
            ),
            app: _assert_security(app, [net_ca], expected_uid=10001),
            control: _assert_security(control, [net_ctrl], expected_uid=10001),
            evaluator: _assert_security(evaluator, [net_ctrl, net_ec], expected_uid=10003),
        }
        _write(attempt_dir / "security.json", security)

        if missing_evidence:
            _run("docker", "network", "disconnect", net_ctrl, evaluator)
            evaluator_control_connected = False

        failure_stage = "guard_execution"
        guard = _run(
            "docker",
            "exec",
            "-e",
            "PHASE2_CANDIDATE_HOST=candidate",
            "-e",
            "PHASE2_CONTROL_HOST=fixture-control",
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
        guard_exit = guard.returncode
        (attempt_dir / "guard-stdout.txt").write_text(guard.stdout, encoding="utf-8")
        (attempt_dir / "guard-stderr.txt").write_text(guard.stderr, encoding="utf-8")
        (attempt_dir / "guard-exit-code.txt").write_text(f"{guard_exit}\n", encoding="utf-8")

        if missing_evidence:
            _run("docker", "network", "connect", "--alias", "evaluator", net_ctrl, evaluator)
            evaluator_control_connected = True
            _wait_exec(
                evaluator,
                "import urllib.request; urllib.request.urlopen('http://fixture-control:9000/health', timeout=1).read()",
            )

        failure_stage = "attempt_close"
        _control(evaluator, "POST", f"/attempts/{attempt_id}/close")
        if inject_rejected_after_close:
            rejected_code = r"""
import json
import os
import urllib.error
import urllib.request

payload = json.dumps(
    {
        "record_id": "synthetic-review-rejected",
        "value": "must-not-commit-after-fence",
        "request_id": "review-rejected-after-fence",
    }
).encode("utf-8")
request = urllib.request.Request(
    "http://fixture-app:8001/records/write",
    data=payload,
    method="POST",
    headers={
        "Authorization": f"Bearer {os.environ['PHASE2_ATTEMPT_TOKEN']}",
        "Content-Type": "application/json",
    },
)
try:
    urllib.request.urlopen(request, timeout=2)
except urllib.error.HTTPError as exc:
    if exc.code != 409:
        raise
    print(exc.code)
else:
    raise RuntimeError("post-fence write unexpectedly succeeded")
"""
            rejected = _run(
                "docker",
                "exec",
                candidate,
                "python",
                "-c",
                rejected_code,
            )
            if rejected.stdout.strip() != "409":
                raise IsolationError(
                    "post-fence candidate write did not produce expected rejection"
                )

        _run("docker", "stop", "-t", "2", candidate, check=False)

        failure_stage = "final_snapshot_export"
        final_snapshot = _control(evaluator, "POST", f"/attempts/{attempt_id}/final-snapshot")
        _write(attempt_dir / "final-snapshot.json", final_snapshot)

        failure_stage = "saved_run_copy"
        remote_run = _find_run_dir(evaluator)
        local_run = attempt_dir / "run"
        _run("docker", "cp", f"{evaluator}:{remote_run}/.", str(local_run))

        failure_stage = "finalization"
        finalized_response = _control(evaluator, "POST", f"/attempts/{attempt_id}/finalize")
        finalized = finalized_response.get("state") == "FINALIZED"
        _write(attempt_dir / "finalize-response.json", finalized_response)

        failure_stage = "context_assembly"
        run_dir = attempt_dir / "run"
        report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
        receipt = json.loads((run_dir / "receipt.json").read_text(encoding="utf-8"))
        inventory = run_dir / "tool-inventory.json"
        if not inventory.is_file():
            raise IsolationError(f"{label}: tool-inventory.json missing")
        if not attempt_id or not token or not finalized:
            raise IsolationError(f"{label}: attempt did not reach trusted finalized state")

        context = {
            "schema_version": 1,
            "policy_profile_digest": policy_digest,
            "attempt_id": attempt_id,
            "guard_run_id": report.get("run_id"),
            "candidate_image": candidate_image,
            "candidate_mode": mode,
            "orchestrator_sha256": _sha(Path(__file__).resolve()),
            "evaluator_image": evaluator_image,
            "fixture_image": fixture_image,
            "gate_image": gate_image,
            "credential_principal": "candidate_app",
            "credential_token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "logical_candidate_origin": "http://candidate:7000",
            "logical_control_origin": "http://fixture-control:9000",
            "logical_fixture_app_origin": "http://fixture-app:8001",
            "report_json_sha256": _sha(run_dir / "report.json"),
            "receipt_json_sha256": _sha(run_dir / "receipt.json"),
            "tool_inventory_sha256": _sha(inventory),
            "final_snapshot_sha256": _sha(attempt_dir / "final-snapshot.json"),
            "subject_binding": "valid",
            "attempt_completion": "finalized",
            "cleanup_complete": False,
            "platform": "linux/arm64",
            "started_at": started,
            "finished_at": None,
            "physical_runtime": physical,
            "guard_exit_code": guard_exit,
            "injected_rejected_after_close": inject_rejected_after_close,
            "receipt_logical_target": receipt.get("context", {}).get("logical_target"),
        }
        _write(attempt_dir / "execution-context.json", context)
        failure_stage = "cleanup"
    except BaseException as exc:
        primary_error = exc
        primary_tb = exc.__traceback__

    try:
        cleanup_result = cleanup_resources(
            run=_run,
            evidence_dir=attempt_dir,
            containers=created_containers,
            networks=created_networks,
            volumes=created_volumes,
            state_volume=state_volume,
            output_volume=output_volume,
            fixture_image=fixture_image,
            evaluator_image=evaluator_image,
            preserve_on_failure=primary_error is not None,
            failure_stage=failure_stage if primary_error is not None else None,
            fence=failure_fence if primary_error is not None and attempt_id else None,
        )
    except Exception as cleanup_exc:
        _write(
            attempt_dir / "cleanup-helper-error.json",
            {
                "failure_stage": failure_stage,
                "cleanup_error_type": type(cleanup_exc).__name__,
                "cleanup_error": str(cleanup_exc),
                "primary_error_present": primary_error is not None,
                "owned_resources": {
                    "containers": list(created_containers),
                    "networks": list(created_networks),
                    "volumes": list(created_volumes),
                },
                "finish_only_recovery_required": True,
                "committed_pass_permitted": False,
            },
        )
        if primary_error is not None:
            raise primary_error.with_traceback(primary_tb) from cleanup_exc
        raise

    if primary_error is not None:
        raise primary_error.with_traceback(primary_tb)

    if cleanup_result is None or not cleanup_result.cleanup_complete:
        raise IsolationError(
            f"{label}: cleanup incomplete; finish-only recovery required: {cleanup_result!r}"
        )
    if context is None:
        raise IsolationError(f"{label}: execution context was not assembled before cleanup")

    context["cleanup_complete"] = True
    context["finished_at"] = datetime.now(UTC).isoformat()
    _write(attempt_dir / "execution-context.json", context)
    return context


def _make_policy(
    *,
    output: Path,
    contract: Path,
    expected_checks: Path,
    rules: Path,
    gate_source: Path,
    orchestrator: Path,
    runtime_profile: Path,
    fixture_profile: Path,
    evaluator_image: str,
    fixture_image: str,
    gate_image: str,
    guard_wheel_sha: str,
) -> str:
    profile = {
        "schema_version": 1,
        "platform": "linux/arm64",
        "contract_sha256": _sha(contract),
        "expected_checks_sha256": _sha(expected_checks),
        "gate_rules_sha256": _sha(rules),
        "gate_source_sha256": _sha(gate_source),
        "orchestrator_sha256": _sha(orchestrator),
        "runtime_profile_sha256": _sha(runtime_profile),
        "fixture_profile_sha256": _sha(fixture_profile),
        "guard": {"version": "0.6.2", "wheel_sha256": guard_wheel_sha},
        "images": {
            "evaluator": evaluator_image,
            "fixture": fixture_image,
            "gate": gate_image,
        },
        "stable_coordinates": {
            "candidate_origin": "http://candidate:7000",
            "control_origin": "http://fixture-control:9000",
            "fixture_app_origin": "http://fixture-app:8001",
        },
        "comparison": {
            "receipt_schema": 1,
            "normalization_version": 3,
            "report_schema": 2,
            "structured_comparator_required": True,
            "comparator_exit_code_is_verdict": False,
            "freshness_source": "trusted_execution_context",
        },
    }
    _write(output, profile)
    return _sha(output)


def _read_gate_json(result: dict[str, Any], key: str) -> str:
    value = result.get(key)
    if not isinstance(value, str) or not value:
        raise IsolationError(f"gate result missing {key}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-profile", type=Path, required=True)
    parser.add_argument("--fixture-profile", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--gate-dir", type=Path, required=True)
    parser.add_argument("--gate-image", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--guard-wheel-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    evidence = args.output / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    policy_path = args.output / "policy-profile.json"
    policy_digest = _make_policy(
        output=policy_path,
        contract=args.contract,
        expected_checks=args.gate_dir / "expected-checks.json",
        rules=args.gate_dir / "gate-rules.json",
        gate_source=args.gate_dir / "gate.py",
        orchestrator=Path(__file__).resolve(),
        runtime_profile=args.runtime_profile,
        fixture_profile=args.fixture_profile,
        evaluator_image=json.loads(args.runtime_profile.read_text(encoding="utf-8"))["images"][
            "evaluator"
        ]["oci_index_digest"],
        fixture_image=json.loads(args.runtime_profile.read_text(encoding="utf-8"))["images"][
            "fixture"
        ]["oci_index_digest"],
        gate_image=args.gate_image,
        guard_wheel_sha=args.guard_wheel_sha,
    )
    runtime = json.loads(args.runtime_profile.read_text(encoding="utf-8"))
    evaluator_image = str(runtime["images"]["evaluator"]["oci_index_digest"])
    fixture_image = str(runtime["images"]["fixture"]["oci_index_digest"])

    reference = _run_attempt(
        label="reference",
        mode="good",
        missing_evidence=False,
        inject_rejected_after_close=False,
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=args.candidate_image,
        gate_image=args.gate_image,
        policy_digest=policy_digest,
        contract=args.contract,
        evidence_root=evidence,
    )

    authority_volume = f"p2b4-authority-{uuid.uuid4().hex[:10]}"
    results_volume = f"p2b4-results-{uuid.uuid4().hex[:10]}"
    _run("docker", "volume", "create", authority_volume)
    _run("docker", "volume", "create", results_volume)
    _init_gate_volume(args.gate_image, authority_volume, "/authority")
    _init_gate_volume(args.gate_image, results_volume, "/results")

    try:
        promoted = _gate_run(
            gate_image=args.gate_image,
            policy=policy_path,
            evidence_root=args.output,
            authority_volume=authority_volume,
            results_volume=None,
            arguments=[
                "promote",
                "--policy",
                "/selected/policy-profile.json",
                "--reference-dir",
                "/evidence/evidence/reference/run",
                "--reference-context",
                "/evidence/evidence/reference/execution-context.json",
                "--reference-final",
                "/evidence/evidence/reference/final-snapshot.json",
                "--output",
                "/authority/approval-bundle.json",
                "--selected-gate-image",
                args.gate_image,
            ],
        )
        approval_digest = _read_gate_json(promoted, "approval_bundle_digest")

        approval_text = _run(
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{authority_volume}:/authority:ro",
            "--entrypoint",
            "cat",
            args.gate_image,
            "/authority/approval-bundle.json",
        ).stdout
        approval_copy = json.loads(approval_text)
        if not isinstance(approval_copy, dict):
            raise IsolationError("promoted approval bundle was not an object")
        tamper = evidence / "tamper"
        tamper.mkdir(parents=True, exist_ok=True)
        approval_copy["policy_profile_digest"] = "0" * 64
        _write(tamper / "bad-approval.json", approval_copy)

        attempts: dict[str, dict[str, Any]] = {}
        for label, mode, missing, inject_rejected in (
            ("candidate-good", "good", False, False),
            ("candidate-write", "write", False, False),
            ("candidate-review", "good", False, True),
            ("candidate-missing", "good", True, False),
        ):
            attempts[label] = _run_attempt(
                label=label,
                mode=mode,
                missing_evidence=missing,
                inject_rejected_after_close=inject_rejected,
                evaluator_image=evaluator_image,
                fixture_image=fixture_image,
                candidate_image=args.candidate_image,
                gate_image=args.gate_image,
                policy_digest=policy_digest,
                contract=args.contract,
                evidence_root=evidence,
            )

        outcomes: dict[str, str] = {}
        expected = {
            "candidate-good": "PASS",
            "candidate-write": "BLOCK",
            "candidate-review": "REVIEW",
            "candidate-missing": "INVALID",
        }
        for label, wanted in expected.items():
            context = attempts[label]
            result = _gate_run(
                gate_image=args.gate_image,
                policy=policy_path,
                evidence_root=args.output,
                authority_volume=authority_volume,
                results_volume=results_volume,
                arguments=[
                    "evaluate",
                    "--policy",
                    "/selected/policy-profile.json",
                    "--approval",
                    "/authority/approval-bundle.json",
                    "--selected-approval-digest",
                    approval_digest,
                    "--reference-dir",
                    "/evidence/evidence/reference/run",
                    "--reference-context",
                    "/evidence/evidence/reference/execution-context.json",
                    "--reference-final",
                    "/evidence/evidence/reference/final-snapshot.json",
                    "--candidate-dir",
                    f"/evidence/evidence/{label}/run",
                    "--candidate-context",
                    f"/evidence/evidence/{label}/execution-context.json",
                    "--candidate-final",
                    f"/evidence/evidence/{label}/final-snapshot.json",
                    "--expected-attempt-id",
                    str(context["attempt_id"]),
                    "--expected-candidate-image",
                    args.candidate_image,
                    "--expected-candidate-mode",
                    str(context["candidate_mode"]),
                    "--selected-gate-image",
                    args.gate_image,
                    "--result-root",
                    "/results",
                    "--result-id",
                    label,
                ],
            )
            outcome = _read_gate_json(result, "outcome")
            if outcome != wanted:
                raise IsolationError(f"{label}: expected gate {wanted}, got {outcome}")
            outcomes[label] = outcome

        good_context = json.loads(
            (evidence / "candidate-good" / "execution-context.json").read_text(encoding="utf-8")
        )
        good_context["candidate_image"] = "sha256:" + ("0" * 64)
        _write(tamper / "bad-context.json", good_context)

        tamper_cases = [
            (
                "tampered-context",
                "/evidence/evidence/candidate-good/run",
                "/evidence/evidence/tamper/bad-context.json",
                "/evidence/evidence/candidate-good/final-snapshot.json",
                str(attempts["candidate-good"]["attempt_id"]),
            ),
            (
                "swapped-run",
                "/evidence/evidence/candidate-write/run",
                "/evidence/evidence/candidate-good/execution-context.json",
                "/evidence/evidence/candidate-good/final-snapshot.json",
                str(attempts["candidate-good"]["attempt_id"]),
            ),
            (
                "stale-attempt",
                "/evidence/evidence/candidate-good/run",
                "/evidence/evidence/candidate-good/execution-context.json",
                "/evidence/evidence/candidate-good/final-snapshot.json",
                str(reference["attempt_id"]),
            ),
        ]
        for result_id, run_path, context_path, final_path, expected_attempt in tamper_cases:
            result = _gate_run(
                gate_image=args.gate_image,
                policy=policy_path,
                evidence_root=args.output,
                authority_volume=authority_volume,
                results_volume=results_volume,
                arguments=[
                    "evaluate",
                    "--policy",
                    "/selected/policy-profile.json",
                    "--approval",
                    "/authority/approval-bundle.json",
                    "--selected-approval-digest",
                    approval_digest,
                    "--reference-dir",
                    "/evidence/evidence/reference/run",
                    "--reference-context",
                    "/evidence/evidence/reference/execution-context.json",
                    "--reference-final",
                    "/evidence/evidence/reference/final-snapshot.json",
                    "--candidate-dir",
                    run_path,
                    "--candidate-context",
                    context_path,
                    "--candidate-final",
                    final_path,
                    "--expected-attempt-id",
                    expected_attempt,
                    "--expected-candidate-image",
                    args.candidate_image,
                    "--selected-gate-image",
                    args.gate_image,
                    "--result-root",
                    "/results",
                    "--result-id",
                    result_id,
                ],
            )
            if _read_gate_json(result, "outcome") != "INVALID":
                raise IsolationError(
                    f"{result_id}: malformed/swapped evidence did not yield INVALID"
                )
            outcomes[result_id] = "INVALID"

        bad_approval_result = _gate_run(
            gate_image=args.gate_image,
            policy=policy_path,
            evidence_root=args.output,
            authority_volume=authority_volume,
            results_volume=results_volume,
            arguments=[
                "evaluate",
                "--policy",
                "/selected/policy-profile.json",
                "--approval",
                "/evidence/evidence/tamper/bad-approval.json",
                "--selected-approval-digest",
                approval_digest,
                "--reference-dir",
                "/evidence/evidence/reference/run",
                "--reference-context",
                "/evidence/evidence/reference/execution-context.json",
                "--reference-final",
                "/evidence/evidence/reference/final-snapshot.json",
                "--candidate-dir",
                "/evidence/evidence/candidate-good/run",
                "--candidate-context",
                "/evidence/evidence/candidate-good/execution-context.json",
                "--candidate-final",
                "/evidence/evidence/candidate-good/final-snapshot.json",
                "--expected-attempt-id",
                str(attempts["candidate-good"]["attempt_id"]),
                "--expected-candidate-image",
                args.candidate_image,
                "--expected-candidate-mode",
                "good",
                "--selected-gate-image",
                args.gate_image,
                "--result-root",
                "/results",
                "--result-id",
                "tampered-approval",
            ],
        )
        if _read_gate_json(bad_approval_result, "outcome") != "INVALID":
            raise IsolationError("tampered approval bundle did not yield INVALID")
        outcomes["tampered-approval"] = "INVALID"

        _copy_volume(args.gate_image, authority_volume, "/authority", args.output / "authority")
        _copy_volume(args.gate_image, results_volume, "/results", args.output / "results")

        summary = {
            "schema_version": 1,
            "scope": "phase2b4_reference_gate_local_only",
            "policy_profile_digest": policy_digest,
            "approval_bundle_digest": approval_digest,
            "reference_attempt_id": reference["attempt_id"],
            "candidate_attempt_ids": {key: value["attempt_id"] for key, value in attempts.items()},
            "outcomes": outcomes,
            "stable_logical_coordinates": {
                "candidate": "http://candidate:7000",
                "control": "http://fixture-control:9000",
                "fixture_app": "http://fixture-app:8001",
            },
        }
        _write(args.output / "approval-summary.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
    except Exception:
        _write(
            args.output / "gate-recovery.json",
            {
                "authority_volume": authority_volume,
                "results_volume": results_volume,
                "preserved_for_finish_only_recovery": True,
            },
        )
        raise
    else:
        for volume in (authority_volume, results_volume):
            _run("docker", "volume", "rm", volume, check=False)
            if _run("docker", "volume", "inspect", volume, check=False).returncode == 0:
                raise IsolationError(f"gate volume still present after cleanup: {volume}")


if __name__ == "__main__":
    main()
