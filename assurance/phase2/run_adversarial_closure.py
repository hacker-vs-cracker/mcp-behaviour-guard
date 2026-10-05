from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from failure_evidence import cleanup_resources
from run_approval_demo import (
    _cleanup_gate_volumes,
    _copy_volume,
    _gate_run,
    _gate_volume_plans,
    _make_policy,
    _prepare_gate_volumes,
    _read_gate_json,
    _selected_platform_scope,
    _sha,
    _write,
)
from run_isolation_check import IsolationError, _resource_args, _run, _wait_exec

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

_HTTP_CLIENT = r"""
import json
import sys
import urllib.error
import urllib.request

method, url = sys.argv[1], sys.argv[2]
payload = None if len(sys.argv) < 4 or sys.argv[3] == "" else json.dumps(json.loads(sys.argv[3])).encode("utf-8")
request = urllib.request.Request(url, data=payload, method=method, headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(request, timeout=3) as response:
        print(json.dumps({"status": response.status, "body": response.read().decode("utf-8")}))
except urllib.error.HTTPError as exc:
    print(json.dumps({"status": exc.code, "body": exc.read().decode("utf-8")}))
"""


@dataclass
class Runtime:
    label: str
    net_ca: str
    net_ec: str
    net_ctrl: str
    state_volume: str
    output_volume: str
    app: str
    control: str
    evaluator: str
    candidate: str
    attempt_id: str
    cleanup_attempt_id: str
    token: str
    containers: list[str]
    networks: list[str]
    volumes: list[str]


CleanupCapture = Callable[[Runtime, Path], None]


def _control(
    runtime: Runtime,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = _run(
        "docker",
        "exec",
        runtime.evaluator,
        "python",
        "-c",
        _CONTROL_CLIENT,
        method,
        f"http://fixture-control:9000{path}",
        "" if payload is None else json.dumps(payload, sort_keys=True),
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise IsolationError(f"{runtime.label}: control response for {path} was not an object")
    return value


def _candidate_http(runtime: Runtime, method: str, path: str) -> dict[str, Any]:
    result = _run(
        "docker",
        "exec",
        runtime.evaluator,
        "python",
        "-c",
        _HTTP_CLIENT,
        method,
        f"http://candidate:7000{path}",
        "",
    )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise IsolationError(f"{runtime.label}: candidate response for {path} was not an object")
    body = value.get("body")
    if isinstance(body, str) and body:
        with contextlib.suppress(json.JSONDecodeError):
            value["json"] = json.loads(body)
    return value


def _best_effort_fence(runtime: Runtime) -> None:
    attempt_id = runtime.cleanup_attempt_id
    if not attempt_id:
        return
    snapshot = _control(runtime, "GET", f"/attempts/{attempt_id}")
    attempt = snapshot.get("attempt")
    if not isinstance(attempt, dict):
        raise IsolationError(f"{runtime.label}: failure fence could not read trusted attempt state")
    state = str(attempt.get("state") or "")
    if state == "OPEN":
        _control(runtime, "POST", f"/attempts/{attempt_id}/close")
        return
    if state in {"PREPARED", "FENCED", "FINALIZED", "ABORTED", "RECOVERY_REQUIRED"}:
        return
    raise IsolationError(
        f"{runtime.label}: failure fence observed unexpected attempt state: {state!r}"
    )


def _start_runtime(
    *,
    label: str,
    mode: str,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
) -> Runtime:
    suffix = uuid.uuid4().hex[:10]
    runtime = Runtime(
        label=label,
        net_ca=f"p2b5-ca-{label}-{suffix}",
        net_ec=f"p2b5-ec-{label}-{suffix}",
        net_ctrl=f"p2b5-ctrl-{label}-{suffix}",
        state_volume=f"p2b5-state-{label}-{suffix}",
        output_volume=f"p2b5-output-{label}-{suffix}",
        app=f"p2b5-app-{label}-{suffix}",
        control=f"p2b5-control-{label}-{suffix}",
        evaluator=f"p2b5-evaluator-{label}-{suffix}",
        candidate=f"p2b5-candidate-{label}-{suffix}",
        attempt_id=f"{label}-{suffix}",
        cleanup_attempt_id="",
        token="",
        containers=[],
        networks=[],
        volumes=[],
    )
    runtime.networks = [runtime.net_ca, runtime.net_ec, runtime.net_ctrl]
    runtime.volumes = [runtime.state_volume, runtime.output_volume]
    runtime.containers = [runtime.app, runtime.control, runtime.evaluator, runtime.candidate]
    common = _resource_args()

    try:
        for network in (runtime.net_ca, runtime.net_ec, runtime.net_ctrl):
            _run(
                "docker",
                "network",
                "create",
                "--internal",
                "--opt",
                "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                network,
            )
        for volume in (runtime.state_volume, runtime.output_volume):
            _run("docker", "volume", "create", volume)

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            runtime.app,
            "--network",
            runtime.net_ca,
            "--network-alias",
            "fixture-app",
            *common,
            "-v",
            f"{runtime.state_volume}:/state",
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

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            runtime.control,
            "--network",
            runtime.net_ctrl,
            "--network-alias",
            "fixture-control",
            *common,
            "-v",
            f"{runtime.state_volume}:/state",
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

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            runtime.evaluator,
            "--network",
            runtime.net_ec,
            "--network-alias",
            "evaluator",
            *common,
            "-v",
            f"{runtime.output_volume}:/trusted-output",
            "-v",
            f"{contract.resolve()}:/trusted-contract/contract.yaml:ro",
            "--entrypoint",
            "python",
            evaluator_image,
            "-c",
            "import time; time.sleep(300)",
        )
        _run(
            "docker",
            "network",
            "connect",
            "--alias",
            "evaluator",
            runtime.net_ctrl,
            runtime.evaluator,
        )
        _wait_exec(
            runtime.evaluator,
            "import urllib.request; urllib.request.urlopen('http://fixture-control:9000/health', timeout=1).read()",
        )
        _wait_exec(
            runtime.app,
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=1).read()",
        )

        runtime.cleanup_attempt_id = runtime.attempt_id
        created = _control(runtime, "POST", "/attempts", {"attempt_id": runtime.attempt_id})
        runtime.token = str(created.get("token") or "")
        if not runtime.token:
            raise IsolationError(f"{label}: no attempt credential")
        _control(runtime, "POST", f"/attempts/{runtime.attempt_id}/open")

        _run(
            "docker",
            "run",
            "-d",
            "--name",
            runtime.candidate,
            "--network",
            runtime.net_ca,
            "--network-alias",
            "candidate",
            *common,
            "-e",
            f"PHASE2_CANDIDATE_MODE={mode}",
            "-e",
            f"PHASE2_ATTEMPT_TOKEN={runtime.token}",
            "-e",
            "PHASE2_REVIEWER_TOKEN=synthetic-phase2-reviewer-token",
            "-e",
            "PHASE2_FIXTURE_APP=http://fixture-app:8001",
            candidate_image,
        )
        _run(
            "docker",
            "network",
            "connect",
            "--alias",
            "candidate",
            runtime.net_ec,
            runtime.candidate,
        )

        _wait_exec(
            runtime.evaluator,
            "import urllib.request; urllib.request.urlopen('http://candidate:7000/healthz', timeout=1).read()",
        )
        _wait_exec(
            runtime.evaluator,
            "import urllib.request; urllib.request.urlopen('http://fixture-control:9000/health', timeout=1).read()",
        )
    except BaseException as exc:
        primary_tb = exc.__traceback__
        try:
            _cleanup(
                runtime,
                output / label,
                fixture_image=fixture_image,
                evaluator_image=evaluator_image,
                preserve_on_failure=True,
                failure_stage="runtime_setup",
            )
        except BaseException as cleanup_exc:
            raise exc.with_traceback(primary_tb) from cleanup_exc
        raise

    return runtime


def _cleanup(
    runtime: Runtime,
    output: Path,
    *,
    fixture_image: str,
    evaluator_image: str,
    preserve_on_failure: bool,
    failure_stage: str | None,
    before_cleanup_capture: CleanupCapture | None = None,
) -> None:
    had_primary_error = preserve_on_failure and failure_stage is not None
    capture_error: BaseException | None = None
    capture_tb = None
    if before_cleanup_capture is not None:
        try:
            before_cleanup_capture(runtime, output)
        except BaseException as exc:
            capture_error = exc
            capture_tb = exc.__traceback__
            preserve_on_failure = True
            if failure_stage is None:
                failure_stage = "capture_export"
            output.mkdir(parents=True, exist_ok=True)
            (output / "capture-error.json").write_text(
                json.dumps(
                    {
                        "failure_stage": failure_stage,
                        "capture_error_type": type(exc).__name__,
                        "capture_error": "optional capture failed; raw error text omitted",
                        "finish_only_recovery_required": True,
                        "committed_pass_permitted": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

    try:
        result = cleanup_resources(
            run=_run,
            evidence_dir=output,
            containers=runtime.containers,
            networks=runtime.networks,
            volumes=runtime.volumes,
            state_volume=runtime.state_volume,
            output_volume=runtime.output_volume,
            fixture_image=fixture_image,
            evaluator_image=evaluator_image,
            preserve_on_failure=preserve_on_failure,
            failure_stage=failure_stage,
            fence=(lambda: _best_effort_fence(runtime)) if preserve_on_failure else None,
        )
    except Exception as exc:
        output.mkdir(parents=True, exist_ok=True)
        (output / "cleanup-helper-error.json").write_text(
            json.dumps(
                {
                    "failure_stage": failure_stage,
                    "cleanup_error_type": type(exc).__name__,
                    "cleanup_error": str(exc),
                    "primary_error_present": preserve_on_failure,
                    "owned_resources": {
                        "containers": list(runtime.containers),
                        "networks": list(runtime.networks),
                        "volumes": list(runtime.volumes),
                    },
                    "finish_only_recovery_required": True,
                    "committed_pass_permitted": False,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        if capture_error is not None and not had_primary_error:
            raise capture_error.with_traceback(capture_tb) from exc
        if preserve_on_failure:
            return
        raise

    if not result.cleanup_complete and not preserve_on_failure:
        raise IsolationError(
            f"{runtime.label}: cleanup incomplete; finish-only recovery required: {result!r}"
        )
    if capture_error is not None and not had_primary_error:
        raise capture_error.with_traceback(capture_tb)


def _guard_command(runtime: Runtime) -> list[str]:
    return [
        "docker",
        "exec",
        "-e",
        "PHASE2_CANDIDATE_HOST=candidate",
        "-e",
        "PHASE2_CONTROL_HOST=fixture-control",
        runtime.evaluator,
        "mcp-guard",
        "run",
        "/trusted-contract/contract.yaml",
        "--output",
        "/trusted-output/reports",
        "--database",
        "/trusted-output/guard.db",
        "--lab-mode",
    ]


def _run_guard(runtime: Runtime, case_dir: Path) -> int:
    result = _run(*_guard_command(runtime), check=False)
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "guard-stdout.txt").write_text(result.stdout, encoding="utf-8")
    (case_dir / "guard-stderr.txt").write_text(result.stderr, encoding="utf-8")
    (case_dir / "guard-exit-code.txt").write_text(
        f"{result.returncode}\n",
        encoding="utf-8",
    )
    return result.returncode


def _finalize(
    runtime: Runtime,
    case_dir: Path,
    stage: dict[str, str],
) -> dict[str, Any]:
    stage["value"] = "attempt_close"
    _control(runtime, "POST", f"/attempts/{runtime.attempt_id}/close")
    _run("docker", "stop", "-t", "2", runtime.candidate, check=False)

    stage["value"] = "final_snapshot_export"
    snapshot = _control(runtime, "POST", f"/attempts/{runtime.attempt_id}/final-snapshot")
    (case_dir / "final-snapshot.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    stage["value"] = "finalization"
    _control(runtime, "POST", f"/attempts/{runtime.attempt_id}/finalize")
    stage["value"] = "complete"
    return snapshot


def _assert_control_unreachable(runtime: Runtime) -> None:
    code = (
        "import socket; "
        "\ntry:\n"
        " socket.create_connection(('fixture-control',9000),timeout=0.8).close(); print('reachable'); raise SystemExit(1)\n"
        "except OSError:\n"
        " print('blocked'); raise SystemExit(0)\n"
    )
    result = _run(
        "docker",
        "exec",
        runtime.candidate,
        "python",
        "-c",
        code,
        check=False,
    )
    if result.returncode != 0:
        raise IsolationError(f"{runtime.label}: candidate reached trusted control plane")


def _wait_background(runtime: Runtime, *, started_only: bool = False) -> dict[str, Any]:
    deadline = time.monotonic() + 15
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = _candidate_http(runtime, "GET", "/phase2/state")
        raw_state = response.get("json")
        if isinstance(raw_state, dict):
            latest = {str(key): value for key, value in raw_state.items()}
        else:
            latest = {}
        if started_only and latest.get("background_started") is True:
            return latest
        if not started_only and latest.get("background_done") is True:
            return latest
        time.sleep(0.1)
    raise IsolationError(f"{runtime.label}: candidate background state timeout: {latest!r}")


def _case_startup(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
    before_cleanup_capture: CleanupCapture | None = None,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="startup",
        mode="startup-write",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
        output=output,
    )
    case_dir = output / "startup"
    stage = {"value": "case_execution"}
    try:
        _assert_control_unreachable(runtime)
        guard_exit = _run_guard(runtime, case_dir)
        snapshot = _finalize(runtime, case_dir, stage)
        if len(snapshot.get("audit", [])) < 1:
            raise IsolationError("startup: whole-attempt audit missed startup write")
        return {
            "guard_exit_code": guard_exit,
            "audit_count": len(snapshot["audit"]),
            "expected_gate_effect": "BLOCK",
            "control_unreachable": True,
        }
    finally:
        _cleanup(
            runtime,
            case_dir,
            fixture_image=fixture_image,
            evaluator_image=evaluator_image,
            preserve_on_failure=sys.exc_info()[0] is not None,
            failure_stage=(stage["value"] if sys.exc_info()[0] is not None else None),
            before_cleanup_capture=before_cleanup_capture,
        )


def _case_interprobe(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
    before_cleanup_capture: CleanupCapture | None = None,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="interprobe",
        mode="interprobe-write",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
        output=output,
    )
    case_dir = output / "interprobe"
    stage = {"value": "case_execution"}
    case_dir.mkdir(parents=True, exist_ok=True)
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            _guard_command(runtime),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        state = _wait_background(runtime, started_only=True)
        if int(state.get("reviewer_calls", 0)) < 1:
            raise IsolationError("interprobe: first reviewer call was not observed")
        released = _candidate_http(runtime, "POST", "/phase2/background/release")
        if released.get("status") != 200:
            raise IsolationError(f"interprobe: release endpoint failed: {released!r}")
        final_state = _wait_background(runtime)
        stdout, stderr = process.communicate(timeout=30)
        return_code = process.returncode
        if return_code is None:
            raise IsolationError("interprobe: Guard process has no return code after communicate")
        (case_dir / "guard-stdout.txt").write_text(stdout or "", encoding="utf-8")
        (case_dir / "guard-stderr.txt").write_text(stderr or "", encoding="utf-8")
        (case_dir / "guard-exit-code.txt").write_text(
            f"{return_code}\n",
            encoding="utf-8",
        )
        snapshot = _finalize(runtime, case_dir, stage)
        if len(snapshot.get("audit", [])) < 1:
            raise IsolationError("interprobe: whole-attempt audit missed inter-probe write")
        background_result = final_state.get("background_result")
        if not isinstance(background_result, dict) or background_result.get("status_code") != 200:
            raise IsolationError(
                f"interprobe: background writer did not commit successfully: {background_result!r}"
            )
        return {
            "guard_exit_code": return_code,
            "audit_count": len(snapshot["audit"]),
            "background_result": final_state.get("background_result"),
            "expected_gate_effect": "BLOCK",
        }
    finally:
        active_error = sys.exc_info()[1]
        process_cleanup_error: Exception | None = None
        if process is not None and process.poll() is None:
            try:
                process.kill()
                process.communicate(timeout=5)
            except Exception as exc:
                process_cleanup_error = exc
                with contextlib.suppress(Exception):
                    process.kill()
                    process.communicate(timeout=2)

        preserve_on_failure = active_error is not None or process_cleanup_error is not None
        cleanup_failure_stage: str | None = None
        if active_error is not None:
            cleanup_failure_stage = stage["value"]
        elif process_cleanup_error is not None:
            cleanup_failure_stage = "process_cleanup"

        _cleanup(
            runtime,
            case_dir,
            fixture_image=fixture_image,
            evaluator_image=evaluator_image,
            preserve_on_failure=preserve_on_failure,
            failure_stage=cleanup_failure_stage,
            before_cleanup_capture=before_cleanup_capture,
        )
        if active_error is None and process_cleanup_error is not None:
            raise process_cleanup_error


def _case_delayed(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
    before_cleanup_capture: CleanupCapture | None = None,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="delayed",
        mode="delayed-write",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
        output=output,
    )
    case_dir = output / "delayed"
    stage = {"value": "case_execution"}
    try:
        guard_exit = _run_guard(runtime, case_dir)
        state = _wait_background(runtime, started_only=True)
        if int(state.get("reviewer_calls", 0)) < 1:
            raise IsolationError("delayed: Guard never triggered the delayed writer")
        released = _candidate_http(runtime, "POST", "/phase2/background/release")
        if released.get("status") != 200:
            raise IsolationError(f"delayed: release endpoint failed: {released!r}")
        final_state = _wait_background(runtime)
        snapshot = _finalize(runtime, case_dir, stage)
        if len(snapshot.get("audit", [])) < 1:
            raise IsolationError("delayed: whole-attempt audit missed post-Guard pre-fence write")
        background_result = final_state.get("background_result")
        if not isinstance(background_result, dict) or background_result.get("status_code") != 200:
            raise IsolationError(
                f"delayed: background writer did not commit successfully: {background_result!r}"
            )
        return {
            "guard_exit_code": guard_exit,
            "audit_count": len(snapshot["audit"]),
            "background_result": final_state.get("background_result"),
            "expected_gate_effect": "BLOCK",
        }
    finally:
        _cleanup(
            runtime,
            case_dir,
            fixture_image=fixture_image,
            evaluator_image=evaluator_image,
            preserve_on_failure=sys.exc_info()[0] is not None,
            failure_stage=(stage["value"] if sys.exc_info()[0] is not None else None),
            before_cleanup_capture=before_cleanup_capture,
        )


def _case_crash(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
    before_cleanup_capture: CleanupCapture | None = None,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="crash",
        mode="crash",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
        output=output,
    )
    case_dir = output / "crash"
    try:
        guard_exit = _run_guard(runtime, case_dir)
        if guard_exit == 0:
            raise IsolationError("crash: candidate crash incorrectly produced Guard PASS")
        return {
            "guard_exit_code": guard_exit,
            "audit_count": 0,
            "expected_gate_effect": "INVALID",
            "final_snapshot_intentionally_absent": True,
        }
    finally:
        _cleanup(
            runtime,
            case_dir,
            fixture_image=fixture_image,
            evaluator_image=evaluator_image,
            preserve_on_failure=True,
            failure_stage="candidate_crash",
            before_cleanup_capture=before_cleanup_capture,
        )


def _case_recovery(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
    before_cleanup_capture: CleanupCapture | None = None,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="recovery",
        mode="good",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
        output=output,
    )
    case_dir = output / "recovery"
    stage = {"value": "case_execution"}
    case_dir.mkdir(parents=True, exist_ok=True)
    try:
        old_token = runtime.token
        _run("docker", "rm", "-f", runtime.app)
        _run("docker", "rm", "-f", runtime.control)

        common = _resource_args()
        _run(
            "docker",
            "run",
            "-d",
            "--name",
            runtime.app,
            "--network",
            runtime.net_ca,
            "--network-alias",
            "fixture-app",
            *common,
            "-v",
            f"{runtime.state_volume}:/state",
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
        _run(
            "docker",
            "run",
            "-d",
            "--name",
            runtime.control,
            "--network",
            runtime.net_ctrl,
            "--network-alias",
            "fixture-control",
            *common,
            "-v",
            f"{runtime.state_volume}:/state",
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
        _wait_exec(
            runtime.evaluator,
            "import urllib.request; urllib.request.urlopen('http://fixture-control:9000/health', timeout=1).read()",
        )
        _wait_exec(
            runtime.app,
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=1).read()",
        )

        snapshot = _control(runtime, "GET", f"/attempts/{runtime.attempt_id}")
        _write(case_dir / "recovery-required-state.json", snapshot)
        attempt = snapshot.get("attempt")
        if not isinstance(attempt, dict) or attempt.get("state") != "RECOVERY_REQUIRED":
            raise IsolationError(f"recovery: orphan did not become RECOVERY_REQUIRED: {snapshot!r}")

        auth_code = (
            "import json,urllib.request,urllib.error;"
            f"req=urllib.request.Request('http://fixture-app:8001/records/write',"
            "data=json.dumps({'record_id':'recovery-record','value':'x','request_id':'recovery-old-token-before-abort'}).encode(),"
            f"method='POST',headers={{'Content-Type':'application/json','Authorization':'Bearer {old_token}'}});"
            "\ntry:\n"
            " r=urllib.request.urlopen(req,timeout=2); print(r.status)\n"
            "except urllib.error.HTTPError as e:\n print(e.code)\n"
        )
        response = _run("docker", "exec", runtime.candidate, "python", "-c", auth_code)
        status_before_abort = int(response.stdout.strip().splitlines()[-1])
        if status_before_abort != 409:
            raise IsolationError(
                f"recovery: old token during RECOVERY_REQUIRED returned {status_before_abort}"
            )

        aborted = _control(
            runtime,
            "POST",
            f"/attempts/{runtime.attempt_id}/abort-recovery",
        )
        if aborted.get("state") != "ABORTED":
            raise IsolationError("recovery: trusted abort did not reach ABORTED")

        created = _control(
            runtime,
            "POST",
            "/attempts",
            {"attempt_id": f"{runtime.attempt_id}-new"},
        )
        new_attempt = str(created.get("attempt_id") or "")
        if not new_attempt:
            raise IsolationError("recovery: new attempt could not be created after trusted abort")
        runtime.cleanup_attempt_id = new_attempt
        _control(runtime, "POST", f"/attempts/{new_attempt}/open")

        response = _run("docker", "exec", runtime.candidate, "python", "-c", auth_code)
        status_after_new = int(response.stdout.strip().splitlines()[-1])
        if status_after_new != 401:
            raise IsolationError(
                f"recovery: stale old token returned {status_after_new} after new attempt"
            )

        stage["value"] = "attempt_close"
        _control(runtime, "POST", f"/attempts/{new_attempt}/close")
        stage["value"] = "final_snapshot_export"
        final = _control(runtime, "POST", f"/attempts/{new_attempt}/final-snapshot")
        _write(case_dir / "recovery-new-attempt-final-snapshot.json", final)
        if final.get("audit") != []:
            raise IsolationError("recovery: new attempt unexpectedly inherited old audit")
        stage["value"] = "finalization"
        _control(runtime, "POST", f"/attempts/{new_attempt}/finalize")
        stage["value"] = "case_execution"

        recovered = _control(runtime, "GET", f"/attempts/{runtime.attempt_id}")
        _write(case_dir / "recovery-aborted-state.json", recovered)
        attempt = recovered.get("attempt")
        requests = recovered.get("requests")
        if not isinstance(attempt, dict) or attempt.get("state") != "ABORTED":
            raise IsolationError("recovery: orphan state was not retained as ABORTED")
        if not isinstance(requests, list) or not any(
            isinstance(item, dict)
            and item.get("state") == "REJECTED"
            and item.get("rejection_reason") == "attempt_state=RECOVERY_REQUIRED"
            for item in requests
        ):
            raise IsolationError("recovery: rejected old-token attempt was not preserved")

        return {
            "orphan_state": "ABORTED",
            "pre_abort_old_token_status": status_before_abort,
            "post_new_attempt_old_token_status": status_after_new,
            "new_attempt_audit_count": 0,
            "new_attempt_id": new_attempt,
            "expected_gate_effect": "INVALID",
        }
    finally:
        _cleanup(
            runtime,
            case_dir,
            fixture_image=fixture_image,
            evaluator_image=evaluator_image,
            preserve_on_failure=sys.exc_info()[0] is not None,
            failure_stage=(stage["value"] if sys.exc_info()[0] is not None else None),
            before_cleanup_capture=before_cleanup_capture,
        )


def _capture_saved_run(runtime: Runtime, case_dir: Path) -> bool:
    code = (
        "from pathlib import Path; "
        "items=sorted({str(p.parent) for p in Path('/trusted-output/reports').glob('*/report.json')}); "
        "print('' if len(items)!=1 else items[0])"
    )
    result = _run(
        "docker",
        "exec",
        runtime.evaluator,
        "python",
        "-c",
        code,
        check=False,
    )
    if result.returncode != 0:
        return False
    remote_run = result.stdout.strip()
    if not remote_run:
        return False
    local_run = case_dir / "run"
    local_run.mkdir(parents=True, exist_ok=True)
    copied = _run(
        "docker",
        "cp",
        f"{runtime.evaluator}:{remote_run}/.",
        str(local_run),
        check=False,
    )
    return copied.returncode == 0


def _runtime_capture(runtime: Runtime, *, run_captured: bool) -> dict[str, Any]:
    return {
        "attempt_id": runtime.attempt_id,
        "credential_token_sha256": hashlib.sha256(runtime.token.encode("utf-8")).hexdigest(),
        "run_captured": run_captured,
        "physical_runtime": {
            "candidate_container": runtime.candidate,
            "fixture_app_container": runtime.app,
            "fixture_control_container": runtime.control,
            "evaluator_container": runtime.evaluator,
            "candidate_app_network": runtime.net_ca,
            "evaluator_candidate_network": runtime.net_ec,
            "evaluator_control_network": runtime.net_ctrl,
        },
    }


def _cleanup_complete(case_dir: Path) -> bool:
    path = case_dir / "cleanup.json"
    if not path.is_file():
        return False
    value = json.loads(path.read_text(encoding="utf-8"))
    return isinstance(value, dict) and value.get("cleanup_complete") is True


def _write_gate_context(
    *,
    case_dir: Path,
    metadata: dict[str, Any],
    candidate_mode: str,
    attempt_completion: str,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    gate_image: str,
    policy_digest: str,
    platform: str,
    guard_exit_code: int | None,
) -> dict[str, Any]:
    run_dir = case_dir / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path = run_dir / "report.json"
    receipt_path = run_dir / "receipt.json"
    inventory_path = run_dir / "tool-inventory.json"
    final_path = case_dir / "final-snapshot.json"

    report: dict[str, Any] = {}
    if report_path.is_file():
        value = json.loads(report_path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            report = value

    receipt: dict[str, Any] = {}
    if receipt_path.is_file():
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            receipt = value

    receipt_context = receipt.get("context")
    if not isinstance(receipt_context, dict):
        receipt_context = {}

    context = {
        "schema_version": 1,
        "policy_profile_digest": policy_digest,
        "attempt_id": metadata["attempt_id"],
        "guard_run_id": report.get("run_id"),
        "candidate_image": candidate_image,
        "candidate_mode": candidate_mode,
        "orchestrator_sha256": _sha(Path(__file__).resolve()),
        "evaluator_image": evaluator_image,
        "fixture_image": fixture_image,
        "gate_image": gate_image,
        "credential_principal": "candidate_app",
        "credential_token_sha256": metadata["credential_token_sha256"],
        "logical_candidate_origin": "http://candidate:7000",
        "logical_control_origin": "http://fixture-control:9000",
        "logical_fixture_app_origin": "http://fixture-app:8001",
        "report_json_sha256": _sha(report_path) if report_path.is_file() else None,
        "receipt_json_sha256": _sha(receipt_path) if receipt_path.is_file() else None,
        "tool_inventory_sha256": _sha(inventory_path) if inventory_path.is_file() else None,
        "final_snapshot_sha256": _sha(final_path) if final_path.is_file() else None,
        "subject_binding": "valid",
        "attempt_completion": attempt_completion,
        "cleanup_complete": _cleanup_complete(case_dir),
        "platform": platform,
        "physical_runtime": metadata["physical_runtime"],
        "guard_exit_code": guard_exit_code,
        "receipt_logical_target": receipt_context.get("logical_target"),
    }
    _write(case_dir / "execution-context.json", context)
    return context


def _run_reference(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="reference",
        mode="good",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
        output=output,
    )
    case_dir = output / "reference"
    stage = {"value": "case_execution"}
    result: dict[str, Any] = {}
    try:
        guard_exit = _run_guard(runtime, case_dir)
        if guard_exit != 0:
            raise IsolationError(f"reference: Guard exit was not zero: {guard_exit}")
        snapshot = _finalize(runtime, case_dir, stage)
        if snapshot.get("audit") != []:
            raise IsolationError("reference: trusted final audit was not clean")
        if not _capture_saved_run(runtime, case_dir):
            raise IsolationError("reference: trusted saved run could not be captured")
        result = {
            "guard_exit_code": guard_exit,
            "audit_count": 0,
            "candidate_mode": "good",
            "attempt_completion": "finalized",
            "gate_capture": _runtime_capture(runtime, run_captured=True),
        }
    finally:
        _cleanup(
            runtime,
            case_dir,
            fixture_image=fixture_image,
            evaluator_image=evaluator_image,
            preserve_on_failure=sys.exc_info()[0] is not None,
            failure_stage=stage["value"] if sys.exc_info()[0] is not None else None,
        )
    if not _cleanup_complete(case_dir):
        raise IsolationError("reference: cleanup did not complete")
    return result


def _run_case_with_capture(
    *,
    name: str,
    function: Any,
    candidate_mode: str,
    attempt_completion: str,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def capture(runtime: Runtime, case_dir: Path) -> None:
        run_captured = _capture_saved_run(runtime, case_dir)
        captured.update(_runtime_capture(runtime, run_captured=run_captured))

    result = function(
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
        output=output,
        before_cleanup_capture=capture,
    )

    if not captured:
        raise IsolationError(f"{name}: runtime capture did not execute")
    if name in {"startup", "interprobe", "delayed"} and not captured["run_captured"]:
        raise IsolationError(f"{name}: trusted saved run was not captured")
    case_dir = output / name
    if not _cleanup_complete(case_dir):
        raise IsolationError(f"{name}: cleanup did not complete")

    result["candidate_mode"] = candidate_mode
    result["attempt_completion"] = attempt_completion
    result["gate_capture"] = captured
    _write(case_dir / "case-result.json", result)
    return result


def _gate_case(
    *,
    name: str,
    expected_outcome: str,
    expected_mode: str,
    case_result: dict[str, Any],
    gate_image: str,
    policy_path: Path,
    evidence_root: Path,
    authority_volume: str,
    results_volume: str,
    approval_digest: str,
) -> str:
    capture = case_result.get("gate_capture")
    if not isinstance(capture, dict):
        raise IsolationError(f"{name}: gate capture metadata missing")
    attempt_id = capture.get("attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id:
        raise IsolationError(f"{name}: gate attempt_id missing")

    result = _gate_run(
        gate_image=gate_image,
        policy=policy_path,
        evidence_root=evidence_root,
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
            f"/evidence/evidence/{name}/run",
            "--candidate-context",
            f"/evidence/evidence/{name}/execution-context.json",
            "--candidate-final",
            f"/evidence/evidence/{name}/final-snapshot.json",
            "--expected-attempt-id",
            attempt_id,
            "--expected-candidate-image",
            str(case_result["candidate_image"]),
            "--expected-candidate-mode",
            expected_mode,
            "--selected-gate-image",
            gate_image,
            "--result-root",
            "/results",
            "--result-id",
            f"adversarial-{name}",
        ],
    )
    outcome = _read_gate_json(result, "outcome")
    if outcome != expected_outcome:
        raise IsolationError(f"{name}: expected actual gate {expected_outcome}, got {outcome}")
    return outcome


def _validate_published_results(output: Path, expected: dict[str, str]) -> dict[str, Any]:
    completed = output / "results" / "completed"
    actual_dirs = sorted(path.name for path in completed.iterdir() if path.is_dir())
    wanted_dirs = sorted(f"adversarial-{name}" for name in expected)
    if actual_dirs != wanted_dirs:
        raise IsolationError(
            f"published result set mismatch: actual={actual_dirs!r} expected={wanted_dirs!r}"
        )

    validation: dict[str, Any] = {}
    for name, expected_outcome in expected.items():
        bundle = completed / f"adversarial-{name}"
        decision_path = bundle / "decision.json"
        manifest_path = bundle / "manifest.json"
        if not decision_path.is_file() or not manifest_path.is_file():
            raise IsolationError(f"{name}: committed result bundle is incomplete")
        decision = json.loads(decision_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if decision.get("assessed_outcome") != expected_outcome:
            raise IsolationError(
                f"{name}: committed decision mismatch: {decision.get('assessed_outcome')!r}"
            )
        if decision.get("authority_binding") != "valid":
            raise IsolationError(f"{name}: authority binding is not valid")
        if decision.get("subject_binding") != "valid":
            raise IsolationError(f"{name}: subject binding is not valid")
        if decision.get("assessed_outcome") == "PASS":
            raise IsolationError(f"{name}: adversarial case committed stale PASS")

        if expected_outcome == "BLOCK" and not (bundle / "final-snapshot.json").is_file():
            raise IsolationError(f"{name}: BLOCK bundle lost final snapshot")
        if name in {"crash", "recovery"} and (bundle / "final-snapshot.json").exists():
            raise IsolationError(f"{name}: failure case fabricated a complete final snapshot")

        files = manifest.get("files")
        if not isinstance(files, dict):
            raise IsolationError(f"{name}: result manifest file map missing")
        for filename, expected_hash in files.items():
            path = bundle / filename
            if not path.is_file():
                raise IsolationError(f"{name}: manifest file missing: {filename}")
            if _sha(path) != expected_hash:
                raise IsolationError(f"{name}: manifest hash mismatch: {filename}")

        source_validation = decision.get("source_validation")
        if not isinstance(source_validation, dict):
            raise IsolationError(f"{name}: per-source validation status missing")
        if expected_outcome == "BLOCK":
            violations = decision.get("confirmed_violations")
            if not isinstance(violations, list) or not violations:
                raise IsolationError(f"{name}: BLOCK has no confirmed violation")
        else:
            if decision.get("evidence_completeness") != "invalid":
                raise IsolationError(f"{name}: INVALID lacks incomplete/invalid evidence status")

        validation[name] = {
            "outcome": decision.get("assessed_outcome"),
            "authority_binding": decision.get("authority_binding"),
            "subject_binding": decision.get("subject_binding"),
            "evidence_completeness": decision.get("evidence_completeness"),
            "confirmed_violation_count": len(decision.get("confirmed_violations") or []),
            "source_validation": source_validation,
        }
    return validation


def _copy_gate_volume_best_effort(
    *,
    gate_image: str,
    volume: str,
    mount: str,
    destination: Path,
) -> str | None:
    try:
        _copy_volume(gate_image, volume, mount, destination)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-profile", type=Path, required=True)
    parser.add_argument("--fixture-profile", type=Path, required=True)
    parser.add_argument("--evaluator-image", required=True)
    parser.add_argument("--fixture-image", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--gate-dir", type=Path, required=True)
    parser.add_argument("--gate-image", required=True)
    parser.add_argument("--guard-wheel-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    evidence = args.output / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(args.runtime_profile.read_text(encoding="utf-8"))
    platform, decision_scope = _selected_platform_scope(runtime)
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
        platform=platform,
        decision_scope=decision_scope,
        evaluator_image=args.evaluator_image,
        fixture_image=args.fixture_image,
        gate_image=args.gate_image,
        guard_wheel_sha=args.guard_wheel_sha,
    )

    reference = _run_reference(
        evaluator_image=args.evaluator_image,
        fixture_image=args.fixture_image,
        candidate_image=args.candidate_image,
        contract=args.contract,
        output=evidence,
    )
    reference_capture = reference["gate_capture"]
    _write_gate_context(
        case_dir=evidence / "reference",
        metadata=reference_capture,
        candidate_mode="good",
        attempt_completion="finalized",
        evaluator_image=args.evaluator_image,
        fixture_image=args.fixture_image,
        candidate_image=args.candidate_image,
        gate_image=args.gate_image,
        policy_digest=policy_digest,
        platform=platform,
        guard_exit_code=int(reference["guard_exit_code"]),
    )

    authority_volume = f"p2r3-authority-{uuid.uuid4().hex[:10]}"
    results_volume = f"p2r3-results-{uuid.uuid4().hex[:10]}"
    gate_plans = _gate_volume_plans(
        authority_volume=authority_volume,
        results_volume=results_volume,
        output=args.output,
    )
    try:
        _prepare_gate_volumes(args.gate_image, gate_plans)
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

        cases: dict[str, dict[str, Any]] = {}
        specs = (
            ("startup", _case_startup, "startup-write", "finalized", "BLOCK"),
            ("interprobe", _case_interprobe, "interprobe-write", "finalized", "BLOCK"),
            ("delayed", _case_delayed, "delayed-write", "finalized", "BLOCK"),
            ("crash", _case_crash, "crash", "candidate_crash_incomplete", "INVALID"),
            ("recovery", _case_recovery, "good", "recovery_aborted", "INVALID"),
        )
        actual_outcomes: dict[str, str] = {}
        for name, function, mode, completion, expected_outcome in specs:
            result = _run_case_with_capture(
                name=name,
                function=function,
                candidate_mode=mode,
                attempt_completion=completion,
                evaluator_image=args.evaluator_image,
                fixture_image=args.fixture_image,
                candidate_image=args.candidate_image,
                contract=args.contract,
                output=evidence,
            )
            result["candidate_image"] = args.candidate_image
            _write(evidence / name / "case-result.json", result)
            guard_exit = result.get("guard_exit_code")
            guard_exit_value = int(guard_exit) if isinstance(guard_exit, int) else None
            _write_gate_context(
                case_dir=evidence / name,
                metadata=result["gate_capture"],
                candidate_mode=mode,
                attempt_completion=completion,
                evaluator_image=args.evaluator_image,
                fixture_image=args.fixture_image,
                candidate_image=args.candidate_image,
                gate_image=args.gate_image,
                policy_digest=policy_digest,
                platform=platform,
                guard_exit_code=guard_exit_value,
            )
            outcome = _gate_case(
                name=name,
                expected_outcome=expected_outcome,
                expected_mode=mode,
                case_result=result,
                gate_image=args.gate_image,
                policy_path=policy_path,
                evidence_root=args.output,
                authority_volume=authority_volume,
                results_volume=results_volume,
                approval_digest=approval_digest,
            )
            result["actual_gate_outcome"] = outcome
            _write(evidence / name / "case-result.json", result)
            cases[name] = result
            actual_outcomes[name] = outcome

        _copy_volume(
            args.gate_image,
            authority_volume,
            "/authority",
            args.output / "authority",
        )
        _copy_volume(
            args.gate_image,
            results_volume,
            "/results",
            args.output / "results",
        )

        expected_outcomes = {
            "startup": "BLOCK",
            "interprobe": "BLOCK",
            "delayed": "BLOCK",
            "crash": "INVALID",
            "recovery": "INVALID",
        }
        published_validation = _validate_published_results(args.output, expected_outcomes)
        summary = {
            "schema_version": 2,
            "scope": (
                "phase2c_r3_adversarial_gate_bridge_local_arm64"
                if platform == "linux/arm64"
                else "phase2c_trusted_ci_adversarial_gate_amd64"
            ),
            "decision_scope": decision_scope,
            "platform": platform,
            "images": {
                "evaluator": args.evaluator_image,
                "fixture": args.fixture_image,
                "candidate": args.candidate_image,
                "gate": args.gate_image,
            },
            "policy_profile_digest": policy_digest,
            "approval_bundle_digest": approval_digest,
            "reference_attempt_id": reference_capture["attempt_id"],
            "cases": cases,
            "actual_outcomes": actual_outcomes,
            "published_validation": published_validation,
            "gate_invoked": True,
            "note": (
                "Selected Phase 2B.5 lifecycle cases were composed with the corrected "
                "trusted gate and committed result publication. Crash/recovery failure "
                "contexts remain intentionally incomplete and never fabricate final evidence."
            ),
        }
        _write(args.output / "adversarial-summary.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
    finally:
        active_error = sys.exc_info()[1]
        gate_cleanup = _cleanup_gate_volumes(
            gate_image=args.gate_image,
            plans=gate_plans,
            output=args.output,
        )
        if active_error is None and not gate_cleanup["cleanup_complete"]:
            raise IsolationError(
                f"gate resource cleanup incomplete; finish-only recovery required: {gate_cleanup!r}"
            )


if __name__ == "__main__":
    main()
