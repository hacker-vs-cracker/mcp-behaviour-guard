from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    token: str
    containers: list[str]
    networks: list[str]
    volumes: list[str]


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


def _start_runtime(
    *,
    label: str,
    mode: str,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
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
        token="",
        containers=[],
        networks=[],
        volumes=[],
    )
    common = _resource_args()

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
        runtime.networks.append(network)
    for volume in (runtime.state_volume, runtime.output_volume):
        _run("docker", "volume", "create", volume)
        runtime.volumes.append(volume)

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
    runtime.containers.append(runtime.app)

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
    runtime.containers.append(runtime.control)

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
    runtime.containers.append(runtime.evaluator)
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
    runtime.containers.append(runtime.candidate)
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
    return runtime


def _cleanup(runtime: Runtime, output: Path) -> None:
    errors: list[str] = []
    for name in reversed(runtime.containers):
        result = _run("docker", "rm", "-f", name, check=False)
        if result.returncode != 0 and "No such container" not in result.stderr:
            errors.append(f"container {name}: {result.stderr.strip()}")
    for name in reversed(runtime.networks):
        result = _run("docker", "network", "rm", name, check=False)
        if result.returncode != 0:
            errors.append(f"network {name}: {result.stderr.strip()}")
    for name in reversed(runtime.volumes):
        result = _run("docker", "volume", "rm", name, check=False)
        if result.returncode != 0:
            errors.append(f"volume {name}: {result.stderr.strip()}")

    for name in runtime.containers:
        if _run("docker", "container", "inspect", name, check=False).returncode == 0:
            errors.append(f"container still present: {name}")
    for name in runtime.networks:
        if _run("docker", "network", "inspect", name, check=False).returncode == 0:
            errors.append(f"network still present: {name}")
    for name in runtime.volumes:
        if _run("docker", "volume", "inspect", name, check=False).returncode == 0:
            errors.append(f"volume still present: {name}")

    output.mkdir(parents=True, exist_ok=True)
    (output / "cleanup.json").write_text(
        json.dumps(
            {"cleanup_complete": not errors, "cleanup_errors": errors},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if errors:
        raise IsolationError(f"{runtime.label}: cleanup errors: {errors}")


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


def _finalize(runtime: Runtime, case_dir: Path) -> dict[str, Any]:
    _control(runtime, "POST", f"/attempts/{runtime.attempt_id}/close")
    _run("docker", "stop", "-t", "2", runtime.candidate, check=False)
    snapshot = _control(runtime, "POST", f"/attempts/{runtime.attempt_id}/final-snapshot")
    (case_dir / "final-snapshot.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _control(runtime, "POST", f"/attempts/{runtime.attempt_id}/finalize")
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
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="startup",
        mode="startup-write",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
    )
    case_dir = output / "startup"
    try:
        _assert_control_unreachable(runtime)
        guard_exit = _run_guard(runtime, case_dir)
        snapshot = _finalize(runtime, case_dir)
        if len(snapshot.get("audit", [])) < 1:
            raise IsolationError("startup: whole-attempt audit missed startup write")
        return {
            "guard_exit_code": guard_exit,
            "audit_count": len(snapshot["audit"]),
            "expected_gate_effect": "BLOCK",
            "control_unreachable": True,
        }
    finally:
        _cleanup(runtime, case_dir)


def _case_interprobe(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="interprobe",
        mode="interprobe-write",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
    )
    case_dir = output / "interprobe"
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
        snapshot = _finalize(runtime, case_dir)
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
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        _cleanup(runtime, case_dir)


def _case_delayed(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="delayed",
        mode="delayed-write",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
    )
    case_dir = output / "delayed"
    try:
        guard_exit = _run_guard(runtime, case_dir)
        state = _wait_background(runtime, started_only=True)
        if int(state.get("reviewer_calls", 0)) < 1:
            raise IsolationError("delayed: Guard never triggered the delayed writer")
        released = _candidate_http(runtime, "POST", "/phase2/background/release")
        if released.get("status") != 200:
            raise IsolationError(f"delayed: release endpoint failed: {released!r}")
        final_state = _wait_background(runtime)
        snapshot = _finalize(runtime, case_dir)
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
        _cleanup(runtime, case_dir)


def _case_crash(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="crash",
        mode="crash",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
    )
    case_dir = output / "crash"
    try:
        guard_exit = _run_guard(runtime, case_dir)
        if guard_exit == 0:
            raise IsolationError("crash: candidate crash incorrectly produced Guard PASS")
        snapshot = _finalize(runtime, case_dir)
        if snapshot.get("audit") != []:
            raise IsolationError("crash: unexpected committed database write")
        return {
            "guard_exit_code": guard_exit,
            "audit_count": 0,
            "expected_gate_effect": "INVALID",
        }
    finally:
        _cleanup(runtime, case_dir)


def _case_recovery(
    *,
    evaluator_image: str,
    fixture_image: str,
    candidate_image: str,
    contract: Path,
    output: Path,
) -> dict[str, Any]:
    runtime = _start_runtime(
        label="recovery",
        mode="good",
        evaluator_image=evaluator_image,
        fixture_image=fixture_image,
        candidate_image=candidate_image,
        contract=contract,
    )
    case_dir = output / "recovery"
    case_dir.mkdir(parents=True, exist_ok=True)
    try:
        old_token = runtime.token
        _run("docker", "rm", "-f", runtime.app)
        _run("docker", "rm", "-f", runtime.control)
        runtime.containers = [
            item for item in runtime.containers if item not in {runtime.app, runtime.control}
        ]

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
        runtime.containers.append(runtime.app)
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
        runtime.containers.append(runtime.control)
        _wait_exec(
            runtime.evaluator,
            "import urllib.request; urllib.request.urlopen('http://fixture-control:9000/health', timeout=1).read()",
        )
        _wait_exec(
            runtime.app,
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=1).read()",
        )

        snapshot = _control(runtime, "GET", f"/attempts/{runtime.attempt_id}")
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
        _control(runtime, "POST", f"/attempts/{new_attempt}/open")

        response = _run("docker", "exec", runtime.candidate, "python", "-c", auth_code)
        status_after_new = int(response.stdout.strip().splitlines()[-1])
        if status_after_new != 401:
            raise IsolationError(
                f"recovery: stale old token returned {status_after_new} after new attempt"
            )

        _control(runtime, "POST", f"/attempts/{new_attempt}/close")
        final = _control(runtime, "POST", f"/attempts/{new_attempt}/final-snapshot")
        if final.get("audit") != []:
            raise IsolationError("recovery: new attempt unexpectedly inherited old audit")
        _control(runtime, "POST", f"/attempts/{new_attempt}/finalize")

        recovered = _control(runtime, "GET", f"/attempts/{runtime.attempt_id}")
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
            "expected_gate_effect": "INVALID",
        }
    finally:
        _cleanup(runtime, case_dir)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evaluator-image", required=True)
    parser.add_argument("--fixture-image", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {}
    functions = (
        ("startup", _case_startup),
        ("interprobe", _case_interprobe),
        ("delayed", _case_delayed),
        ("crash", _case_crash),
        ("recovery", _case_recovery),
    )
    for name, function in functions:
        results[name] = function(
            evaluator_image=args.evaluator_image,
            fixture_image=args.fixture_image,
            candidate_image=args.candidate_image,
            contract=args.contract,
            output=args.output,
        )

    summary = {
        "schema_version": 1,
        "scope": "phase2b5_adversarial_closure_only",
        "images": {
            "evaluator": args.evaluator_image,
            "fixture": args.fixture_image,
            "candidate": args.candidate_image,
        },
        "cases": results,
        "gate_invoked": False,
        "note": (
            "2B.4 gate precedence is reused; 2B.5 adds adversarial whole-attempt/recovery evidence."
        ),
    }
    (args.output / "adversarial-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
