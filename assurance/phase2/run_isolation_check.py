from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import selectors
import signal
import socketserver
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any


class IsolationError(RuntimeError):
    pass


_COMMAND_TIMEOUT_SECONDS = 120.0
_CAPTURE_LIMIT_BYTES = 128 * 1024
_OUTPUT_BUDGET_BYTES = 1024 * 1024
_PIPE_READ_CHUNK_BYTES = 64 * 1024
_PROCESS_POLL_INTERVAL_SECONDS = 0.05
_PIPE_DRAIN_GRACE_SECONDS = 0.5
_REDACTION_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)([^\s'\"]+)"),
    re.compile(
        r"(?i)([\"']?(?:PHASE2_)?(?:ATTEMPT_)?(?:TOKEN|SECRET|PASSWORD|CREDENTIAL)[\"']?\s*[=:]\s*[\"']?)([^\"'\s,}]+)"
    ),
)


def _decode_capture(data: bytes, limit: int) -> str:
    truncated = len(data) > limit
    value = data[:limit].decode("utf-8", errors="replace")
    if truncated:
        value += f"\n[truncated after {limit} bytes]"
    return value


def _terminate_process_group(process: subprocess.Popen[bytes], grace: float = 2.0) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=grace)
    # Kill the whole process group even if the parent exited during the grace period.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _secret_values(args: tuple[str, ...]) -> tuple[str, ...]:
    values: set[str] = set()
    for arg in args:
        for pattern in _REDACTION_PATTERNS:
            for match in pattern.finditer(arg):
                value = match.group(2)
                if len(value) >= 6:
                    values.add(value)
    return tuple(sorted(values, key=len, reverse=True))


def _redact(value: str, args: tuple[str, ...]) -> str:
    redacted = value
    for secret in _secret_values(args):
        redacted = redacted.replace(secret, "[REDACTED]")
    for pattern in _REDACTION_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


def _capture_process_output(
    process: subprocess.Popen[bytes],
    *,
    timeout: float,
    capture_limit: int,
    output_budget: int,
) -> tuple[int, bytes, bytes, bool, bool, int]:
    if process.stdout is None or process.stderr is None:
        raise IsolationError("command output pipes were not created")

    stdout_capture = bytearray()
    stderr_capture = bytearray()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    os.set_blocking(stdout_fd, False)
    os.set_blocking(stderr_fd, False)

    selector = selectors.DefaultSelector()
    selector.register(stdout_fd, selectors.EVENT_READ, stdout_capture)
    selector.register(stderr_fd, selectors.EVENT_READ, stderr_capture)
    open_fds = {stdout_fd, stderr_fd}
    deadline = time.monotonic() + timeout
    drain_deadline: float | None = None
    forced_descendant_cleanup = False
    timed_out = False
    budget_exceeded = False
    emitted_bytes = 0
    returncode: int | None = None

    try:
        while open_fds or returncode is None:
            now = time.monotonic()
            if returncode is None:
                returncode = process.poll()

            if returncode is None and not budget_exceeded and not timed_out and now >= deadline:
                timed_out = True
                _terminate_process_group(process)
                returncode = process.poll()
                if returncode is None:
                    raise IsolationError("command process did not terminate after timeout")
                drain_deadline = time.monotonic() + _PIPE_DRAIN_GRACE_SECONDS

            if returncode is not None and open_fds and drain_deadline is None:
                drain_deadline = now + _PIPE_DRAIN_GRACE_SECONDS

            if not open_fds:
                if returncode is not None:
                    break
                time.sleep(_PROCESS_POLL_INTERVAL_SECONDS)
                continue

            wait_for = _PROCESS_POLL_INTERVAL_SECONDS
            if returncode is None and not budget_exceeded and not timed_out:
                wait_for = min(wait_for, max(0.0, deadline - now))
            if drain_deadline is not None:
                wait_for = min(wait_for, max(0.0, drain_deadline - now))

            events = selector.select(wait_for)
            for key, _mask in events:
                fd = int(key.fd)
                try:
                    chunk = os.read(fd, _PIPE_READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    with contextlib.suppress(Exception):
                        selector.unregister(fd)
                    open_fds.discard(fd)
                    continue

                emitted_bytes += len(chunk)
                capture = key.data
                if not isinstance(capture, bytearray):
                    raise IsolationError("command output capture state is invalid")
                remaining = capture_limit + 1 - len(capture)
                if remaining > 0:
                    capture.extend(chunk[:remaining])

                if emitted_bytes > output_budget and not budget_exceeded:
                    budget_exceeded = True
                    _terminate_process_group(process)
                    returncode = process.poll()
                    if returncode is None:
                        raise IsolationError(
                            "command process did not terminate after output budget breach"
                        )
                    drain_deadline = time.monotonic() + _PIPE_DRAIN_GRACE_SECONDS

            if open_fds and drain_deadline is not None and time.monotonic() >= drain_deadline:
                if budget_exceeded or timed_out:
                    for fd in tuple(open_fds):
                        with contextlib.suppress(Exception):
                            selector.unregister(fd)
                    open_fds.clear()
                    break
                if not forced_descendant_cleanup:
                    _terminate_process_group(process)
                    forced_descendant_cleanup = True
                    drain_deadline = time.monotonic() + _PIPE_DRAIN_GRACE_SECONDS
                else:
                    for fd in tuple(open_fds):
                        with contextlib.suppress(Exception):
                            selector.unregister(fd)
                    open_fds.clear()
                    break
    finally:
        selector.close()

    if returncode is None:
        raise IsolationError("command return code unavailable after output drain")
    return (
        returncode,
        bytes(stdout_capture),
        bytes(stderr_capture),
        timed_out,
        budget_exceeded,
        emitted_bytes,
    )


def _run(
    *args: str,
    check: bool = True,
    timeout: float = _COMMAND_TIMEOUT_SECONDS,
    capture_limit: int = _CAPTURE_LIMIT_BYTES,
    output_budget: int = _OUTPUT_BUDGET_BYTES,
) -> subprocess.CompletedProcess[str]:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if capture_limit <= 0:
        raise ValueError("capture_limit must be positive")
    if output_budget <= 0:
        raise ValueError("output_budget must be positive")

    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        (
            returncode,
            stdout_bytes,
            stderr_bytes,
            timed_out,
            budget_exceeded,
            emitted_bytes,
        ) = _capture_process_output(
            process,
            timeout=timeout,
            capture_limit=capture_limit,
            output_budget=output_budget,
        )
    except BaseException as exc:
        primary_tb = exc.__traceback__
        try:
            _terminate_process_group(process)
        except Exception as termination_exc:
            raise exc.with_traceback(primary_tb) from termination_exc
        raise
    finally:
        if process.stdout is not None:
            with contextlib.suppress(Exception):
                process.stdout.close()
        if process.stderr is not None:
            with contextlib.suppress(Exception):
                process.stderr.close()

    stdout = _decode_capture(stdout_bytes, capture_limit)
    stderr = _decode_capture(stderr_bytes, capture_limit)
    result = subprocess.CompletedProcess(args, returncode, stdout, stderr)
    safe_command = _redact(" ".join(args), args)
    safe_stdout = _redact(stdout, args)
    safe_stderr = _redact(stderr, args)

    if budget_exceeded:
        raise IsolationError(
            "resource_limit=output_budget_exceeded "
            f"budget={output_budget} emitted_at_least={emitted_bytes}: {safe_command}\n"
            f"stdout={safe_stdout}\nstderr={safe_stderr}"
        )
    if timed_out:
        raise IsolationError(
            f"command timed out after {timeout:.1f}s: {safe_command}\n"
            f"stdout={safe_stdout}\nstderr={safe_stderr}"
        )
    if check and result.returncode != 0:
        raise IsolationError(
            f"command failed ({result.returncode}): {safe_command}\n"
            f"stdout={safe_stdout}\nstderr={safe_stderr}"
        )
    return result


def _json_run(*args: str) -> Any:
    result = _run(*args)
    return json.loads(result.stdout)


def _container_ip(name: str, network: str) -> str:
    data = _json_run("docker", "inspect", name)[0]
    return str(data["NetworkSettings"]["Networks"][network]["IPAddress"])


def _wait_exec(name: str, code: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        result = _run("docker", "exec", name, "python", "-c", code, check=False)
        if result.returncode == 0:
            return
        last = result.stderr or result.stdout
        time.sleep(0.2)
    raise IsolationError(f"service did not become reachable from {name}: {last}")


class _Sentinel(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(b"phase2-host-sentinel")


def _resource_args() -> list[str]:
    return [
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "64",
        "--memory",
        "256m",
        "--cpus",
        "0.50",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
    ]


def _image_ref(images: dict[str, Any], key: str) -> str:
    identity = images.get(key)
    if not isinstance(identity, dict):
        raise IsolationError(f"missing image identity: {key}")
    execution_ref = identity.get("execution_ref")
    if isinstance(execution_ref, str) and execution_ref:
        return execution_ref
    legacy = identity.get("oci_index_digest")
    if isinstance(legacy, str) and legacy:
        return legacy
    raise IsolationError(f"image identity has no executable reference: {key}")


def _inspect_security(name: str) -> dict[str, Any]:
    data = _json_run("docker", "inspect", name)[0]
    host = data["HostConfig"]
    return {
        "user": data["Config"].get("User"),
        "readonly_rootfs": host.get("ReadonlyRootfs"),
        "cap_drop": host.get("CapDrop") or [],
        "security_opt": host.get("SecurityOpt") or [],
        "pids_limit": host.get("PidsLimit"),
        "memory": host.get("Memory"),
        "nano_cpus": host.get("NanoCpus"),
        "privileged": host.get("Privileged"),
        "network_mode": host.get("NetworkMode"),
        "pid_mode": host.get("PidMode"),
        "ipc_mode": host.get("IpcMode"),
        "devices": host.get("Devices") or [],
        "port_bindings": host.get("PortBindings"),
        "mounts": data.get("Mounts") or [],
        "networks": sorted((data["NetworkSettings"].get("Networks") or {}).keys()),
    }


def _assert_security(
    name: str,
    expected_networks: list[str],
    *,
    expected_uid: int,
    candidate: bool = False,
) -> dict[str, Any]:
    info = _inspect_security(name)
    uid_result = _run("docker", "exec", name, "python", "-c", "import os;print(os.getuid())")
    actual_uid = int(uid_result.stdout.strip())
    info["runtime_uid"] = actual_uid
    if actual_uid != expected_uid:
        raise IsolationError(f"{name}: unexpected runtime uid {actual_uid!r}")
    if info["readonly_rootfs"] is not True:
        raise IsolationError(f"{name}: rootfs is not read-only")
    if "ALL" not in info["cap_drop"]:
        raise IsolationError(f"{name}: capabilities were not fully dropped")
    if not any("no-new-privileges" in item for item in info["security_opt"]):
        raise IsolationError(f"{name}: no-new-privileges missing")
    if int(info["pids_limit"] or 0) != 64:
        raise IsolationError(f"{name}: unexpected pids limit {info['pids_limit']!r}")
    if int(info["memory"] or 0) != 268435456:
        raise IsolationError(f"{name}: unexpected memory limit {info['memory']!r}")
    if int(info["nano_cpus"] or 0) != 500000000:
        raise IsolationError(f"{name}: unexpected CPU limit {info['nano_cpus']!r}")
    if info["privileged"] is not False:
        raise IsolationError(f"{name}: privileged mode unexpectedly enabled")
    if info["network_mode"] == "host":
        raise IsolationError(f"{name}: host network namespace unexpectedly enabled")
    if info["pid_mode"] == "host":
        raise IsolationError(f"{name}: host PID namespace unexpectedly enabled")
    if info["ipc_mode"] == "host":
        raise IsolationError(f"{name}: host IPC namespace unexpectedly enabled")
    if info["devices"]:
        raise IsolationError(f"{name}: device mappings unexpectedly present: {info['devices']!r}")
    if info["port_bindings"] not in (None, {}):
        raise IsolationError(f"{name}: host ports unexpectedly published")
    if sorted(info["networks"]) != sorted(expected_networks):
        raise IsolationError(f"{name}: unexpected networks {info['networks']!r}")
    if candidate:
        disallowed = [m for m in info["mounts"] if m.get("Type") != "tmpfs"]
        if disallowed:
            raise IsolationError(
                f"candidate unexpectedly has persistent/host mounts: {disallowed!r}"
            )
    return info


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    images = profile["images"]
    suffix = uuid.uuid4().hex[:10]
    net_ca = f"p2b2-ca-{suffix}"
    net_ec = f"p2b2-ec-{suffix}"
    net_ctrl = f"p2b2-ctrl-{suffix}"
    candidate = f"p2b2-candidate-{suffix}"
    app = f"p2b2-app-{suffix}"
    control = f"p2b2-control-{suffix}"
    evaluator = f"p2b2-evaluator-{suffix}"
    positive = f"p2b2-positive-{suffix}"
    state_volume = f"p2b2-state-{suffix}"
    output_volume = f"p2b2-output-{suffix}"
    created_containers: list[str] = []
    created_networks: list[str] = []
    created_volumes: list[str] = []
    result: dict[str, Any] = {"cleanup_complete": False}

    sentinel = socketserver.ThreadingTCPServer(("0.0.0.0", 0), _Sentinel)
    sentinel_thread = threading.Thread(target=sentinel.serve_forever, daemon=True)
    sentinel_thread.start()
    host_port = int(sentinel.server_address[1])

    with tempfile.TemporaryDirectory(prefix="phase2-trusted-output-") as out_dir:
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
                candidate,
                "--network",
                net_ca,
                *common,
                _image_ref(images, "candidate_probe"),
                "server",
                "--port",
                "7000",
            )
            created_containers.append(candidate)
            _run("docker", "network", "connect", net_ec, candidate)

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
                _image_ref(images, "fixture"),
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
                _image_ref(images, "fixture"),
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
                "--entrypoint",
                "python",
                _image_ref(images, "evaluator"),
                "-c",
                "import time; time.sleep(120)",
            )
            created_containers.append(evaluator)
            _run("docker", "network", "connect", net_ctrl, evaluator)

            # Wait for intended paths from the exact actors that should have access.
            _wait_exec(
                candidate,
                "import urllib.request; urllib.request.urlopen('http://fixture-app:8001/health', timeout=1).read()".replace(
                    "fixture-app", app
                ),
            )
            _wait_exec(
                evaluator,
                "import urllib.request; urllib.request.urlopen('http://candidate:7000/health', timeout=1).read()".replace(
                    "candidate", candidate
                ),
            )
            _wait_exec(
                evaluator,
                "import urllib.request; urllib.request.urlopen('http://fixture-control:9000/health', timeout=1).read()".replace(
                    "fixture-control", control
                ),
            )

            # A separate trusted positive-control actor intentionally reaches both
            # fixture planes. This proves that "no candidate write" is not a
            # vacuous result caused by a dead or unreachable fixture.
            _run(
                "docker",
                "run",
                "-d",
                "--name",
                positive,
                "--network",
                net_ca,
                *common,
                "--entrypoint",
                "python",
                _image_ref(images, "evaluator"),
                "-c",
                "import time; time.sleep(120)",
            )
            created_containers.append(positive)
            _run("docker", "network", "connect", net_ctrl, positive)

            positive_code = f"""
import json
import urllib.request


def call(method, url, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    combined = {{"Content-Type": "application/json"}}
    combined.update(headers or {{}})
    request = urllib.request.Request(url, data=data, headers=combined, method=method)
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


created = call("POST", "http://{control}:9000/attempts", {{"attempt_id": "p2-positive-{suffix}"}})
attempt_id = created["attempt_id"]
token = created["token"]
call("POST", f"http://{control}:9000/attempts/{{attempt_id}}/open")
write = call(
    "POST",
    "http://{app}:8001/records/write",
    {{
        "record_id": "p2-positive-record",
        "value": "p2-positive-value",
        "request_id": "p2-positive-request",
    }},
    {{"Authorization": f"Bearer {{token}}"}},
)
snapshot = call("GET", f"http://{control}:9000/attempts/{{attempt_id}}")
call("POST", f"http://{control}:9000/attempts/{{attempt_id}}/close")
final = call("POST", f"http://{control}:9000/attempts/{{attempt_id}}/final-snapshot")
call("POST", f"http://{control}:9000/attempts/{{attempt_id}}/finalize")
audit = [row for row in snapshot["audit"] if row.get("operation") == "record_write"]
requests = [row for row in snapshot["requests"] if row.get("request_id") == "p2-positive-request"]
print(json.dumps(
    {{
        "write_state": write["state"],
        "committed": write["committed"],
        "audit_count": len(audit),
        "request_state": requests[0]["state"] if len(requests) == 1 else "INVALID",
        "final_audit_complete": final["audit_complete"],
    }},
    sort_keys=True,
))
"""
            positive_result = json.loads(
                _run("docker", "exec", positive, "python", "-c", positive_code).stdout
            )
            expected_positive = {
                "write_state": "COMMITTED",
                "committed": True,
                "audit_count": 1,
                "request_state": "COMMITTED",
                "final_audit_complete": True,
            }
            if positive_result != expected_positive:
                raise IsolationError(
                    f"positive control differs: expected={expected_positive!r} "
                    f"actual={positive_result!r}"
                )

            control_ip = _container_ip(control, net_ctrl)
            app_ip = _container_ip(app, net_ca)

            probe = _run(
                "docker",
                "exec",
                candidate,
                "python",
                "/candidate/probe.py",
                "checks",
                "--app-host",
                app,
                "--app-port",
                "8001",
                "--control-host",
                control,
                "--control-ip",
                control_ip,
                "--control-port",
                "9000",
                "--host-port",
                str(host_port),
            )
            candidate_checks = json.loads(probe.stdout)
            expected_candidate = {
                "uid": 10002,
                "app_http_ok": True,
                "control_hostname_tcp": False,
                "control_ip_tcp": False,
                "internet_tcp": False,
                "host_service_tcp": False,
                "docker_socket_exists": False,
                "rootfs_write_blocked": True,
                "tmp_writable": True,
                "trusted_output_visible": False,
            }
            if candidate_checks != expected_candidate:
                raise IsolationError(
                    f"candidate isolation checks differ\nexpected={expected_candidate!r}\nactual={candidate_checks!r}"
                )

            # Evaluator can reach candidate and control, but not the fixture application network.
            eval_code = f"""
import json
import pathlib
import socket
import urllib.request


def tcp(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return True
    except OSError:
        return False


ok1 = urllib.request.urlopen("http://{candidate}:7000/health", timeout=1).status == 200
ok2 = urllib.request.urlopen("http://{control}:9000/health", timeout=1).status == 200
payload = {{
    "candidate": ok1,
    "control": ok2,
    "app_direct": tcp("{app_ip}", 8001),
    "internet_tcp": tcp("1.1.1.1", 443),
    "host_service_tcp": tcp("host.docker.internal", {host_port}),
}}
p = pathlib.Path("/trusted-output/evaluator-proof.json")
p.write_text(json.dumps(payload), encoding="utf-8")
print(p.read_text(encoding="utf-8"))
"""
            eval_result = _run("docker", "exec", evaluator, "python", "-c", eval_code)
            evaluator_checks = json.loads(eval_result.stdout)
            if evaluator_checks != {
                "candidate": True,
                "control": True,
                "app_direct": False,
                "internet_tcp": False,
                "host_service_tcp": False,
            }:
                raise IsolationError(f"evaluator reachability differs: {evaluator_checks!r}")
            proof_path = Path(out_dir) / "evaluator-proof.json"
            _run(
                "docker", "cp", f"{evaluator}:/trusted-output/evaluator-proof.json", str(proof_path)
            )
            if not proof_path.is_file():
                raise IsolationError(
                    "trusted evaluator output was not recoverable from evaluator-only output volume"
                )

            security = {
                candidate: _assert_security(
                    candidate, [net_ca, net_ec], expected_uid=10002, candidate=True
                ),
                app: _assert_security(app, [net_ca], expected_uid=10001),
                control: _assert_security(control, [net_ctrl], expected_uid=10001),
                evaluator: _assert_security(evaluator, [net_ctrl, net_ec], expected_uid=10003),
                positive: _assert_security(positive, [net_ca, net_ctrl], expected_uid=10003),
            }

            # Network objects themselves must be internal with isolated IPv4 gateway mode.
            network_inspect: dict[str, Any] = {}
            for network in (net_ca, net_ec, net_ctrl):
                data = _json_run("docker", "network", "inspect", network)[0]
                if data.get("Internal") is not True:
                    raise IsolationError(f"network {network} is not internal")
                options = data.get("Options") or {}
                if options.get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated":
                    raise IsolationError(f"network {network} lacks isolated IPv4 gateway mode")
                network_inspect[network] = {
                    "internal": data.get("Internal"),
                    "driver": data.get("Driver"),
                    "options": options,
                }

            result.update(
                {
                    "status": "passed",
                    "candidate_checks": candidate_checks,
                    "evaluator_checks": evaluator_checks,
                    "positive_control": positive_result,
                    "security": security,
                    "networks": network_inspect,
                    "host_sentinel_port": host_port,
                    "trusted_output_proof": json.loads(proof_path.read_text(encoding="utf-8")),
                }
            )
        finally:
            sentinel.shutdown()
            sentinel.server_close()
            sentinel_thread.join(timeout=2)
            cleanup_errors: list[str] = []
            for name in reversed(created_containers):
                res = _run("docker", "rm", "-f", name, check=False)
                if res.returncode != 0:
                    cleanup_errors.append(f"container {name}: {res.stderr.strip()}")
            for name in reversed(created_networks):
                res = _run("docker", "network", "rm", name, check=False)
                if res.returncode != 0:
                    cleanup_errors.append(f"network {name}: {res.stderr.strip()}")
            for name in reversed(created_volumes):
                res = _run("docker", "volume", "rm", name, check=False)
                if res.returncode != 0:
                    cleanup_errors.append(f"volume {name}: {res.stderr.strip()}")

            # Authoritative readback: successful remove commands are not enough by themselves.
            for name in created_containers:
                if _run("docker", "container", "inspect", name, check=False).returncode == 0:
                    cleanup_errors.append(f"container {name}: still present after removal")
            for name in created_networks:
                if _run("docker", "network", "inspect", name, check=False).returncode == 0:
                    cleanup_errors.append(f"network {name}: still present after removal")
            for name in created_volumes:
                if _run("docker", "volume", "inspect", name, check=False).returncode == 0:
                    cleanup_errors.append(f"volume {name}: still present after removal")
            result["cleanup_errors"] = cleanup_errors
            result["cleanup_complete"] = not cleanup_errors
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            if cleanup_errors:
                raise IsolationError("runtime cleanup failed: " + "; ".join(cleanup_errors))


if __name__ == "__main__":
    main()
