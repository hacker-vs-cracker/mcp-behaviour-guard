from __future__ import annotations

import argparse
import json
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


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise IsolationError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
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
                images["candidate_probe"]["oci_index_digest"],
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
                images["fixture"]["oci_index_digest"],
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
                images["fixture"]["oci_index_digest"],
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
                images["evaluator"]["oci_index_digest"],
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
