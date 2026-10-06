from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PHASE2 = PROJECT_ROOT / "assurance/phase2"
PROFILE = PHASE2 / "runtime-profile.json"
REQ = PHASE2 / "evaluator/requirements.lock"
EVAL_DOCKERFILE = PHASE2 / "evaluator/Dockerfile"
CANDIDATE_DOCKERFILE = PHASE2 / "candidate-probe/Dockerfile"
PROBE = PHASE2 / "candidate-probe/probe.py"
ISOLATION = PHASE2 / "run_isolation_check.py"
GUARD_WHEEL_SHA = "d27b68638f7896999e22e0a74b0a82cb16c47994e9b98b7940eb9aa7eb9818af"


def test_runtime_profile_binds_arm64_base_guard_and_built_images() -> None:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    assert profile["schema_version"] == 1
    assert profile["platform"] == "linux/arm64"
    assert profile["base_image"]["reference"] == "python:3.11.14-slim"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", profile["base_image"]["platform_manifest_digest"])
    assert profile["guard"]["version"] == "0.6.2"
    assert profile["guard"]["wheel_sha256"] == GUARD_WHEEL_SHA
    assert profile["phase2b_profile_status"] == "closed-local-candidate"
    assert profile["fixture_profile"]["profile_id"] == "phase2-fixture-v2"
    for key in ("evaluator", "fixture", "candidate_probe", "vertical_candidate", "gate"):
        image = profile["images"][key]
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", image["oci_index_digest"])
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", image["platform_manifest_digest"])
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", image["config_digest"])
        assert image["os"] == "linux"
        assert image["architecture"] == "arm64"
    assert profile["closure_scope"] == {
        "phase2c_trusted_ci": False,
        "reference_gate": "local-only",
        "release_changed": False,
        "remote_branch_published": False,
    }


def test_evaluator_dependency_install_is_offline_hash_locked_and_not_built_from_repository_source() -> (
    None
):
    dockerfile = EVAL_DOCKERFILE.read_text(encoding="utf-8")
    assert "ARG BASE_IMAGE" in dockerfile
    assert "ARG BASE_IMAGE=" not in dockerfile
    assert "COPY --from=wheelhouse" in dockerfile
    assert "--no-index" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "--only-binary=:all:" in dockerfile
    assert "COPY src" not in dockerfile
    assert "git clone" not in dockerfile
    assert "apt-get" not in dockerfile
    assert "curl " not in dockerfile
    assert "USER evaluator" in dockerfile


def test_requirements_lock_is_exact_and_contains_verified_guard_wheel() -> None:
    lines = [line.strip() for line in REQ.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    assert all("==" in line and " --hash=sha256:" in line for line in lines)
    guard = [line for line in lines if line.startswith("mcp-behaviour-guard==0.6.2 ")]
    assert guard == [f"mcp-behaviour-guard==0.6.2 --hash=sha256:{GUARD_WHEEL_SHA}"]
    names = [line.split("==", 1)[0] for line in lines]
    assert names == sorted(names)
    assert len(names) == len(set(names))


def test_candidate_probe_build_recipe_has_no_dependency_or_privileged_escape_hooks() -> None:
    dockerfile = CANDIDATE_DOCKERFILE.read_text(encoding="utf-8")
    assert "ARG BASE_IMAGE" in dockerfile
    assert "ARG BASE_IMAGE=" not in dockerfile
    assert "COPY probe.py" in dockerfile
    assert "pip install" not in dockerfile
    assert "apt-get" not in dockerfile
    assert "--mount=" not in dockerfile
    assert "USER candidate" in dockerfile
    source = PROBE.read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "/var/run/docker.sock" in source


def test_isolation_runner_requires_internal_isolated_gateway_and_resource_controls() -> None:
    source = ISOLATION.read_text(encoding="utf-8")
    for value in (
        "--internal",
        "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        "--read-only",
        "--cap-drop",
        "no-new-privileges:true",
        "--pids-limit",
        "--memory",
        "--cpus",
    ):
        assert value in source
    tree = ast.parse(source)
    initial_networks: set[str] = set()
    connected_networks: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "_run":
            continue
        args = node.args
        constants = [item.value if isinstance(item, ast.Constant) else None for item in args]
        if len(args) >= 2 and constants[:2] == ["docker", "run"]:
            for index, item in enumerate(args[:-1]):
                if isinstance(item, ast.Constant) and item.value == "--network":
                    next_item = args[index + 1]
                    if isinstance(next_item, ast.Name):
                        initial_networks.add(next_item.id)
        if len(args) >= 4 and constants[:3] == ["docker", "network", "connect"]:
            network_arg = args[3]
            if isinstance(network_arg, ast.Name):
                connected_networks.add(network_arg.id)
    assert {"net_ca", "net_ctrl"} <= initial_networks
    assert {"net_ec", "net_ctrl"} <= connected_networks
    for value in (
        '"Privileged"',
        '"PidMode"',
        '"IpcMode"',
        '"Devices"',
        '"runtime_uid"',
        '"container", "inspect"',
        '"network", "inspect"',
        '"volume", "inspect"',
    ):
        assert value in source


def _isolation_module():
    spec = importlib.util.spec_from_file_location("phase2_isolation_p1a_test", ISOLATION)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load run_isolation_check.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_shared_runner_times_out_and_terminates_subprocess() -> None:
    module = _isolation_module()
    try:
        module._run(sys.executable, "-c", "import time; time.sleep(5)", timeout=0.05)
    except module.IsolationError as exc:
        assert "timed out" in str(exc)
    else:
        raise AssertionError("expected bounded subprocess timeout")


def test_shared_runner_redacts_sensitive_arguments_and_output() -> None:
    module = _isolation_module()
    secret = "phase2-realistic-secret-value"
    try:
        module._run(
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1], file=sys.stderr); raise SystemExit(7)",
            f"PHASE2_ATTEMPT_TOKEN={secret}",
        )
    except module.IsolationError as exc:
        message = str(exc)
        assert secret not in message
        assert "[REDACTED]" in message
    else:
        raise AssertionError("expected command failure")

    json_message = module._redact('{"token":"' + secret + '"}', ())
    assert secret not in json_message
    assert "[REDACTED]" in json_message


def test_shared_runner_bounds_success_capture() -> None:
    module = _isolation_module()
    result = module._run(
        sys.executable,
        "-c",
        "print('x' * 20000)",
        capture_limit=1024,
    )
    assert "[truncated after 1024 bytes]" in result.stdout
    assert len(result.stdout) < 1200


def test_shared_runner_uses_bounded_pipes_instead_of_tempfile_spool() -> None:
    source = ISOLATION.read_text(encoding="utf-8")
    start = source.index("def _capture_process_output(")
    end = source.index("\ndef _json_run", start)
    runner = source[start:end]
    assert "tempfile.TemporaryFile" not in runner
    assert "stdout=subprocess.PIPE" in runner
    assert "stderr=subprocess.PIPE" in runner
    assert "resource_limit=output_budget_exceeded" in runner


def test_shared_runner_enforces_finite_stdout_output_budget() -> None:
    module = _isolation_module()
    with pytest.raises(module.IsolationError, match="resource_limit=output_budget_exceeded") as exc:
        module._run(
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('x' * 200000); sys.stdout.flush()",
            capture_limit=256,
            output_budget=4096,
        )
    message = str(exc.value)
    assert "[truncated after 256 bytes]" in message
    assert len(message) < 1600


def test_shared_runner_enforces_finite_stderr_output_budget() -> None:
    module = _isolation_module()
    with pytest.raises(module.IsolationError, match="resource_limit=output_budget_exceeded") as exc:
        module._run(
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('y' * 200000); sys.stderr.flush()",
            capture_limit=256,
            output_budget=4096,
        )
    message = str(exc.value)
    assert "[truncated after 256 bytes]" in message
    assert len(message) < 1600


def test_shared_runner_handles_simultaneous_stdout_stderr_pressure() -> None:
    module = _isolation_module()
    code = "\n".join(
        [
            "import sys",
            "for _ in range(256):",
            "    sys.stdout.write('o' * 512)",
            "    sys.stdout.flush()",
            "    sys.stderr.write('e' * 512)",
            "    sys.stderr.flush()",
        ]
    )
    with pytest.raises(module.IsolationError, match="resource_limit=output_budget_exceeded"):
        module._run(
            sys.executable,
            "-c",
            code,
            capture_limit=256,
            output_budget=8192,
            timeout=3.0,
        )


def test_shared_runner_budget_breach_terminates_descendant_process_group(tmp_path: Path) -> None:
    module = _isolation_module()
    marker = tmp_path / "descendant-survived"
    child = (
        "import pathlib,time;"
        "time.sleep(0.8);"
        f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
    )
    parent = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable, '-c', {child!r}]);"
        "sys.stdout.write('z' * 200000);"
        "sys.stdout.flush();"
        "time.sleep(5)"
    )
    started = time.monotonic()
    with pytest.raises(module.IsolationError, match="resource_limit=output_budget_exceeded"):
        module._run(
            sys.executable,
            "-c",
            parent,
            capture_limit=256,
            output_budget=4096,
            timeout=4.0,
        )
    assert time.monotonic() - started < 3.0
    time.sleep(1.0)
    assert not marker.exists()


def test_shared_runner_terminates_process_group_on_base_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _isolation_module()
    signals: list[tuple[int, int]] = []

    class FakeStream:
        def close(self) -> None:
            return None

    class FakeProcess:
        pid = 4242

        def __init__(self) -> None:
            self.returncode: int | None = None
            self.stdout = FakeStream()
            self.stderr = FakeStream()

        def wait(self, timeout: float | None = None) -> int:
            self.returncode = -15
            return self.returncode

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    def interrupt(*_args: object, **_kwargs: object) -> object:
        raise KeyboardInterrupt()

    fake = FakeProcess()
    monkeypatch.setattr(module.subprocess, "Popen", lambda *_args, **_kwargs: fake)
    monkeypatch.setattr(module, "_capture_process_output", interrupt)
    monkeypatch.setattr(module.os, "killpg", lambda pid, sig: signals.append((pid, sig)))

    with pytest.raises(KeyboardInterrupt):
        module._run("synthetic-command")

    assert (fake.pid, module.signal.SIGTERM) in signals
    assert (fake.pid, module.signal.SIGKILL) in signals
