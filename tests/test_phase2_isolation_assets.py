from __future__ import annotations

import ast
import json
import re
from pathlib import Path

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
