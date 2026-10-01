from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import yaml

from mcp_behaviour_guard import run_contract
from mcp_behaviour_guard.client import McpClient, _matches_denial_marker
from mcp_behaviour_guard.config import load_contract
from mcp_behaviour_guard.models import FindingStatus, ObservationStatus

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_CANONICAL = PROJECT_ROOT / "contracts/examples/local-coding-assistant.yaml"
TENANT_CANONICAL = PROJECT_ROOT / "contracts/examples/tenant-isolation.yaml"
FIXTURE = PROJECT_ROOT / "tests/fixtures/canonical_examples_mcp_server.py"

SECRET = "synthetic-guard-demo-secret-value"
TENANT_B_CANARY = "SYNTHETIC_TENANT_B_PRIVATE_CANARY"


def _read_yaml(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def _write_yaml(path: Path, raw: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def _local_test_contract(
    tmp_path: Path,
    *,
    path_mode: str = "deny",
    diagnostics_mode: str = "safe",
) -> Path:
    raw = _read_yaml(LOCAL_CANONICAL)
    server = raw["server"]
    server["command"] = sys.executable
    server["args"] = [str(FIXTURE)]
    server["cwd"] = str(PROJECT_ROOT)
    environment = dict(server.get("environment", {}))
    environment.update(
        {
            "GUARD_FIXTURE_TRANSPORT": "stdio",
            "GUARD_FIXTURE_STDIO_PATH_MODE": path_mode,
            "GUARD_FIXTURE_STDIO_DIAGNOSTICS_MODE": diagnostics_mode,
        }
    )
    server["environment"] = environment

    _assert_only_local_target_coordinates_changed(raw)
    path = tmp_path / f"local-{path_mode}-{diagnostics_mode}.yaml"
    _write_yaml(path, raw)
    return path


def _tenant_test_contract(tmp_path: Path, url: str, mode: str) -> Path:
    raw = _read_yaml(TENANT_CANONICAL)
    raw["server"]["url"] = url
    _assert_only_tenant_target_coordinates_changed(raw)
    path = tmp_path / f"tenant-{mode}.yaml"
    _write_yaml(path, raw)
    return path


def _assert_only_local_target_coordinates_changed(candidate: dict[str, Any]) -> None:
    expected = _read_yaml(LOCAL_CANONICAL)
    normalized = _read_yaml(LOCAL_CANONICAL)
    normalized["server"] = dict(candidate["server"])

    for name in ("command", "args", "cwd"):
        normalized["server"][name] = expected["server"][name]

    environment = dict(normalized["server"].get("environment", {}))
    for name in (
        "GUARD_FIXTURE_TRANSPORT",
        "GUARD_FIXTURE_STDIO_PATH_MODE",
        "GUARD_FIXTURE_STDIO_DIAGNOSTICS_MODE",
    ):
        environment.pop(name, None)
    normalized["server"]["environment"] = environment
    assert normalized == expected


def _assert_only_tenant_target_coordinates_changed(candidate: dict[str, Any]) -> None:
    expected = _read_yaml(TENANT_CANONICAL)
    normalized = _read_yaml(TENANT_CANONICAL)
    normalized["server"] = dict(candidate["server"])
    normalized["server"]["url"] = expected["server"]["url"]
    assert normalized == expected


def _finding(result: Any, test_id: str) -> Any:
    return next(item for item in result.summary.findings if item.test_id == test_id)


def _exported_text(run_dir: Path) -> str:
    values: list[str] = []
    for path in sorted(item for item in run_dir.rglob("*") if item.is_file()):
        try:
            values.append(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            continue
    return "\n".join(values)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"HTTP fixture exited before startup with code {process.returncode}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError("HTTP fixture did not become ready before timeout")


@contextmanager
def _http_fixture(mode: str) -> Iterator[str]:
    port = _free_port()
    env = dict(os.environ)
    env.update(
        {
            "GUARD_FIXTURE_TRANSPORT": "http",
            "GUARD_FIXTURE_HOST": "127.0.0.1",
            "GUARD_FIXTURE_PORT": str(port),
            "GUARD_FIXTURE_TENANT_MODE": mode,
        }
    )
    process = subprocess.Popen(
        [sys.executable, str(FIXTURE)],
        cwd=PROJECT_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(port, process)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def test_tenant_example_uses_same_identity_positive_and_negative_controls() -> None:
    contract = load_contract(TENANT_CANONICAL)
    tool = contract.tools["customer_lookup"]

    assert tool.permitted_identities == ["tenant_a_agent"]
    assert tool.probe_arguments["customer_id"] == "tenant-a-synthetic-001"
    assert tool.denial_error_markers == ["GUARD_DEMO_DENIED"]

    probe = tool.tenant_probes["tenant_a_agent"]
    assert probe.require_denial is True
    assert probe.expected_tenant == "tenant-a"
    assert probe.arguments["customer_id"] == "tenant-b-synthetic-001"
    assert probe.confidentiality is not None

    assert (
        probe.confidentiality.match_count(
            {"tenant": "tenant-a", "result": "safe synthetic response"}
        )
        == 0
    )
    assert (
        probe.confidentiality.match_count(
            {
                "tenant": "tenant-b",
                "result": TENANT_B_CANARY,
            }
        )
        == 1
    )


def test_tenant_example_uses_explicit_synthetic_denial_marker() -> None:
    contract = load_contract(TENANT_CANONICAL)
    markers = contract.tools["customer_lookup"].denial_error_markers

    assert _matches_denial_marker(
        {"error": "GUARD_DEMO_DENIED: cross-tenant access"},
        markers,
    )
    assert not _matches_denial_marker({"error": "validation failed"}, markers)


def test_local_example_uses_explicit_nonproduction_secret_canary() -> None:
    contract = load_contract(LOCAL_CANONICAL)
    value = contract.server.environment["GUARD_DEMO_SECRET"]

    assert value == SECRET

    diagnostics = contract.tools["diagnostics"]
    env_check = diagnostics.policy_probes[0].checks[0]
    assert env_check.type == "response_not_contains_env"
    assert env_check.env_names == ["GUARD_DEMO_SECRET"]


def test_local_example_denial_is_not_a_generic_error_convention() -> None:
    contract = load_contract(LOCAL_CANONICAL)
    markers = contract.tools["repo_read"].denial_error_markers

    assert markers == ["GUARD_DEMO_DENIED"]
    assert _matches_denial_marker(
        {"error": "GUARD_DEMO_DENIED: path outside workspace"},
        markers,
    )
    assert not _matches_denial_marker({"error": "file not found"}, markers)


@pytest.mark.asyncio
async def test_local_fixture_child_receives_secret_without_echoing_it(tmp_path: Path) -> None:
    contract_path = _local_test_contract(tmp_path)
    contract = load_contract(contract_path)
    identity = contract.identities["developer_agent"]
    client = McpClient(contract.server, "developer_agent", identity)

    invocation = await client.invoke(
        "FIXTURE-SECRET-PRESENCE",
        "diagnostics",
        {},
        denial_error_markers=[],
    )

    assert invocation.allowed is True
    assert invocation.response["secret_present"] is True
    assert SECRET not in json.dumps(invocation.response, sort_keys=True)


@pytest.mark.asyncio
async def test_local_canonical_controls_run_through_real_client_and_engine(tmp_path: Path) -> None:
    result = await run_contract(
        _local_test_contract(tmp_path),
        output=tmp_path / "reports",
        database=tmp_path / "guard.db",
    )

    assert _finding(result, "AUTH-REPO-READ-DEVELOPER-AGENT").status == FindingStatus.PASSED
    assert _finding(result, "AUTH-DIAGNOSTICS-DEVELOPER-AGENT").status == FindingStatus.PASSED
    assert _finding(result, "DEV-PATH-ESCAPE-001").status == FindingStatus.PASSED
    assert _finding(result, "DEV-ENV-LEAK-001").status == FindingStatus.PASSED

    repo_observation = _finding(result, "BEHAVIOUR-REPO-READ")
    diagnostics_observation = _finding(result, "BEHAVIOUR-DIAGNOSTICS")
    assert repo_observation.status == FindingStatus.ERROR
    assert diagnostics_observation.status == FindingStatus.ERROR
    assert repo_observation.observation == ObservationStatus.UNAVAILABLE
    assert diagnostics_observation.observation == ObservationStatus.UNAVAILABLE
    assert result.summary.assessment.value == "inconclusive"


@pytest.mark.asyncio
async def test_local_generic_error_does_not_count_as_denial(tmp_path: Path) -> None:
    result = await run_contract(
        _local_test_contract(tmp_path, path_mode="generic"),
        output=tmp_path / "reports",
        database=tmp_path / "guard.db",
    )

    finding = _finding(result, "DEV-PATH-ESCAPE-001")
    assert finding.status == FindingStatus.ERROR


@pytest.mark.asyncio
async def test_local_deliberate_secret_disclosure_fails_and_is_redacted(
    tmp_path: Path,
) -> None:
    result = await run_contract(
        _local_test_contract(tmp_path, diagnostics_mode="leak"),
        output=tmp_path / "reports",
        database=tmp_path / "guard.db",
    )

    finding = _finding(result, "DEV-ENV-LEAK-001")
    assert finding.status == FindingStatus.FAILED
    assert SECRET not in _exported_text(result.run_dir)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "expected_status"),
    [
        ("deny", FindingStatus.PASSED),
        ("generic", FindingStatus.ERROR),
        ("leak", FindingStatus.FAILED),
    ],
)
async def test_tenant_canonical_control_real_transport_outcomes(
    tmp_path: Path,
    mode: str,
    expected_status: FindingStatus,
) -> None:
    with _http_fixture(mode) as url:
        result = await run_contract(
            _tenant_test_contract(tmp_path, url, mode),
            output=tmp_path / f"reports-{mode}",
            database=tmp_path / f"guard-{mode}.db",
        )

    assert _finding(result, "AUTH-CUSTOMER-LOOKUP-TENANT-A-AGENT").status == FindingStatus.PASSED
    tenant_finding = _finding(result, "TENANT-CUSTOMER-LOOKUP-TENANT-A-AGENT")
    assert tenant_finding.status == expected_status

    behavior = _finding(result, "BEHAVIOUR-CUSTOMER-LOOKUP")
    assert behavior.status == FindingStatus.ERROR
    assert behavior.observation == ObservationStatus.UNAVAILABLE

    if mode == "leak":
        assert tenant_finding.observed["confidentiality_assertion"] == "failed"
        assert TENANT_B_CANARY not in _exported_text(result.run_dir)
