from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mcp_behaviour_guard.client as client_module
from mcp_behaviour_guard.client import McpClient
from mcp_behaviour_guard.config import ContractError, validate_target
from mcp_behaviour_guard.models import Contract, IdentitySpec, ServerSpec


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _restricted_payload(
    *,
    command: str,
    cwd: Path | None,
    allowed_executables: list[str],
    allowed_cwd_roots: list[str],
    inherit_environment: list[str] | None = None,
    legacy_allowed_commands: list[str] | None = None,
) -> dict[str, Any]:
    server: dict[str, Any] = {
        "name": "restricted-stdio",
        "transport": "stdio",
        "command": command,
        "args": [],
        "environment": {"SERVER_EXPLICIT": "server-value"},
        "stdio_launch": {
            "mode": "restricted",
            "allowed_executables": allowed_executables,
            "allowed_cwd_roots": allowed_cwd_roots,
            "inherit_environment": inherit_environment or [],
        },
    }
    if cwd is not None:
        server["cwd"] = str(cwd)

    return {
        "version": 1,
        "server": server,
        "identities": {
            "reviewer": {
                "tenant": "tenant-a",
                "role": "reviewer",
                "environment": {"IDENTITY_EXPLICIT": "identity-value"},
            }
        },
        "tools": {
            "read": {
                "permitted_identities": ["reviewer"],
                "read_only": True,
            }
        },
        "safety": {
            # Legacy field remains present but must not authorize or deny the
            # restricted executable decision.
            "allowed_stdio_commands": (
                legacy_allowed_commands
                if legacy_allowed_commands is not None
                else [Path(command).name]
            ),
        },
    }


def test_restricted_stdio_launch_policy_is_additive_and_keeps_contract_v1(
    tmp_path: Path,
) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=tmp_path,
            allowed_executables=[str(executable)],
            allowed_cwd_roots=[str(tmp_path)],
            inherit_environment=["PATH"],
        )
    )

    assert contract.version == 1
    assert contract.server.stdio_launch.mode == "restricted"
    assert contract.server.stdio_launch.allowed_executables == [executable]
    assert contract.server.stdio_launch.allowed_cwd_roots == [tmp_path]
    assert contract.server.stdio_launch.inherit_environment == ["PATH"]


def test_legacy_stdio_contract_keeps_existing_allowlist_behavior(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "bin" / "legacy-runner")
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "legacy",
                "transport": "stdio",
                "command": str(executable),
                "cwd": str(tmp_path),
            },
            "identities": {"reviewer": {}},
            "tools": {
                "read": {
                    "permitted_identities": ["reviewer"],
                    "read_only": True,
                }
            },
            "safety": {
                "allowed_stdio_commands": [executable.name],
            },
        }
    )

    # This already passes before R10 and must continue to pass afterward.
    validate_target(contract, lab_mode=False)


def test_restricted_stdio_rejects_basename_only_executable_allowlist(
    tmp_path: Path,
) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=tmp_path,
            allowed_executables=[executable.name],
            allowed_cwd_roots=[str(tmp_path)],
        )
    )

    with pytest.raises(ContractError, match="absolute|executable"):
        validate_target(contract, lab_mode=False)


def test_restricted_stdio_rejects_same_basename_different_executable(
    tmp_path: Path,
) -> None:
    approved = _make_executable(tmp_path / "approved" / "runner")
    unapproved = _make_executable(tmp_path / "unapproved" / "runner")
    contract = Contract.model_validate(
        _restricted_payload(
            command=str(unapproved),
            cwd=tmp_path,
            allowed_executables=[str(approved)],
            allowed_cwd_roots=[str(tmp_path)],
        )
    )

    with pytest.raises(ContractError, match="executable|allow"):
        validate_target(contract, lab_mode=False)


def test_restricted_stdio_resolves_basename_to_approved_canonical_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _make_executable(tmp_path / "bin" / "r10-runner")
    monkeypatch.setenv("PATH", str(executable.parent))

    contract = Contract.model_validate(
        _restricted_payload(
            command=executable.name,
            cwd=tmp_path,
            allowed_executables=[str(executable)],
            allowed_cwd_roots=[str(tmp_path)],
        )
    )

    validate_target(contract, lab_mode=False)


@pytest.mark.parametrize("lab_mode", [False, True])
def test_restricted_stdio_rejects_cwd_outside_approved_root_even_in_lab_mode(
    tmp_path: Path,
    lab_mode: bool,
) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    approved_root = tmp_path / "approved"
    outside = tmp_path / "outside"
    approved_root.mkdir()
    outside.mkdir()

    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=outside,
            allowed_executables=[str(executable)],
            allowed_cwd_roots=[str(approved_root)],
        )
    )

    with pytest.raises(ContractError, match="cwd|working|root"):
        validate_target(contract, lab_mode=lab_mode)


def test_restricted_stdio_rejects_symlink_cwd_escape(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    approved_root = tmp_path / "approved"
    outside = tmp_path / "outside"
    approved_root.mkdir()
    outside.mkdir()
    link = approved_root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=link,
            allowed_executables=[str(executable)],
            allowed_cwd_roots=[str(approved_root)],
        )
    )

    with pytest.raises(ContractError, match="cwd|working|root"):
        validate_target(contract, lab_mode=False)


@pytest.mark.asyncio
async def test_restricted_stdio_launches_canonical_command_with_minimal_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    monkeypatch.setenv("R10_PARENT_SECRET", "must-not-reach-target")
    monkeypatch.setenv("R10_ALLOWED_PARENT", "allowed-parent-value")

    payload = _restricted_payload(
        command=str(executable),
        cwd=tmp_path,
        allowed_executables=[str(executable)],
        allowed_cwd_roots=[str(tmp_path)],
        inherit_environment=["R10_ALLOWED_PARENT"],
    )
    payload["server"]["environment"]["MCP_GUARD_IDENTITY"] = "spoofed-server"
    payload["identities"]["reviewer"]["environment"].update(
        {
            "MCP_GUARD_IDENTITY": "spoofed-identity",
            "MCP_GUARD_TENANT": "spoofed-tenant",
            "MCP_GUARD_ROLE": "spoofed-role",
        }
    )
    contract = Contract.model_validate(payload)
    validate_target(contract, lab_mode=False)

    captured: dict[str, Any] = {}

    @asynccontextmanager
    async def fake_stdio_client(parameters: Any) -> Any:
        captured["parameters"] = parameters
        yield object(), object()

    class DummySession:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs

        async def __aenter__(self) -> DummySession:
            return self

        async def __aexit__(self, *args: Any) -> None:
            del args

        async def initialize(self) -> Any:
            return SimpleNamespace(protocolVersion="test")

    monkeypatch.setattr(client_module, "stdio_client", fake_stdio_client)
    monkeypatch.setattr(client_module, "ClientSession", DummySession)

    identity = contract.identities["reviewer"]
    client = McpClient(contract.server, "reviewer", identity)

    async with client._stdio_session(None):
        pass

    parameters = captured["parameters"]
    assert Path(parameters.command).resolve() == executable.resolve()

    environment = parameters.env
    assert environment == {
        "R10_ALLOWED_PARENT": "allowed-parent-value",
        "SERVER_EXPLICIT": "server-value",
        "IDENTITY_EXPLICIT": "identity-value",
        "MCP_GUARD_IDENTITY": "reviewer",
        "MCP_GUARD_TENANT": "tenant-a",
        "MCP_GUARD_ROLE": "reviewer",
    }
    assert "R10_PARENT_SECRET" not in environment


def test_lab_mode_cannot_bypass_restricted_executable_identity(
    tmp_path: Path,
) -> None:
    approved = _make_executable(tmp_path / "approved" / "runner")
    unapproved = _make_executable(tmp_path / "unapproved" / "runner")

    contract = Contract.model_validate(
        _restricted_payload(
            command=str(unapproved),
            cwd=tmp_path,
            allowed_executables=[str(approved)],
            allowed_cwd_roots=[str(tmp_path)],
        )
    )

    with pytest.raises(ContractError, match="executable|allow"):
        validate_target(contract, lab_mode=True)


def test_restricted_stdio_does_not_require_legacy_basename_approval(
    tmp_path: Path,
) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=tmp_path,
            allowed_executables=[str(executable)],
            allowed_cwd_roots=[str(tmp_path)],
            legacy_allowed_commands=["not-the-runner"],
        )
    )
    validate_target(contract, lab_mode=False)


def test_stdio_launch_policy_is_rejected_for_http_transport(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    with pytest.raises(ValueError, match="stdio_launch.*stdio|stdio.*stdio_launch"):
        Contract.model_validate(
            {
                "version": 1,
                "server": {
                    "name": "http",
                    "transport": "streamable-http",
                    "url": "http://127.0.0.1:8000/mcp",
                    "stdio_launch": {
                        "mode": "restricted",
                        "allowed_executables": [str(executable)],
                        "allowed_cwd_roots": [str(tmp_path)],
                    },
                },
                "identities": {"reviewer": {}},
                "tools": {"read": {"permitted_identities": ["reviewer"], "read_only": True}},
            }
        )


def test_legacy_mode_rejects_restricted_only_settings(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    with pytest.raises(ValueError, match="legacy.*restricted|restricted.*legacy"):
        Contract.model_validate(
            {
                "version": 1,
                "server": {
                    "name": "stdio",
                    "transport": "stdio",
                    "command": str(executable),
                    "cwd": str(tmp_path),
                    "stdio_launch": {
                        "mode": "legacy",
                        "allowed_executables": [str(executable)],
                        "allowed_cwd_roots": [str(tmp_path)],
                    },
                },
                "identities": {"reviewer": {}},
                "tools": {"read": {"permitted_identities": ["reviewer"], "read_only": True}},
                "safety": {"allowed_stdio_commands": [executable.name]},
            }
        )


def test_restricted_stdio_rejects_relative_cwd_root(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=tmp_path,
            allowed_executables=[str(executable)],
            allowed_cwd_roots=["relative-root"],
        )
    )
    with pytest.raises(ContractError, match="absolute|root"):
        validate_target(contract, lab_mode=False)


def test_restricted_stdio_rejects_non_directory_cwd(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    cwd_file = tmp_path / "not-a-directory"
    cwd_file.write_text("file", encoding="utf-8")
    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=cwd_file,
            allowed_executables=[str(executable)],
            allowed_cwd_roots=[str(tmp_path)],
        )
    )
    with pytest.raises(ContractError, match="cwd|working.*directory|directory"):
        validate_target(contract, lab_mode=False)


@pytest.mark.asyncio
async def test_restricted_stdio_is_enforced_at_client_launch_without_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = _make_executable(tmp_path / "approved" / "runner")
    unapproved = _make_executable(tmp_path / "unapproved" / "runner")
    contract = Contract.model_validate(
        _restricted_payload(
            command=str(unapproved),
            cwd=tmp_path,
            allowed_executables=[str(approved)],
            allowed_cwd_roots=[str(tmp_path)],
        )
    )
    launched = False

    @asynccontextmanager
    async def forbidden_stdio_client(parameters: Any) -> Any:
        del parameters
        nonlocal launched
        launched = True
        yield object(), object()

    monkeypatch.setattr(client_module, "stdio_client", forbidden_stdio_client)
    client = McpClient(contract.server, "reviewer", contract.identities["reviewer"])
    with pytest.raises(ContractError, match="executable|allow"):
        async with client._stdio_session(None):
            pass
    assert not launched


def test_legacy_stdio_serialization_omits_absent_launch_policy() -> None:
    server = ServerSpec(
        name="legacy",
        transport="stdio",
        command="python",
    )
    assert "stdio_launch" not in server.model_dump(mode="json")

    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "legacy",
                "transport": "stdio",
                "command": "python",
            },
            "identities": {"reviewer": {}},
            "tools": {
                "read": {
                    "permitted_identities": ["reviewer"],
                    "read_only": True,
                }
            },
        }
    )
    assert "stdio_launch" not in contract.model_dump(mode="json")["server"]


def test_restricted_stdio_rejects_relative_cwd(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=Path("relative-cwd"),
            allowed_executables=[str(executable)],
            allowed_cwd_roots=[str(tmp_path)],
        )
    )

    with pytest.raises(ContractError, match="absolute|cwd|working"):
        validate_target(contract, lab_mode=False)


def test_restricted_stdio_rejects_noncanonical_allowed_executable(
    tmp_path: Path,
) -> None:
    executable = _make_executable(tmp_path / "real" / "runner")
    link = tmp_path / "bin" / "runner"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(executable)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    contract = Contract.model_validate(
        _restricted_payload(
            command=str(link),
            cwd=tmp_path,
            allowed_executables=[str(link)],
            allowed_cwd_roots=[str(tmp_path)],
        )
    )

    with pytest.raises(ContractError, match="canonical|executable|symlink"):
        validate_target(contract, lab_mode=False)


def test_restricted_stdio_rejects_noncanonical_cwd_root(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "bin" / "runner")
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    root_link = tmp_path / "root-link"
    try:
        root_link.symlink_to(real_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    contract = Contract.model_validate(
        _restricted_payload(
            command=str(executable),
            cwd=real_root,
            allowed_executables=[str(executable)],
            allowed_cwd_roots=[str(root_link)],
        )
    )

    with pytest.raises(ContractError, match="canonical|root|symlink"):
        validate_target(contract, lab_mode=False)


@pytest.mark.asyncio
async def test_restricted_stdio_real_mcp_launch_discovers_demo_tools(
    tmp_path: Path,
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    launch_executable = Path(sys.executable).absolute()
    approved_executable = launch_executable.resolve()

    server = ServerSpec.model_validate(
        {
            "name": "restricted-real-launch",
            "transport": "stdio",
            "command": str(launch_executable),
            "args": ["-m", "demo.stdio_server.app"],
            "cwd": str(project_root),
            "environment": {
                "DEMO_STDIO_ROOT": str(tmp_path / "stdio"),
                "DEMO_STDIO_AUDIT": str(tmp_path / "stdio" / "audit.jsonl"),
                "DEMO_AGENT_TOKEN": "test-token",
            },
            "stdio_launch": {
                "mode": "restricted",
                "allowed_executables": [str(approved_executable)],
                "allowed_cwd_roots": [str(project_root)],
                "inherit_environment": [],
            },
        }
    )

    tools = await McpClient(
        server,
        "local_developer",
        IdentitySpec(role="developer"),
    ).list_tools()

    assert {item["name"] for item in tools} >= {
        "workspace_read",
        "diagnostics",
        "run_project_task",
    }
