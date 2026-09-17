from __future__ import annotations

from mcp_behaviour_guard.engine import (
    _required_effect_kinds,
    _side_effect_violations,
)
from mcp_behaviour_guard.models import SideEffectKind, ToolContract
from mcp_behaviour_guard.observers.base import SideEffectEvent


def _event(kind: SideEffectKind, **details: str) -> SideEffectEvent:
    return SideEffectEvent(observer="test", kind=kind, details=details)


def test_omitted_allowlists_mean_no_claim() -> None:
    tool = ToolContract(permitted_identities=["user"])

    assert tool.allowed_network_destinations is None
    assert tool.allowed_filesystem_writes is None
    assert tool.allowed_process_commands is None
    assert _required_effect_kinds(tool) == set()


def test_explicit_null_allowlists_mean_no_claim() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_network_destinations=None,
        allowed_filesystem_writes=None,
        allowed_process_commands=None,
    )

    assert _required_effect_kinds(tool) == set()


def test_empty_network_allowlist_is_deny_all() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_network_destinations=[],
    )
    event = _event(
        SideEffectKind.NETWORK_REQUEST,
        destination="example.invalid:443",
    )

    assert SideEffectKind.NETWORK_REQUEST in _required_effect_kinds(tool)
    violations = _side_effect_violations(tool, [event])
    assert len(violations) == 1
    assert violations[0]["reason"] == "network destination is not allowlisted"


def test_empty_filesystem_allowlist_is_deny_all() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_filesystem_writes=[],
    )
    event = _event(
        SideEffectKind.FILESYSTEM_WRITE,
        path="/tmp/out.txt",
    )

    assert SideEffectKind.FILESYSTEM_WRITE in _required_effect_kinds(tool)
    violations = _side_effect_violations(tool, [event])
    assert len(violations) == 1
    assert violations[0]["reason"] == "filesystem path is not allowlisted"


def test_empty_process_allowlist_is_deny_all() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_process_commands=[],
    )
    event = _event(
        SideEffectKind.PROCESS_EXECUTION,
        command="python build.py",
    )

    assert SideEffectKind.PROCESS_EXECUTION in _required_effect_kinds(tool)
    violations = _side_effect_violations(tool, [event])
    assert len(violations) == 1
    assert violations[0]["reason"] == "process command is not allowlisted"


def test_non_empty_network_allowlist_requires_coverage_and_enforces_match() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_network_destinations=["*.internal.example:443"],
    )
    allowed = _event(
        SideEffectKind.NETWORK_REQUEST,
        destination="customer.internal.example:443",
    )
    denied = _event(
        SideEffectKind.NETWORK_REQUEST,
        destination="analytics.example.net:443",
    )

    assert SideEffectKind.NETWORK_REQUEST in _required_effect_kinds(tool)
    assert _side_effect_violations(tool, [allowed]) == []
    assert _side_effect_violations(tool, [denied])


def test_non_empty_filesystem_allowlist_requires_coverage_and_enforces_match() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_filesystem_writes=["/workspace/*"],
    )
    allowed = _event(
        SideEffectKind.FILESYSTEM_WRITE,
        path="/workspace/result.txt",
    )
    denied = _event(
        SideEffectKind.FILESYSTEM_WRITE,
        path="/tmp/result.txt",
    )

    assert SideEffectKind.FILESYSTEM_WRITE in _required_effect_kinds(tool)
    assert _side_effect_violations(tool, [allowed]) == []
    assert _side_effect_violations(tool, [denied])


def test_non_empty_process_allowlist_requires_coverage_and_enforces_match() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_process_commands=["python *"],
    )
    allowed = _event(
        SideEffectKind.PROCESS_EXECUTION,
        command="python build.py",
    )
    denied = _event(
        SideEffectKind.PROCESS_EXECUTION,
        command="bash deploy.sh",
    )

    assert SideEffectKind.PROCESS_EXECUTION in _required_effect_kinds(tool)
    assert _side_effect_violations(tool, [allowed]) == []
    assert _side_effect_violations(tool, [denied])


def test_explicit_forbidden_side_effect_overrides_allowlist() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_network_destinations=["*.internal.example:443"],
        forbidden_side_effects=[SideEffectKind.NETWORK_REQUEST],
    )
    event = _event(
        SideEffectKind.NETWORK_REQUEST,
        destination="customer.internal.example:443",
    )

    violations = _side_effect_violations(tool, [event])

    assert len(violations) == 1
    assert violations[0]["reason"] == "side-effect kind is explicitly forbidden"


def test_read_only_requires_state_changing_coverage() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        read_only=True,
    )

    assert {
        SideEffectKind.FILESYSTEM_WRITE,
        SideEffectKind.DATABASE_WRITE,
        SideEffectKind.PROCESS_EXECUTION,
        SideEffectKind.MESSAGE_DISPATCH,
    }.issubset(_required_effect_kinds(tool))


def test_read_only_deny_all_overrides_filesystem_allowlist() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        read_only=True,
        allowed_filesystem_writes=["/workspace/*"],
    )
    event = _event(
        SideEffectKind.FILESYSTEM_WRITE,
        path="/workspace/result.txt",
    )

    violations = _side_effect_violations(tool, [event])

    assert len(violations) == 1
    assert violations[0]["reason"] == "read-only tool caused a state-changing side effect"
