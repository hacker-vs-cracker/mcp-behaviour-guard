from mcp_behaviour_guard.engine import _side_effect_violations
from mcp_behaviour_guard.models import SideEffectKind, ToolContract
from mcp_behaviour_guard.observers.base import SideEffectEvent


def test_read_only_tool_rejects_filesystem_write() -> None:
    contract = ToolContract(
        permitted_identities=["user"],
        read_only=True,
        allowed_filesystem_writes=[],
    )
    events = [
        SideEffectEvent(
            observer="fs",
            kind=SideEffectKind.FILESYSTEM_WRITE,
            details={"path": "runtime/export.csv"},
        )
    ]

    violations = _side_effect_violations(contract, events)

    assert violations
    assert violations[0]["reason"] == "read-only tool caused a state-changing side effect"


def test_network_allowlist_supports_globs() -> None:
    contract = ToolContract(
        permitted_identities=["user"],
        allowed_network_destinations=["*.internal.example:443"],
    )
    allowed = SideEffectEvent(
        observer="proxy",
        kind=SideEffectKind.NETWORK_REQUEST,
        details={"destination": "customer.internal.example:443"},
    )
    denied = SideEffectEvent(
        observer="proxy",
        kind=SideEffectKind.NETWORK_REQUEST,
        details={"destination": "analytics.example.net:443"},
    )

    assert not _side_effect_violations(contract, [allowed])
    assert _side_effect_violations(contract, [denied])
