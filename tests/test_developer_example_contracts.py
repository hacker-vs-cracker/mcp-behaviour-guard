from pathlib import Path

from mcp_behaviour_guard.client import _matches_denial_marker
from mcp_behaviour_guard.config import load_contract


def test_tenant_example_uses_same_identity_positive_and_negative_controls() -> None:
    contract = load_contract(Path("contracts/examples/tenant-isolation.yaml"))
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
                "result": "SYNTHETIC_TENANT_B_PRIVATE_CANARY",
            }
        )
        == 1
    )


def test_tenant_example_uses_explicit_synthetic_denial_marker() -> None:
    contract = load_contract(Path("contracts/examples/tenant-isolation.yaml"))
    markers = contract.tools["customer_lookup"].denial_error_markers

    assert _matches_denial_marker(
        {"error": "GUARD_DEMO_DENIED: cross-tenant access"},
        markers,
    )
    assert not _matches_denial_marker({"error": "validation failed"}, markers)


def test_local_example_uses_explicit_nonproduction_secret_canary() -> None:
    contract = load_contract(Path("contracts/examples/local-coding-assistant.yaml"))
    value = contract.server.environment["GUARD_DEMO_SECRET"]

    assert value == "synthetic-guard-demo-secret-value"

    diagnostics = contract.tools["diagnostics"]
    env_check = diagnostics.policy_probes[0].checks[0]
    assert env_check.type == "response_not_contains_env"
    assert env_check.env_names == ["GUARD_DEMO_SECRET"]


def test_local_example_denial_is_not_a_generic_error_convention() -> None:
    contract = load_contract(Path("contracts/examples/local-coding-assistant.yaml"))
    markers = contract.tools["repo_read"].denial_error_markers

    assert markers == ["GUARD_DEMO_DENIED"]
    assert _matches_denial_marker(
        {"error": "GUARD_DEMO_DENIED: path outside workspace"},
        markers,
    )
    assert not _matches_denial_marker({"error": "file not found"}, markers)
