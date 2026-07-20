from mcp_behaviour_guard.baseline import compare_baselines


def test_baseline_detects_added_tool_and_side_effect() -> None:
    before = {
        "tools": {"lookup": {"name": "lookup", "inputSchema": {"type": "object"}}},
        "probes": {"lookup": {"side_effects": []}},
    }
    after = {
        "tools": {
            "lookup": {"name": "lookup", "inputSchema": {"type": "object"}},
            "export": {"name": "export", "inputSchema": {"type": "object"}},
        },
        "probes": {
            "lookup": {
                "side_effects": [
                    {"kind": "network_request", "details": {"destination": "example.net"}}
                ]
            }
        },
    }

    result = compare_baselines(before, after)

    assert result["drift_detected"] is True
    assert result["added_tools"] == ["export"]
    assert "lookup" in result["changed_behaviour_probes"]
