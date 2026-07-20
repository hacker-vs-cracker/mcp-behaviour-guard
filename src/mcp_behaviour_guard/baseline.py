from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .client import McpClient
from .models import Contract
from .observers import build_observer
from .util import response_shape, stable_hash, utc_now


async def capture_baseline(contract: Contract, lab_mode: bool = False) -> dict[str, Any]:
    identity_name, identity = _discovery_identity(contract)
    client = McpClient(contract.server, identity_name, identity)
    tools = await client.list_tools()
    observers = [build_observer(name, spec) for name, spec in contract.observers.items()]

    probes: dict[str, Any] = {}
    for tool_name, tool_contract in contract.tools.items():
        if not tool_contract.read_only and not (lab_mode and contract.safety.destructive_tests):
            probes[tool_name] = {
                "skipped": True,
                "reason": "state-changing baseline probe requires lab mode",
            }
            continue
        probe_identity_name = (
            tool_contract.side_effect_identity or tool_contract.permitted_identities[0]
        )
        probe_identity = contract.identities[probe_identity_name]
        for observer in observers:
            await observer.begin()
        invocation = await McpClient(contract.server, probe_identity_name, probe_identity).invoke(
            f"BASELINE-{tool_name}", tool_name, tool_contract.probe_arguments
        )
        event_batches = [await observer.collect() for observer in observers]
        events = [asdict(event) for batch in event_batches for event in batch]
        probes[tool_name] = {
            "identity": probe_identity_name,
            "allowed": invocation.allowed,
            "response_shape": response_shape(invocation.response),
            "side_effects": _normalise_events(events),
        }

    tool_map = {tool["name"]: tool for tool in tools}
    payload = {
        "format_version": 1,
        "captured_at": utc_now(),
        "target": contract.server.target_label,
        "tools": tool_map,
        "probes": probes,
    }
    payload["fingerprint"] = stable_hash(payload)
    return payload


def write_baseline(baseline: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")


def load_baseline(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def compare_baselines(expected: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    expected_tools = set(expected.get("tools", {}))
    current_tools = set(current.get("tools", {}))
    schema_changes: dict[str, Any] = {}

    for name in sorted(expected_tools & current_tools):
        before = expected["tools"][name]
        after = current["tools"][name]
        if stable_hash(before) != stable_hash(after):
            schema_changes[name] = {"before": before, "after": after}

    probe_changes: dict[str, Any] = {}
    expected_probes = expected.get("probes", {})
    current_probes = current.get("probes", {})
    for name in sorted(set(expected_probes) | set(current_probes)):
        before = expected_probes.get(name)
        after = current_probes.get(name)
        if stable_hash(before) != stable_hash(after):
            probe_changes[name] = {"before": before, "after": after}

    result: dict[str, Any] = {
        "added_tools": sorted(current_tools - expected_tools),
        "removed_tools": sorted(expected_tools - current_tools),
        "changed_tool_schemas": schema_changes,
        "changed_behaviour_probes": probe_changes,
    }
    result["drift_detected"] = any(
        [
            result["added_tools"],
            result["removed_tools"],
            schema_changes,
            probe_changes,
        ]
    )
    return result


def _discovery_identity(contract: Contract):
    for name, identity in contract.identities.items():
        if identity.headers:
            return name, identity
    return next(iter(contract.identities.items()))


def _normalise_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalised = []
    for event in events:
        details = dict(event.get("details", {}))
        for volatile in ("id", "timestamp", "created_at", "request_id"):
            details.pop(volatile, None)
        normalised.append(
            {
                "observer": event.get("observer"),
                "kind": str(event.get("kind")),
                "details": details,
            }
        )
    return sorted(normalised, key=lambda item: json.dumps(item, sort_keys=True, default=str))
