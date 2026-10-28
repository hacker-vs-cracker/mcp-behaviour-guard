"""Complete helper-group source observations, never a native candidate-start test."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "assurance/phase2/ci"))
from p4_helper_active_controller import reconcile_trusted_helper_group  # noqa: E402
from p4_pipeline_journal import JournalUnknown, PipelineJournal  # noqa: E402
from p4_trusted_runtime_adapter import CommandResult, OwnedItem, P4RecoveryRequired  # noqa: E402
from test_phase2_p4_trusted_starts import ROLE_IDS, _attempt, _prestart  # noqa: E402


def scenario(tmp_path: Path, monkeypatch, broken: str = ""):
    attempt, relay, journal = _attempt(tmp_path)
    items = {
        role: OwnedItem("container", "owned-" + role, "CREATED", ident)
        for role, ident in ROLE_IDS.items()
    }
    items["relay"] = relay
    networks = {
        name: OwnedItem("network", "owned-" + name, "CREATED", nid * 64)
        for name, nid in {"subject": "a", "fixture": "b", "control": "c"}.items()
    }
    attempt.items.extend(x for x in items.values() if x is not relay)
    attempt.items.extend(networks.values())
    calls: list[tuple[str, str]] = []
    started: set[str] = set()
    seen_candidate = 0

    def engine_call(argv, *, structured=False):
        nonlocal seen_candidate
        assert structured
        assert argv[0] == "docker"
        verb = argv[1]
        container_id = argv[-1]
        if verb == "network":
            role = next(k for k, v in networks.items() if v.object_id == container_id)
            calls.append((verb, role))
            peers = {
                "subject": {"evaluator", "relay"},
                "fixture": {"fixture-app", "relay"},
                "control": {"fixture-control"},
            }[role]
            actual = {ROLE_IDS[x]: {} for x in peers}
            if broken == "network-bypass" and role == "subject":
                actual["f" * 64] = {}
            if broken == "candidate-network-peer" and role == "subject":
                actual[ROLE_IDS["candidate"]] = {}
            if broken == "network-missing" and role == "fixture":
                actual.pop(ROLE_IDS["relay"])
            owner = (
                "wrong-attempt"
                if broken == "network-owner" and role == "control"
                else attempt.attempt_id
            )
            payload = {
                "Id": container_id,
                "Labels": {"mcpbg.p4.owner": owner},
                "Internal": True,
                "Attachable": False,
                "Ingress": False,
                "Driver": "bridge",
                "EnableIPv6": False,
                "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
                "Containers": actual,
            }
            raw = json.dumps(payload).encode()
            return CommandResult(0, raw, b"", len(raw))
        role = next(k for k, v in ROLE_IDS.items() if v == container_id)
        calls.append((verb, role))
        if verb == "start":
            assert role != "candidate"
            if broken == "lost-ack" and role == "relay":
                started.add(role)
                raise TimeoutError("reply missing after successful remote start")
            started.add(role)
            return CommandResult(0, (container_id + "\n").encode(), b"", 65)
        assert verb == "container"
        if role == "candidate":
            seen_candidate += 1
        state = {
            "Running": role in started,
            "Restarting": False,
            "Dead": False,
            "Pid": 42 if role in started else 0,
        }
        cfg = {"Labels": {"mcpbg.p4.owner": attempt.attempt_id}}
        host = {"RestartPolicy": {"Name": "no"}}
        if role == "candidate" and broken == "premature-candidate":
            state.update(Running=True, Pid=43)
        if role == "candidate" and broken == "late-candidate" and seen_candidate == 2:
            state.update(Running=True, Pid=43)
        if role == "candidate" and broken == "candidate-descriptor-drift" and seen_candidate == 2:
            cfg["Labels"]["unexpected"] = "drift"
        if role == "evaluator" and broken == "wrong-owner":
            cfg["Labels"]["mcpbg.p4.owner"] = "different-attempt"
        if (
            role == "relay"
            and broken == "helper-stopped"
            and calls.count(("container", "relay")) >= 2
        ):
            state.update(Running=False, Pid=0)
        if role == "relay" and broken == "truncated" and calls.count(("container", "relay")) >= 2:
            return CommandResult(0, b'{"Id":', b"", 6)
        raw = json.dumps(
            {"Id": container_id, "Config": cfg, "HostConfig": host, "State": state}
        ).encode()
        return CommandResult(0, raw, b"", len(raw))

    monkeypatch.setattr(attempt, "_checked_call", engine_call)
    return attempt, journal, items, networks, calls


def test_four_helpers_have_one_durable_intent_and_candidate_remains_stopped(tmp_path, monkeypatch):
    attempt, journal, items, networks, calls = scenario(tmp_path, monkeypatch)
    try:
        with journal:
            _prestart(journal)
            result = reconcile_trusted_helper_group(
                attempt=attempt,
                journal=journal,
                role_items=items,
                network_items=networks,
                operation_id="helper-start-group",
            )
            assert result["next_stage"] == "RELAY_DRAINED"
            assert result["complete_integrated_runtime_wiring"] is False
            assert not journal.pending and not journal.unknown
            assert [(verb, role) for verb, role in calls if verb == "start"] == [
                ("start", role) for role in ("fixture-control", "fixture-app", "relay", "evaluator")
            ]
            assert [role for verb, role in calls if role == "candidate"] == [
                "candidate",
                "candidate",
            ]
            assert items["candidate"].state == "CREATED"
            assert [role for verb, role in calls if verb == "network"] == [
                "subject",
                "fixture",
                "control",
            ]
            events = [json.loads(line) for line in journal.path.read_text().splitlines()]
            assert events[-2]["status"] == "INTENT"
            assert events[-1]["status"] == "OBSERVED_SOURCE_ONLY"
    finally:
        os.close(attempt._ledger_fd)


@pytest.mark.parametrize(
    "broken",
    [
        "lost-ack",
        "premature-candidate",
        "late-candidate",
        "candidate-descriptor-drift",
        "wrong-owner",
        "helper-stopped",
        "truncated",
        "network-bypass",
        "candidate-network-peer",
        "network-missing",
        "network-owner",
    ],
)
def test_group_rejects_real_engine_drift_and_requires_recovery(tmp_path, monkeypatch, broken):
    attempt, journal, items, networks, calls = scenario(tmp_path, monkeypatch, broken)
    try:
        with journal:
            _prestart(journal)
            with pytest.raises((JournalUnknown, P4RecoveryRequired, ValueError)):
                reconcile_trusted_helper_group(
                    attempt=attempt,
                    journal=journal,
                    role_items=items,
                    network_items=networks,
                    operation_id="helper-start-group",
                )
            assert journal.unknown is True
            assert (
                PipelineJournal.inspect_recovery(journal.path, journal.identity)[
                    "remote_operation_unresolved"
                ]
                is True
            )
            prev_calls = len(calls)
            with pytest.raises(JournalUnknown):
                reconcile_trusted_helper_group(
                    attempt=attempt,
                    journal=journal,
                    role_items=items,
                    network_items=networks,
                    operation_id="helper-start-group-retry",
                )
            assert len(calls) == prev_calls
            assert all(role != "candidate" for verb, role in calls if verb == "start")
    finally:
        os.close(attempt._ledger_fd)


@pytest.mark.parametrize(
    "change", ["missing", "wrong-id", "wrong-daemon", "candidate-running-state", "wrong-stage"]
)
def test_group_fails_before_start_when_admission_is_incomplete(tmp_path, monkeypatch, change):
    attempt, journal, items, networks, calls = scenario(tmp_path, monkeypatch)
    try:
        with journal:
            _prestart(journal)
            if change == "missing":
                del items["relay"]
            elif change == "wrong-id":
                items["relay"].object_id = "f" * 64
            elif change == "wrong-daemon":
                attempt.daemon_identity = "b" * 64
            elif change == "candidate-running-state":
                items["candidate"].state = "RUNNING"
            elif change == "wrong-stage":
                journal.stage_index -= 1
            with pytest.raises(JournalUnknown):
                reconcile_trusted_helper_group(
                    attempt=attempt,
                    journal=journal,
                    role_items=items,
                    network_items=networks,
                    operation_id="helper-start-group",
                )
            assert not calls
    finally:
        os.close(attempt._ledger_fd)
