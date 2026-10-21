"""Source-only trusted-helper starts: no Docker calls or candidate execution."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "assurance/phase2/ci"))
from p4_pipeline_journal import _STAGES, PipelineJournal  # noqa: E402
from p4_scoped_engine import EngineBinding, ScopedEngineRunner  # noqa: E402
from p4_trusted_runtime_adapter import (  # noqa: E402
    CommandResult,
    OwnedDockerAttempt,
    OwnedItem,
    P4AdapterError,
    P4RecoveryRequired,
)
from test_phase2_p4_pipeline_journal import advance, identity, observation  # noqa: E402

ROLE_IDS = dict(
    zip(
        ("candidate", "evaluator", "relay", "fixture-app", "fixture-control"),
        ("1" * 64, "2" * 64, "3" * 64, "4" * 64, "5" * 64),
        strict=True,
    )
)


def _attempt(tmp_path: Path, *, role: str = "relay"):
    ident = identity()
    outer = time.monotonic() + 500.0
    binding = EngineBinding("unix:///run/mcpbg-p4-a/engine.sock", ident.runtime_daemon, 1, 2)
    runner = ScopedEngineRunner(binding, invoke=lambda *args, **kwargs: None)
    item = OwnedItem("container", "owned-" + role, "CREATED", ROLE_IDS[role])
    a = OwnedDockerAttempt(
        policy=json.loads((ROOT / "assurance/phase2/ci/p4-resource-policy.json").read_text()),
        attempt_id=ident.attempt_id,
        lease_path=tmp_path / "attempt.lock",
        ledger_path=tmp_path / "owned.jsonl",
        daemon_context=binding.endpoint,
        daemon_identity=binding.daemon_id_sha256,
        run=runner,
        outer_deadline_monotonic=outer,
    )
    a._entered = True
    a._ledger_fd = os.open(tmp_path / "owned.jsonl", os.O_CREAT | os.O_WRONLY, 0o600)
    a._attested_role_ids = ROLE_IDS.copy()
    a.items.append(item)
    journal = PipelineJournal(tmp_path / "owned-p4-attempt-a.jsonl", ident, deadline=outer)
    return a, item, journal


def _prestart(journal: PipelineJournal):
    for stage in _STAGES[:6]:
        advance(journal, stage)


def _readback(item: OwnedItem, attempt: OwnedDockerAttempt, **changes):
    payload = {
        "Id": item.object_id,
        "Config": {"Labels": {"mcpbg.p4.owner": attempt.attempt_id}},
        "HostConfig": {"RestartPolicy": {"Name": "no"}},
        "State": {"Running": True, "Restarting": False, "Dead": False, "Pid": 31},
    }
    for key, value in changes.items():
        payload[key] = value
    raw = json.dumps(payload).encode()
    return CommandResult(0, raw, b"", len(raw))


def test_trusted_helper_started_only_inside_durable_active_intent(tmp_path: Path, monkeypatch):
    attempt, item, journal = _attempt(tmp_path)
    calls = []

    def fake_call(args, *, structured=False):
        calls.append(tuple(args))
        assert structured
        return (
            CommandResult(0, (item.object_id + "\n").encode(), b"", 65)
            if args[1] == "start"
            else _readback(item, attempt)
        )

    monkeypatch.setattr(attempt, "_checked_call", fake_call)
    try:
        with journal:
            _prestart(journal)
            assert journal.stage_index == 6
            with pytest.raises(P4AdapterError, match="durable graph intent"):
                attempt.start_attested_trusted_role(role="relay", item=item, journal=journal)
            assert calls == []
            result = journal.advance(
                "ACTIVE_GRAPH_OBSERVED",
                operation_id="active-graph",
                mutate=lambda: attempt.start_attested_trusted_role(
                    role="relay", item=item, journal=journal
                ),
                observe=lambda _result: json.dumps(
                    observation(journal.identity, "ACTIVE_GRAPH_OBSERVED", "active-graph")
                ).encode(),
            )
            assert result["runtime_enforcement_proven"] is False
            assert item.state == "RUNNING"
            assert len(calls) == 2
            assert journal.events[-2]["status"] == "INTENT"
            events = [
                json.loads(line)["event"]
                for line in (tmp_path / "owned.jsonl").read_text().splitlines()
            ]
            assert events == ["START_REQUESTED", "START_CONFIRMED"]
    finally:
        os.close(attempt._ledger_fd)


@pytest.mark.parametrize("change", ["candidate", "wrong-id", "wrong-owner", "deadline"])
def test_start_guard_rejects_before_engine_mutation(tmp_path: Path, monkeypatch, change: str):
    role = "candidate" if change == "candidate" else "relay"
    attempt, item, journal = _attempt(tmp_path, role=role)
    called = []
    monkeypatch.setattr(attempt, "_checked_call", lambda *a, **kw: called.append(a))
    try:
        with journal:
            _prestart(journal)
            if change == "wrong-id":
                attempt._attested_role_ids[role] = "f" * 64
            if change == "wrong-owner":
                attempt.daemon_identity = "f" * 64
            if change == "deadline":
                attempt.outer_deadline_monotonic = time.monotonic() - 1

            def mut():
                with pytest.raises(P4AdapterError):
                    attempt.start_attested_trusted_role(role=role, item=item, journal=journal)
                return object()

            journal.advance(
                "ACTIVE_GRAPH_OBSERVED",
                operation_id="active-graph",
                mutate=mut,
                observe=lambda _result: json.dumps(
                    observation(journal.identity, "ACTIVE_GRAPH_OBSERVED", "active-graph")
                ).encode(),
            )
            assert not called
    finally:
        os.close(attempt._ledger_fd)


@pytest.mark.parametrize(
    "broken", ["lost-ack", "drifted-id", "bad-pid", "restart-policy", "malformed"]
)
def test_start_failure_retains_unknown_and_prevents_retry(tmp_path: Path, monkeypatch, broken: str):
    attempt, item, journal = _attempt(tmp_path)
    calls = []

    def fake_call(args, *, structured=False):
        calls.append(tuple(args))
        if broken == "lost-ack":
            raise TimeoutError("Engine response lost")
        if args[1] == "start":
            return CommandResult(0, (item.object_id + "\n").encode(), b"", 65)
        if broken == "drifted-id":
            return _readback(item, attempt, Id="f" * 64)
        if broken == "bad-pid":
            return _readback(
                item, attempt, State={"Running": True, "Restarting": False, "Dead": False, "Pid": 0}
            )
        if broken == "restart-policy":
            return _readback(item, attempt, HostConfig={"RestartPolicy": {"Name": "always"}})
        return CommandResult(0, b'{"broken":', b"", 10)

    monkeypatch.setattr(attempt, "_checked_call", fake_call)
    try:
        with journal:
            _prestart(journal)
            with pytest.raises(P4RecoveryRequired):
                journal.advance(
                    "ACTIVE_GRAPH_OBSERVED",
                    operation_id="active-graph",
                    mutate=lambda: attempt.start_attested_trusted_role(
                        role="relay", item=item, journal=journal
                    ),
                    observe=lambda _: b"{}",
                )
            assert journal.unknown
            assert attempt.recovery_required
            assert item.state == "UNKNOWN"
            assert any(
                x["event"] == "START_UNKNOWN"
                for x in map(json.loads, (tmp_path / "owned.jsonl").read_text().splitlines())
            )
            count = len(calls)
            with pytest.raises(P4AdapterError):
                attempt.start_attested_trusted_role(role="relay", item=item, journal=journal)
            assert len(calls) == count
    finally:
        os.close(attempt._ledger_fd)
