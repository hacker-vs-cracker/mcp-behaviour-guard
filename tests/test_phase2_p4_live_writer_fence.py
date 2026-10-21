"""Source-only Engine readback faults; no Docker daemon is contacted."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "assurance/phase2/ci"))
from p4_live_writer_fence import (  # noqa: E402
    WriterFenceUnknown,
    observe_both_writers_fenced,
)
from p4_pipeline_journal import _STAGES, PipelineJournal  # noqa: E402
from p4_scoped_engine import EngineBinding, ScopedEngineRunner  # noqa: E402
from p4_trusted_runtime_adapter import CommandResult  # noqa: E402
from test_phase2_p4_pipeline_journal import advance, identity  # noqa: E402

IDS = {"fixture-app": "a" * 64, "fixture-control": "b" * 64}


class FakeScopedEngine(ScopedEngineRunner):
    def __init__(self, *, mutate=None):
        self.binding = EngineBinding(
            endpoint="unix:///run/mcpbg-p4-example/engine.sock",
            daemon_id_sha256="8" * 64,
            socket_dev=1,
            socket_ino=2,
        )
        self.mutate = mutate
        self.calls: list[str] = []

    def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
        assert argv[:5] == ("docker", "container", "inspect", "--format", "{{json .}}")
        assert 0 < timeout <= 20
        assert output_budget == retained_per_stream == 65536
        cid = argv[-1]
        self.calls.append(cid)
        obj = {
            "Id": cid,
            "Config": {"Labels": {"mcpbg.p4.owner": "attempt-a"}},
            "HostConfig": {"RestartPolicy": {"Name": "no"}},
            "State": {
                "Status": "exited",
                "Running": False,
                "Restarting": False,
                "Dead": False,
                "Pid": 0,
            },
            "RestartCount": 0,
        }
        if self.mutate:
            self.mutate(obj, len(self.calls))
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return CommandResult(0, raw, b"", len(raw) + 16)


def capture(runner=None, **changes):
    options = dict(
        runtime_runner=runner or FakeScopedEngine(),
        runtime_daemon_sha256="8" * 64,
        attempt_id="attempt-a",
        owned_container_ids=dict(IDS),
        active_requests=lambda: 0,
        original_deadline_monotonic=time.monotonic() + 200.0,
    )
    options.update(changes)
    return observe_both_writers_fenced(**options)


def test_two_distinct_writer_ids_are_checked_twice():
    runner = FakeScopedEngine()
    result = capture(runner)
    assert runner.calls == [IDS["fixture-app"], IDS["fixture-control"]] * 2
    assert result["writers"]["fixture-control"]["pid"] == 0
    assert result["writer_observation_status"] == "BOUND_ENGINE_DOUBLE_READ_SOURCE_ONLY"
    assert result["runtime_enforcement_proven"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda x, n: x["State"].update({"Running": True}),
        lambda x, n: x["State"].update({"Pid": 123}),
        lambda x, n: x["State"].update({"Status": "running"}),
        lambda x, n: x["State"].update({"Restarting": True}),
        lambda x, n: x["State"].update({"Dead": True}),
        lambda x, n: x["HostConfig"]["RestartPolicy"].update({"Name": "always"}),
        lambda x, n: x["Config"]["Labels"].update({"mcpbg.p4.owner": "other"}),
        lambda x, n: x.update({"Id": "f" * 64}),
        lambda x, n: x.update({"RestartCount": 1}) if n > 2 else None,
        lambda x, n: x.update({"RestartCount": False}),
        lambda x, n: x["State"].update({"Pid": False}),
    ],
)
def test_rejects_each_unsafe_or_drifting_engine_field(mutation):
    with pytest.raises(WriterFenceUnknown):
        capture(FakeScopedEngine(mutate=mutation))


@pytest.mark.parametrize(
    "change",
    [
        {"runtime_daemon_sha256": "9" * 64},
        {"attempt_id": "wrong"},
        {"owned_container_ids": {"fixture-app": "a" * 64, "fixture-control": "a" * 64}},
        {"owned_container_ids": {"fixture-app": "a" * 64}},
        {"active_requests": lambda: 1},
        {"active_requests": lambda: False},
        {"original_deadline_monotonic": 0.0},
    ],
)
def test_rejects_invalid_identity_counter_or_expired_original_budget(change):
    with pytest.raises(WriterFenceUnknown):
        capture(**change)


def test_fence_journal_intent_precedes_four_engine_reads(tmp_path: Path):
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, identity(), deadline=time.monotonic() + 300) as journal:
        for stage in _STAGES[: _STAGES.index("WRITERS_FENCED")]:
            advance(journal, stage)
        runner = FakeScopedEngine()
        # Special method lookup is on the class; the journal itself is already
        # responsible for writing the intent before the bound runner is called.
        result = journal.reconcile_live_writer_fence(
            operation_id="writer-fence-source",
            runtime_runner=runner,
            owned_container_ids=dict(IDS),
            active_requests=lambda: 0,
        )
        assert result["next_stage"] == "EXPORT_RECONCILED"
        rows = [json.loads(row) for row in path.read_text().splitlines()]
        assert rows[-2]["status"] == "INTENT"
        assert rows[-1]["status"] == "OBSERVED_SOURCE_ONLY"
        assert rows[-2]["details"]["reserved_output_bytes"] == 262144


def test_fence_journal_unsafe_readback_remains_unknown(tmp_path: Path):
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, identity(), deadline=time.monotonic() + 300) as journal:
        for stage in _STAGES[: _STAGES.index("WRITERS_FENCED")]:
            advance(journal, stage)
        with pytest.raises(WriterFenceUnknown):
            journal.reconcile_live_writer_fence(
                operation_id="writer-fence-source",
                runtime_runner=FakeScopedEngine(
                    mutate=lambda x, n: x["State"].update({"Running": True})
                ),
                owned_container_ids=dict(IDS),
                active_requests=lambda: 0,
            )
        assert journal.unknown is True
        assert journal.pending is True
    assert PipelineJournal.inspect_recovery(path, identity())["remote_operation_unresolved"] is True


@pytest.mark.parametrize("mode", ["nonzero", "stderr", "malformed", "truncated", "overflow"])
def test_rejects_incomplete_command_results(mode):
    class BrokenResult(FakeScopedEngine):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            base = super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )
            if mode == "nonzero":
                return CommandResult(1, base.stdout, b"", base.output_bytes)
            if mode == "stderr":
                return CommandResult(0, base.stdout, b"warning", base.output_bytes + 7)
            if mode == "malformed":
                return CommandResult(0, b'{"a":1,"a":2}', b"", base.output_bytes)
            if mode == "truncated":
                return CommandResult(0, base.stdout[:13], b"", base.output_bytes)
            return CommandResult(0, base.stdout, b"", 65537)

    with pytest.raises(WriterFenceUnknown):
        capture(BrokenResult())


def test_rejects_relay_counter_that_changes_after_second_sample():
    count = 0

    def active() -> int:
        nonlocal count
        count += 1
        return 1 if count == 3 else 0

    with pytest.raises(WriterFenceUnknown, match="counter changed"):
        capture(active_requests=active)
