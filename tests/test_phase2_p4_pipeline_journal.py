"""Source-only fault matrix; no Docker, remote mutation or runtime proof."""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "assurance/phase2/ci"))
from p4_pipeline_journal import (  # noqa: E402
    _STAGES,
    JournalUnknown,
    PipelineIdentity,
    PipelineJournal,
)

SHA = "a" * 64


def identity() -> PipelineIdentity:
    return PipelineIdentity(
        pipeline_id="pipeline-a",
        attempt_id="attempt-a",
        source_commit="1" * 40,
        source_tree="2" * 40,
        policy_sha256="cd321216217fbc11034e0aeb0a4afaca7ae42607142cd9158e31d094f54a707f",
        reference_sha256="54ddd04418211add290a597b2e775fb05953d7599b4e78014e57b24b105b6f09",
        build_worker="5" * 64,
        build_daemon="6" * 64,
        runtime_worker="7" * 64,
        runtime_daemon="8" * 64,
    )


def observation(ident: PipelineIdentity, stage: str, operation: str) -> dict:
    is_build = stage in _STAGES[:4]
    obj = {
        "schema_version": 1,
        "attempt_id": ident.attempt_id,
        "operation_id": operation,
        "stage": stage,
        "worker": ident.build_worker if is_build else ident.runtime_worker,
        "daemon": ident.build_daemon if is_build else ident.runtime_daemon,
        "runtime_enforcement_proven": False,
        "approval_outcome": "NOT_EVALUATED",
    }
    cases = {
        "IMAGE_TRANSFER_OBSERVED": {
            "platform": "linux/amd64",
            "source_archive_sha256": SHA,
            "destination_archive_sha256": SHA,
            "source_image_id": "sha256:" + SHA,
            "destination_image_id": "sha256:" + SHA,
            "transfer_bytes": 4096,
        },
        "BUILD_WORKER_DISPOSED": {
            "worker_alive": False,
            "daemon_alive": False,
            "cache_entries": 0,
            "scratch_entries": 0,
            "remaining_owned_resources": [],
        },
        "CREATED_GRAPH_OBSERVED": {
            "roles": dict.fromkeys(
                ("candidate", "evaluator", "relay", "fixture-app", "fixture-control"), SHA
            ),
            "candidate_started": False,
            "profiles_sha256": SHA,
        },
        "ACTIVE_GRAPH_OBSERVED": {"startup_barrier_proven": False},
        "RELAY_DRAINED": {"admission_closed": True, "active_requests": 0, "drain_complete": True},
        "CONTROL_FINALIZED": {"audit_complete": True, "active_requests": 0},
        "WRITERS_FENCED": {
            "writers": {
                x: {"running": False, "pid": 0, "container_id": SHA}
                for x in ("fixture-app", "fixture-control")
            },
            "active_requests": 0,
        },
        "EXPORT_RECONCILED": {
            "source_export_status": "MATCHED_FENCED_SOURCE_DIGESTS_SOURCE_ONLY",
            "business_effect_status": "MATCHED_REVIEWED_PROJECTION_SOURCE_ONLY",
            "runtime_enforcement_proven": False,
        },
        "SAVED_RUN_COMPARED": {"comparison_sha256": SHA},
        "CLEANUP_RECONCILED": {"owned_resources_remaining": []},
    }
    obj.update(cases.get(stage, {}))
    return obj


def advance(j: PipelineJournal, stage: str, *, modify=None):
    op = "op-" + stage.lower().replace("_", "-")
    data = observation(j.identity, stage, op)
    if modify is not None:
        modify(data)
    return j.advance(
        stage,
        operation_id=op,
        mutate=lambda: object(),
        observe=lambda _: json.dumps(data, sort_keys=True).encode(),
        output_bytes=13,
    )


def test_one_durable_source_pipeline_and_replay(tmp_path: Path):
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    i = identity()
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as j:
        for stage in _STAGES:
            value = advance(j, stage)
            assert value["runtime_enforcement_proven"] is False
            assert value["complete_integrated_runtime_wiring"] is False
            assert value["approval_outcome"] == "NOT_EVALUATED"
    recovered = PipelineJournal.inspect_recovery(path, i)
    assert recovered["stages_observed"] == len(_STAGES)
    assert recovered["remote_operation_unresolved"] is False
    assert recovered["historical_receipts_are_startup_authority"] is False
    assert path.stat().st_mode & 0o077 == 0


def test_must_write_intent_before_mutation_and_observation(tmp_path: Path):
    i = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as j:
        seen = []

        def mut():
            lines = path.read_text().splitlines()
            assert json.loads(lines[-1])["status"] == "INTENT"
            seen.append("mutate")
            return object()

        def obs(_):
            seen.append("readback")
            return json.dumps(observation(i, _STAGES[0], "first-op")).encode()

        j.advance(_STAGES[0], operation_id="first-op", mutate=mut, observe=obs)
        assert seen == ["mutate", "readback"]


def test_lost_ack_crash_keeps_unknown_never_replays(tmp_path: Path):
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    i = identity()
    count = 0
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as j:

        def mut():
            nonlocal count
            count += 1
            raise TimeoutError("CLI reply lost after possible remote action")

        with pytest.raises(TimeoutError):
            j.advance(_STAGES[0], operation_id="lost-ack", mutate=mut, observe=lambda _: b"{}")
        with pytest.raises(JournalUnknown):
            j.advance(_STAGES[0], operation_id="again", mutate=mut, observe=lambda _: b"{}")
    assert count == 1
    assert PipelineJournal.inspect_recovery(path, i)["remote_operation_unresolved"] is True


def test_failed_unknown_journal_append_requires_reconciliation(tmp_path: Path, monkeypatch):
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    i = identity()
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as journal:
        original_append = journal._append

        def append_or_fail(status, stage, operation_id, details):
            if status == "UNKNOWN":
                raise OSError("simulated journal fsync failure")
            return original_append(status, stage, operation_id, details)

        monkeypatch.setattr(journal, "_append", append_or_fail)

        def lost_ack():
            raise TimeoutError("simulated lost acknowledgement")

        with pytest.raises(JournalUnknown, match="cannot durably record uncertain"):
            journal.advance(
                _STAGES[0],
                operation_id="lost-ack-journal-error",
                mutate=lost_ack,
                observe=lambda _: b"{}",
            )
        assert journal.unknown is True
        assert journal.pending is True
    # The earlier INTENT remains durable even when the UNKNOWN append fails.
    assert PipelineJournal.inspect_recovery(path, i)["remote_operation_unresolved"] is True


def test_crash_between_intent_and_observation_retained(tmp_path: Path):
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    i = identity()
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as j:
        j._append("INTENT", _STAGES[0], "op-crash", {})
    assert PipelineJournal.inspect_recovery(path, i)["remote_operation_unresolved"] is True


@pytest.mark.parametrize(
    "stage,mutant",
    [
        ("IMAGE_TRANSFER_OBSERVED", {"destination_archive_sha256": "b" * 64}),
        ("IMAGE_TRANSFER_OBSERVED", {"transfer_bytes": 1_073_741_825}),
        ("IMAGE_TRANSFER_OBSERVED", {"platform": "linux/arm64"}),
        ("BUILD_WORKER_DISPOSED", {"daemon_alive": True}),
        ("BUILD_WORKER_DISPOSED", {"cache_entries": 1}),
        ("CREATED_GRAPH_OBSERVED", {"candidate_started": True}),
        ("ACTIVE_GRAPH_OBSERVED", {"startup_barrier_proven": True}),
        ("RELAY_DRAINED", {"active_requests": 1}),
        ("RELAY_DRAINED", {"admission_closed": False}),
        ("CONTROL_FINALIZED", {"audit_complete": False}),
        ("WRITERS_FENCED", {"active_requests": 1}),
        ("WRITERS_FENCED", {"writers": {"fixture-app": {"running": False}}}),
        ("EXPORT_RECONCILED", {"source_export_status": "NOT_EVALUATED"}),
        ("EXPORT_RECONCILED", {"business_effect_status": "NOT_EVALUATED"}),
        ("SAVED_RUN_COMPARED", {"approval_outcome": "PASS"}),
        ("CLEANUP_RECONCILED", {"owned_resources_remaining": ["unreconciled"]}),
    ],
)
def test_fault_matrix_rejects_unproven_boundary(tmp_path: Path, stage: str, mutant: dict):
    i = identity()
    with PipelineJournal(
        tmp_path / "owned-p4-attempt-a.jsonl", i, deadline=time.monotonic() + 500
    ) as j:
        for prior in _STAGES[: _STAGES.index(stage)]:
            advance(j, prior)
        with pytest.raises(JournalUnknown):
            advance(j, stage, modify=lambda data: data.update(mutant))
        assert j.unknown is True


def test_stage_order_and_attempt_worker_identity_guards(tmp_path: Path):
    i = identity()
    with PipelineJournal(
        tmp_path / "owned-p4-attempt-a.jsonl", i, deadline=time.monotonic() + 500
    ) as j:
        with pytest.raises(JournalUnknown):
            advance(j, _STAGES[1])
        with pytest.raises(JournalUnknown):
            advance(j, _STAGES[0], modify=lambda d: d.update({"attempt_id": "wrong"}))
    with pytest.raises(JournalUnknown):
        PipelineIdentity(**{**vars(i), "runtime_daemon": i.build_daemon})


def test_torn_log_and_tampered_digest_refuse_recovery(tmp_path: Path):
    i = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as j:
        advance(j, _STAGES[0])
    raw = path.read_bytes()
    path.write_bytes(raw[:-1])
    with pytest.raises(JournalUnknown):
        PipelineJournal.inspect_recovery(path, i)
    path.write_bytes(raw.replace(b"BUILD_WORKER_ADMITTED", b"BUILD_WORKER_ADMITTEd"))
    with pytest.raises(JournalUnknown):
        PipelineJournal.inspect_recovery(path, i)


def test_source_outputs_do_not_mint_native_authority(tmp_path: Path):
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    i = identity()
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as j:
        value = advance(j, _STAGES[0])
        assert value["complete_integrated_runtime_wiring"] is False
        assert value["runtime_enforcement_proven"] is False
        assert value["approval_outcome"] == "NOT_EVALUATED"
    assert hashlib.sha256(path.read_bytes()).hexdigest()


def test_composed_export_calls_real_fenced_sqlite_business_verifier(tmp_path: Path):
    import shutil
    import sqlite3

    from assurance.phase2.fixture.store import FixtureStore

    live = tmp_path / "live"
    live.mkdir()
    store = FixtureStore(live / "fixture.db")
    store.bootstrap()
    token = store.create_attempt("attempt-a").token
    store.open_attempt("attempt-a")
    store.business_write(token, record_id="record-1", value="expected", request_id="request-1")
    store.close_attempt("attempt-a")
    fenced = store.final_snapshot("attempt-a")
    store.finalize_attempt("attempt-a")
    finalized = store.snapshot("attempt-a")
    exported = tmp_path / "exported"
    shutil.copytree(live, exported)
    with sqlite3.connect(exported / "fixture.db") as db:
        db.row_factory = sqlite3.Row
        expected = [
            dict(x)
            for x in db.execute(
                "SELECT record_id,value,updated_by_attempt,updated_by_request,updated_at "
                "FROM records ORDER BY record_id"
            )
        ]
    fingerprints = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in exported.iterdir()}
    i = identity()
    with PipelineJournal(
        tmp_path / "owned-p4-attempt-a.jsonl", i, deadline=time.monotonic() + 500
    ) as j:
        for stage in _STAGES[: _STAGES.index("EXPORT_RECONCILED")]:
            advance(j, stage)
        reconciled = j.reconcile_exported_fixture(
            operation_id="export-one",
            exported_state=exported,
            fenced_snapshot=fenced,
            finalized_snapshot=finalized,
            expected_records=expected,
            fenced_source_sha256=fingerprints,
            artifact_ceiling_bytes=16_777_216,
        )
        assert reconciled["status"] == "SOURCE_STAGE_RECONCILED_ONLY"
        assert reconciled["next_stage"] == "SAVED_RUN_COMPARED"


def test_composed_export_rejects_wrong_business_effect(tmp_path: Path):
    import shutil
    import sqlite3

    from assurance.phase2.fixture.store import FixtureStore

    live = tmp_path / "live"
    live.mkdir()
    store = FixtureStore(live / "fixture.db")
    store.bootstrap()
    token = store.create_attempt("attempt-a").token
    store.open_attempt("attempt-a")
    store.business_write(token, record_id="record-1", value="expected", request_id="request-1")
    store.close_attempt("attempt-a")
    fenced = store.final_snapshot("attempt-a")
    store.finalize_attempt("attempt-a")
    finalized = store.snapshot("attempt-a")
    exported = tmp_path / "exported"
    shutil.copytree(live, exported)
    with sqlite3.connect(exported / "fixture.db") as db:
        db.row_factory = sqlite3.Row
        expected = [
            dict(x)
            for x in db.execute(
                "SELECT record_id,value,updated_by_attempt,updated_by_request,updated_at "
                "FROM records ORDER BY record_id"
            )
        ]
        db.execute("UPDATE records SET value='wrong'")
    fingerprints = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in exported.iterdir()}
    i = identity()
    with PipelineJournal(
        tmp_path / "owned-p4-attempt-a.jsonl", i, deadline=time.monotonic() + 500
    ) as j:
        for stage in _STAGES[: _STAGES.index("EXPORT_RECONCILED")]:
            advance(j, stage)
        with pytest.raises(RuntimeError):
            j.reconcile_exported_fixture(
                operation_id="export-one",
                exported_state=exported,
                fenced_snapshot=fenced,
                finalized_snapshot=finalized,
                expected_records=expected,
                fenced_source_sha256=fingerprints,
                artifact_ceiling_bytes=16_777_216,
            )
        assert j.unknown is True
