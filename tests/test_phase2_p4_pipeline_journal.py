"""Source-only fault matrix; no Docker, remote mutation or runtime proof."""

from __future__ import annotations

import contextlib
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
        "BUILD_WORKER_ADMITTED": {
            "platform": "linux/amd64",
            "whole_worker_storage_sha256": SHA,
            "whole_worker_storage_bytes": 1_073_741_824,
            "reviewed_build_spec_sha256": SHA,
            "private_engine_endpoint_sha256": SHA,
            "physical_admission_proven": False,
        },
        "BUILD_RESULT_OBSERVED": {
            "platform": "linux/amd64",
            "reviewed_build_spec_sha256": SHA,
            "bounded_build_receipt_sha256": SHA,
            "resolved_image_id": "sha256:" + SHA,
            "build_exit_code": 0,
            "build_observed_source_only": True,
            "physical_build_proven": False,
        },
        "RUNTIME_WORKER_ADMITTED": {
            "platform": "linux/amd64",
            "private_engine_endpoint_sha256": SHA,
            "build_disposal_receipt_sha256": SHA,
            "image_transfer_receipt_sha256": SHA,
            "resolved_image_id": "sha256:" + SHA,
            "candidate_started": False,
            "native_runtime_admission_proven": False,
        },
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
            "disposal_readback_sha256": SHA,
            "daemon_socket_present": False,
            "data_root_mounted": False,
            "builder_present": False,
            "disposal_inspected_source_only": True,
            "physical_disposal_proven": False,
        },
        "CREATED_GRAPH_OBSERVED": {
            "roles": dict.fromkeys(
                ("candidate", "evaluator", "relay", "fixture-app", "fixture-control"), SHA
            ),
            "candidate_started": False,
            "profiles_sha256": SHA,
        },
        "ACTIVE_GRAPH_OBSERVED": {
            "startup_barrier_proven": False,
            "candidate_started": False,
            "active_network_verified": False,
            "helper_network_membership_verified_source_only": True,
            "helper_start_receipts": {
                "fixture-control": "1" * 64,
                "fixture-app": "2" * 64,
                "relay": "3" * 64,
                "evaluator": "4" * 64,
            },
            "helper_descriptors_sha256": {
                "fixture-control": SHA,
                "fixture-app": SHA,
                "relay": SHA,
                "evaluator": SHA,
            },
            "candidate_descriptor_sha256": SHA,
            "helper_network_descriptors_sha256": {
                "subject": SHA,
                "fixture": SHA,
                "control": SHA,
            },
        },
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
    if stage == "BUILD_RESULT_OBSERVED" and "BUILD_WORKER_ADMITTED" in j.observed_receipts:
        data["reviewed_build_spec_sha256"] = j.observed_receipts["BUILD_WORKER_ADMITTED"][
            "reviewed_build_spec_sha256"
        ]
    elif stage == "IMAGE_TRANSFER_OBSERVED" and "BUILD_RESULT_OBSERVED" in j.observed_receipts:
        data["source_image_id"] = j.observed_receipts["BUILD_RESULT_OBSERVED"]["resolved_image_id"]
        data["destination_image_id"] = data["source_image_id"]
    elif stage == "RUNTIME_WORKER_ADMITTED" and "BUILD_WORKER_DISPOSED" in j.observed_receipts:
        data["private_engine_endpoint_sha256"] = "b" * 64
        data["build_disposal_receipt_sha256"] = j.observed_receipts["BUILD_WORKER_DISPOSED"][
            "observation_sha256"
        ]
        data["image_transfer_receipt_sha256"] = j.observed_receipts["IMAGE_TRANSFER_OBSERVED"][
            "observation_sha256"
        ]
        data["resolved_image_id"] = j.observed_receipts["IMAGE_TRANSFER_OBSERVED"][
            "destination_image_id"
        ]
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
        j._append(
            "INTENT",
            _STAGES[0],
            "op-crash",
            {"worker": i.build_worker, "daemon": i.build_daemon, "reserved_output_bytes": 19},
        )
    assert PipelineJournal.inspect_recovery(path, i)["remote_operation_unresolved"] is True


@pytest.mark.parametrize(
    "stage,mutant",
    [
        ("BUILD_WORKER_ADMITTED", {"whole_worker_storage_bytes": 1_073_741_825}),
        ("BUILD_WORKER_ADMITTED", {"whole_worker_storage_sha256": None}),
        ("BUILD_WORKER_ADMITTED", {"physical_admission_proven": True}),
        ("BUILD_WORKER_ADMITTED", {"platform": "linux/arm64"}),
        ("BUILD_RESULT_OBSERVED", {"build_exit_code": True}),
        ("BUILD_RESULT_OBSERVED", {"bounded_build_receipt_sha256": None}),
        ("BUILD_RESULT_OBSERVED", {"resolved_image_id": "old-untagged"}),
        ("BUILD_RESULT_OBSERVED", {"physical_build_proven": True}),
        ("RUNTIME_WORKER_ADMITTED", {"build_disposal_receipt_sha256": None}),
        ("RUNTIME_WORKER_ADMITTED", {"image_transfer_receipt_sha256": None}),
        ("RUNTIME_WORKER_ADMITTED", {"native_runtime_admission_proven": True}),
        ("RUNTIME_WORKER_ADMITTED", {"candidate_started": True}),
        ("IMAGE_TRANSFER_OBSERVED", {"destination_archive_sha256": "b" * 64}),
        ("IMAGE_TRANSFER_OBSERVED", {"transfer_bytes": 1_073_741_825}),
        ("IMAGE_TRANSFER_OBSERVED", {"platform": "linux/arm64"}),
        ("BUILD_WORKER_DISPOSED", {"daemon_alive": True}),
        ("BUILD_WORKER_DISPOSED", {"cache_entries": 1}),
        ("BUILD_WORKER_DISPOSED", {"disposal_readback_sha256": None}),
        ("BUILD_WORKER_DISPOSED", {"disposal_inspected_source_only": False}),
        ("BUILD_WORKER_DISPOSED", {"physical_disposal_proven": True}),
        ("BUILD_WORKER_DISPOSED", {"data_root_mounted": True}),
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
    exported.mkdir()
    # Snapshot the finalized logical state without copying disappearing WAL/SHM paths.
    with (
        contextlib.closing(sqlite3.connect(live / "fixture.db")) as source,
        contextlib.closing(sqlite3.connect(exported / "fixture.db")) as target,
    ):
        source.backup(target)
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
        assert reconciled["next_stage"] == "CLEANUP_RECONCILED"


def test_composed_export_rejects_wrong_business_effect(tmp_path: Path):
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
    exported.mkdir()
    # Snapshot the finalized logical state without copying disappearing WAL/SHM paths.
    with (
        contextlib.closing(sqlite3.connect(live / "fixture.db")) as source,
        contextlib.closing(sqlite3.connect(exported / "fixture.db")) as target,
    ):
        source.backup(target)
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


def test_reconciled_image_file_digest_is_used_by_journal(tmp_path: Path):
    i = identity()
    build_archive = tmp_path / "build.tar"
    runtime_archive = tmp_path / "runtime.tar"
    build_archive.write_bytes(b"reviewed-image-archive")
    runtime_archive.write_bytes(b"reviewed-image-archive")
    expected = {"Id": "sha256:" + SHA, "Os": "linux", "Architecture": "amd64"}
    with PipelineJournal(
        tmp_path / "owned-p4-attempt-a.jsonl", i, deadline=time.monotonic() + 500
    ) as j:
        advance(j, _STAGES[0])
        advance(j, _STAGES[1])
        response = j.reconcile_staged_image_archive(
            operation_id="bounded-image-transfer",
            source_archive=build_archive,
            destination_archive=runtime_archive,
            source_image_inspect=expected,
            destination_image_inspect=expected,
            remaining_transfer_bytes=4096,
        )
        assert response["next_stage"] == "BUILD_WORKER_DISPOSED"
        assert response["runtime_enforcement_proven"] is False


def test_journal_image_transfer_rejects_drift_and_retains_unknown(tmp_path: Path):
    i = identity()
    a, b = tmp_path / "source", tmp_path / "dest"
    a.write_bytes(b"one")
    b.write_bytes(b"two")
    img = {"Id": "sha256:" + SHA, "Os": "linux", "Architecture": "amd64"}
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as j:
        for stage in _STAGES[:2]:
            advance(j, stage)
        from p4_image_handover import HandoverUnknown

        with pytest.raises(HandoverUnknown):
            j.reconcile_staged_image_archive(
                operation_id="bounded-image-transfer",
                source_archive=a,
                destination_archive=b,
                source_image_inspect=img,
                destination_image_inspect=img,
                remaining_transfer_bytes=4096,
            )
    recovery = PipelineJournal.inspect_recovery(path, i)
    assert recovery["remote_operation_unresolved"] is True
    assert recovery["source_journal_schema_version"] == 2


def test_recovery_persists_reserved_output_on_lost_reply(tmp_path: Path):
    i = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as j:
        with pytest.raises(TimeoutError):
            j.advance(
                _STAGES[0],
                operation_id="lost-after-reservation",
                mutate=lambda: (_ for _ in ()).throw(TimeoutError("lost ack")),
                observe=lambda _: b"{}",
                output_bytes=16384,
            )
        assert j.bytes_accounted == 16384
    recovery = PipelineJournal.inspect_recovery(path, i)
    assert recovery["durable_output_bytes_accounted"] == 16384
    assert recovery["remote_operation_unresolved"] is True


def test_comparison_is_ordered_after_cleanup(tmp_path: Path):
    i = identity()
    with PipelineJournal(
        tmp_path / "owned-p4-attempt-a.jsonl", i, deadline=time.monotonic() + 500
    ) as j:
        for stage in _STAGES[: _STAGES.index("CLEANUP_RECONCILED")]:
            advance(j, stage)
        with pytest.raises(JournalUnknown, match="requires reconciled cleanup"):
            j.compare_saved_run_after_cleanup(
                operation_id="early-compare",
                authority_raw=b"{}",
                policy_raw=b"{}",
                reference_dir=tmp_path,
                candidate_dir=tmp_path,
                stage_handoff={},
                subject={},
                runtime_evidence={},
            )
        advance(j, "CLEANUP_RECONCILED")
        import importlib.util

        if importlib.util.find_spec("mcp") is None:
            # Offline source sandbox lacks the published MCP SDK. The real
            # comparator is exercised by the installed-package Mac/CI suite.
            assert j.stage_index == _STAGES.index("SAVED_RUN_COMPARED")
            return
        from p4_reference_bridge import P4BridgeError

        with pytest.raises(P4BridgeError):
            j.compare_saved_run_after_cleanup(
                operation_id="after-cleanup-compare",
                authority_raw=b"{}",
                policy_raw=b"{}",
                reference_dir=tmp_path,
                candidate_dir=tmp_path,
                stage_handoff={},
                subject={},
                runtime_evidence={},
            )
        assert j.unknown is True


def test_recovery_preserves_historical_v1_with_no_runtime_authority(tmp_path: Path):
    """R33 order remains readable as history, not a new startup permission."""
    i = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as journal:
        for stage in _STAGES[:5]:
            advance(journal, stage)
    original = [json.loads(line) for line in path.read_text().splitlines()]
    prior = "0" * 64
    legacy = []
    for row in original:
        row["schema_version"] = 1
        if row["status"] == "INTENT":
            del row["details"]["reserved_output_bytes"]
        row["prior_sha256"] = prior
        row.pop("digest")
        prior = hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        row["digest"] = prior
        legacy.append(row)
    path.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in legacy))
    recovered = PipelineJournal.inspect_recovery(path, i)
    assert recovered["source_journal_schema_version"] == 1
    assert recovered["stages_observed"] == 5
    assert recovered["historical_receipts_are_startup_authority"] is False


def test_recovery_rejects_rehashed_worker_drift(tmp_path: Path):
    i = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as journal:
        advance(journal, _STAGES[0], modify=None)
    rows = [json.loads(x) for x in path.read_text().splitlines()]
    rows[1]["details"]["worker"] = "f" * 64
    prev = "0" * 64
    for row in rows:
        row["prior_sha256"] = prev
        row.pop("digest")
        prev = hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        row["digest"] = prev
    path.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in rows))
    with pytest.raises(JournalUnknown, match="unbound remote mutation"):
        PipelineJournal.inspect_recovery(path, i)


def test_recovery_rejects_rehashed_output_budget_overdraw(tmp_path: Path):
    i = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 500) as journal:
        advance(journal, _STAGES[0])
    rows = [json.loads(x) for x in path.read_text().splitlines()]
    rows[1]["details"]["reserved_output_bytes"] = 1_048_577
    prev = "0" * 64
    for row in rows:
        row["prior_sha256"] = prev
        row.pop("digest")
        prev = hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        ).hexdigest()
        row["digest"] = prev
    path.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in rows))
    with pytest.raises(JournalUnknown, match="output allowance exceeded"):
        PipelineJournal.inspect_recovery(path, i)


def _outside_disposal_readback(ident: PipelineIdentity, **mutants: object) -> bytes:
    """Synthetic *external* supervisor fixture, not physical worker proof."""
    obj = {
        "schema_version": 1,
        "worker": ident.build_worker,
        "daemon": ident.build_daemon,
        "worker_alive": False,
        "daemon_alive": False,
        "daemon_socket_present": False,
        "data_root_mounted": False,
        "builder_present": False,
        "cache_entries": 0,
        "scratch_entries": 0,
        "remaining_owned_resources": [],
        "inspection_complete": True,
    }
    obj.update(mutants)
    return json.dumps(obj, sort_keys=True).encode()


def test_journaled_external_disposal_binds_intent_and_two_readbacks(tmp_path: Path):
    i = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 300) as j:
        for previous in _STAGES[:3]:
            advance(j, previous)
        events = []

        def dispose():
            lines = [json.loads(x) for x in path.read_text().splitlines()]
            assert lines[-1]["status"] == "INTENT"
            assert lines[-1]["stage"] == "BUILD_WORKER_DISPOSED"
            events.append("dispose")

        def inspect():
            events.append("outside-readback")
            return _outside_disposal_readback(i)

        receipt = j.reconcile_build_worker_disposal(
            operation_id="outside-disposal",
            dispose_worker=dispose,
            independently_inspect=inspect,
        )
        assert events == ["dispose", "outside-readback", "outside-readback"]
        assert receipt["next_stage"] == "RUNTIME_WORKER_ADMITTED"
        assert receipt["runtime_enforcement_proven"] is False
        assert receipt["approval_outcome"] == "NOT_EVALUATED"
    recovered = PipelineJournal.inspect_recovery(path, i)
    assert recovered["remote_operation_unresolved"] is False
    assert recovered["stages_observed"] == 4


@pytest.mark.parametrize(
    "changed",
    [
        {"worker_alive": True},
        {"daemon_alive": True},
        {"daemon_socket_present": True},
        {"data_root_mounted": True},
        {"builder_present": True},
        {"cache_entries": 1},
        {"scratch_entries": 1},
        {"remaining_owned_resources": ["hidden-cache"]},
        {"worker": "a" * 64},
        {"daemon": "b" * 64},
        {"inspection_complete": False},
        {"cache_entries": False},
    ],
)
def test_external_disposal_refuses_false_cleanup(tmp_path: Path, changed: dict):
    i = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, i, deadline=time.monotonic() + 300) as j:
        for previous in _STAGES[:3]:
            advance(j, previous)
        calls = []

        def dispose():
            calls.append("dispose")

        def inspect():
            calls.append("inspect")
            return _outside_disposal_readback(i, **changed)

        with pytest.raises(JournalUnknown):
            j.reconcile_build_worker_disposal(
                operation_id="failed-disposal",
                dispose_worker=dispose,
                independently_inspect=inspect,
            )
        assert j.unknown and j.pending
        with pytest.raises(JournalUnknown):
            j.reconcile_build_worker_disposal(
                operation_id="retry-disposal",
                dispose_worker=dispose,
                independently_inspect=inspect,
            )
        assert calls == ["dispose", "inspect"]
    assert PipelineJournal.inspect_recovery(path, i)["remote_operation_unresolved"]


def test_external_disposal_drift_and_lost_ack_keep_unknown(tmp_path: Path):
    i = identity()
    for variant in ("second-changes", "lost-ack", "malformed"):
        path = tmp_path / variant / "owned-p4-attempt-a.jsonl"
        path.parent.mkdir()
        with PipelineJournal(path, i, deadline=time.monotonic() + 300) as j:
            for previous in _STAGES[:3]:
                advance(j, previous)
            inspected = 0

            def dispose(variant=variant):
                if variant == "lost-ack":
                    raise TimeoutError("worker gone but acknowledgment lost")

            def inspect(variant=variant):
                nonlocal inspected
                inspected += 1
                if variant == "malformed":
                    return b'{"worker":'
                if variant == "second-changes" and inspected == 2:
                    return _outside_disposal_readback(i, inspection_complete=False)
                return _outside_disposal_readback(i)

            with pytest.raises((JournalUnknown, TimeoutError)):
                j.reconcile_build_worker_disposal(
                    operation_id="uncertain-disposal",
                    dispose_worker=dispose,
                    independently_inspect=inspect,
                )
            assert j.unknown is True
        assert PipelineJournal.inspect_recovery(path, i)["remote_operation_unresolved"] is True


@pytest.mark.parametrize(
    "field,changed",
    [
        ("helper_start_receipts", None),
        ("helper_start_receipts", {}),
        ("helper_descriptors_sha256", None),
        ("candidate_descriptor_sha256", None),
        ("helper_network_descriptors_sha256", {}),
        ("active_network_verified", True),
        ("helper_network_membership_verified_source_only", False),
        ("candidate_started", True),
    ],
)
def test_active_graph_rejects_missing_or_legacy_source_receipt(tmp_path: Path, field, changed):
    i = identity()
    with PipelineJournal(
        tmp_path / "owned-p4-active.jsonl", i, deadline=time.monotonic() + 500
    ) as j:
        for prior in _STAGES[: _STAGES.index("ACTIVE_GRAPH_OBSERVED")]:
            advance(j, prior)

        def mutate(value):
            value[field] = changed

        with pytest.raises(JournalUnknown):
            advance(j, "ACTIVE_GRAPH_OBSERVED", modify=mutate)
        assert j.unknown and j.pending


@pytest.mark.parametrize(
    "stage",
    [
        "BUILD_WORKER_ADMITTED",
        "BUILD_RESULT_OBSERVED",
        "RUNTIME_WORKER_ADMITTED",
    ],
)
def test_early_source_stage_rejects_boolean_only_shortcuts(tmp_path: Path, stage: str):
    ident = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, ident, deadline=time.monotonic() + 500) as journal:
        for prior in _STAGES[: _STAGES.index(stage)]:
            advance(journal, prior)
        op = "shortcut-" + stage.lower().replace("_", "-")
        shortened = {
            key: value
            for key, value in observation(ident, stage, op).items()
            if key
            in {
                "schema_version",
                "attempt_id",
                "operation_id",
                "stage",
                "worker",
                "daemon",
                "runtime_enforcement_proven",
                "approval_outcome",
            }
        }
        shortened["admitted"] = shortened["build_succeeded"] = True
        with pytest.raises(JournalUnknown):
            journal.advance(
                stage,
                operation_id=op,
                mutate=lambda: True,
                observe=lambda _: json.dumps(shortened).encode(),
            )
        assert journal.unknown is True
    assert PipelineJournal.inspect_recovery(path, ident)["remote_operation_unresolved"] is True


@pytest.mark.parametrize(
    "stage,changed_field,wrong",
    [
        ("BUILD_RESULT_OBSERVED", "reviewed_build_spec_sha256", "b" * 64),
        ("IMAGE_TRANSFER_OBSERVED", "source_image_id", "sha256:" + "b" * 64),
        ("RUNTIME_WORKER_ADMITTED", "build_disposal_receipt_sha256", "b" * 64),
        ("RUNTIME_WORKER_ADMITTED", "image_transfer_receipt_sha256", "b" * 64),
        ("RUNTIME_WORKER_ADMITTED", "resolved_image_id", "sha256:" + "b" * 64),
        ("RUNTIME_WORKER_ADMITTED", "private_engine_endpoint_sha256", SHA),
    ],
)
def test_rejects_cross_stage_identity_substitution(
    tmp_path: Path, stage: str, changed_field: str, wrong: str
):
    ident = identity()
    path = tmp_path / "owned-p4-attempt-a.jsonl"
    with PipelineJournal(path, ident, deadline=time.monotonic() + 500) as journal:
        for prior in _STAGES[: _STAGES.index(stage)]:
            advance(journal, prior)
        with pytest.raises(JournalUnknown):
            advance(journal, stage, modify=lambda event: event.update({changed_field: wrong}))
        assert journal.unknown is True
        assert journal.pending is True
    recovered = PipelineJournal.inspect_recovery(path, ident)
    assert recovered["remote_operation_unresolved"] is True
    assert recovered["historical_receipts_are_startup_authority"] is False


def test_runtime_stage_anchors_are_bound_to_current_attempt(tmp_path: Path):
    with PipelineJournal(
        tmp_path / "owned-p4-attempt-a.jsonl", identity(), deadline=time.monotonic() + 500
    ) as journal:
        for stage in _STAGES[: _STAGES.index("CREATED_GRAPH_OBSERVED")]:
            advance(journal, stage)
        links = journal.observed_receipts
        assert (
            links["IMAGE_TRANSFER_OBSERVED"]["source_image_id"]
            == links["BUILD_RESULT_OBSERVED"]["resolved_image_id"]
        )
        assert (
            links["RUNTIME_WORKER_ADMITTED"]["resolved_image_id"]
            == links["IMAGE_TRANSFER_OBSERVED"]["destination_image_id"]
        )
        assert (
            links["BUILD_WORKER_ADMITTED"]["private_engine_endpoint_sha256"]
            != links["RUNTIME_WORKER_ADMITTED"]["private_engine_endpoint_sha256"]
        )
