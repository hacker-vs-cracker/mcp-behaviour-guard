from __future__ import annotations

import importlib.util
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"


def _mod():
    sys.path.insert(0, str(CI))
    try:
        spec = importlib.util.spec_from_file_location(
            "p4_fixture_sqlite_export", CI / "p4_fixture_sqlite_export.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def _fixture(tmp_path: Path):
    from assurance.phase2.fixture.store import FixtureStore

    live = tmp_path / "live"
    live.mkdir(parents=True)
    store = FixtureStore(live / "fixture.db")
    store.bootstrap()
    credential = store.create_attempt("attempt-1")
    store.open_attempt("attempt-1")
    store.business_write(
        credential.token, record_id="record-1", value="synthetic", request_id="request-1"
    )
    store.close_attempt("attempt-1")
    fenced = store.final_snapshot("attempt-1")
    store.finalize_attempt("attempt-1")
    finalized = store.snapshot("attempt-1")
    exported = tmp_path / "exported"
    exported.mkdir()
    # Deterministic logical SQLite snapshot: do not race transient WAL/SHM
    # deletion while copying a live directory. Raw WAL cases need separate coverage.
    with (
        closing(sqlite3.connect(live / "fixture.db")) as source,
        closing(sqlite3.connect(exported / "fixture.db")) as target,
    ):
        source.backup(target)
    return exported, fenced, finalized


def _verify(module, exported, fenced, finalized):
    return module.verify_exported_fixture_sqlite(
        exported_state=exported,
        attempt_id="attempt-1",
        fenced_snapshot=fenced,
        finalized_snapshot=finalized,
        artifact_ceiling_bytes=16_777_216,
    )


def test_consistent_finalized_export_attests_full_sqlite_state(tmp_path: Path):
    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    output = _verify(m, exported, fenced, finalized)
    assert output["status"] == "OFFLINE_SQLITE_RECONCILED_SOURCE_ONLY"
    assert output["runtime_enforcement_proven"] is False
    assert output["verdict_publication_enabled"] is False
    assert output["audit_events"] == output["final_watermark"] == 1
    assert output["requests"] == 1
    assert len(output["export_file_sha256"]["fixture.db"]) == 64


def test_rejects_mismatched_final_watermark_and_request_count(tmp_path: Path):
    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    finalized["attempt"]["final_request_count"] = 2
    with pytest.raises(m.ExportInconsistent):
        _verify(m, exported, fenced, finalized)
    exported, fenced, finalized = _fixture(tmp_path / "again")
    fenced["final_watermark"] = 2
    with pytest.raises(m.ExportInconsistent):
        _verify(m, exported, fenced, finalized)


def test_rejects_data_tamper_even_when_sqlite_integrity_check_passes(tmp_path: Path):
    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    with sqlite3.connect(exported / "fixture.db") as db:
        db.execute("UPDATE audit_events SET event_hash = ?", ("1" * 64,))
    with pytest.raises(m.ExportInconsistent):
        _verify(m, exported, fenced, finalized)


def test_rejects_db_symlink_and_unexpected_files(tmp_path: Path):
    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    (exported / "fixture.db").rename(exported / "real.db")
    (exported / "fixture.db").symlink_to("real.db")
    with pytest.raises(m.ExportInconsistent):
        _verify(m, exported, fenced, finalized)
    (exported / "fixture.db").unlink()
    (exported / "real.db").rename(exported / "fixture.db")
    (exported / "unknown-file").write_bytes(b"payload")
    with pytest.raises(m.ExportInconsistent):
        _verify(m, exported, fenced, finalized)


def test_rejects_export_limit_and_unfinalized_state(tmp_path: Path):
    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    with pytest.raises(m.ExportInconsistent):
        m.verify_exported_fixture_sqlite(
            exported_state=exported,
            attempt_id="attempt-1",
            fenced_snapshot=fenced,
            finalized_snapshot=finalized,
            artifact_ceiling_bytes=1,
        )
    with sqlite3.connect(exported / "fixture.db") as db:
        db.execute("UPDATE attempts SET state='FENCED' WHERE attempt_id='attempt-1'")
    with pytest.raises(m.ExportInconsistent):
        _verify(m, exported, fenced, finalized)


def test_independent_business_projection_rejects_wrong_value_and_attribution(tmp_path: Path):
    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    with sqlite3.connect(exported / "fixture.db") as db:
        expected = [
            dict(
                zip(
                    (
                        "record_id",
                        "value",
                        "updated_by_attempt",
                        "updated_by_request",
                        "updated_at",
                    ),
                    row,
                    strict=True,
                )
            )
            for row in db.execute(
                "SELECT record_id,value,updated_by_attempt,updated_by_request,updated_at "
                "FROM records ORDER BY record_id"
            ).fetchall()
        ]
    assert len(expected) == 1
    output = m.verify_exported_fixture_sqlite(
        exported_state=exported,
        attempt_id="attempt-1",
        fenced_snapshot=fenced,
        finalized_snapshot=finalized,
        artifact_ceiling_bytes=16_777_216,
        reviewed_expected_records=expected,
    )
    assert output["business_effect_status"] == "MATCHED_REVIEWED_PROJECTION_SOURCE_ONLY"
    assert output["source_export_status"] == "NOT_EVALUATED"
    with sqlite3.connect(exported / "fixture.db") as db:
        db.execute("UPDATE records SET value='wrong-business-value'")
    with pytest.raises(m.ExportInconsistent, match="business records"):
        m.verify_exported_fixture_sqlite(
            exported_state=exported,
            attempt_id="attempt-1",
            fenced_snapshot=fenced,
            finalized_snapshot=finalized,
            artifact_ceiling_bytes=16_777_216,
            reviewed_expected_records=expected,
        )
    tampered = [{**expected[0], "updated_by_attempt": "another-attempt"}]
    with pytest.raises(m.ExportInconsistent):
        m.verify_exported_fixture_sqlite(
            exported_state=exported,
            attempt_id="attempt-1",
            fenced_snapshot=fenced,
            finalized_snapshot=finalized,
            artifact_ceiling_bytes=16_777_216,
            reviewed_expected_records=tampered,
        )


def test_independent_fenced_source_fingerprint_must_match(tmp_path: Path):
    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    with pytest.raises(m.ExportInconsistent, match="fenced source/export"):
        m.verify_exported_fixture_sqlite(
            exported_state=exported,
            attempt_id="attempt-1",
            fenced_snapshot=fenced,
            finalized_snapshot=finalized,
            artifact_ceiling_bytes=16_777_216,
            observed_fenced_file_sha256={"fixture.db": "0" * 64},
        )
    output = _verify(m, exported, fenced, finalized)
    assert output["business_effect_status"] == "NOT_EVALUATED"
    assert output["source_export_status"] == "NOT_EVALUATED"


def test_bounded_sqlite_rejects_expired_outer_deadline(tmp_path: Path):
    import time

    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    with pytest.raises(m.ExportInconsistent, match="admission invalid"):
        m.verify_exported_fixture_sqlite(
            exported_state=exported,
            attempt_id="attempt-1",
            fenced_snapshot=fenced,
            finalized_snapshot=finalized,
            artifact_ceiling_bytes=16_777_216,
            original_deadline_monotonic=time.monotonic() - 1,
        )


def test_bounded_sqlite_rejects_more_than_1024_business_rows(tmp_path: Path):
    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    with sqlite3.connect(exported / "fixture.db") as db:
        db.executemany(
            "INSERT INTO records "
            "(record_id,value,updated_by_attempt,updated_by_request,updated_at) "
            "VALUES(?,?,?,?,?)",
            [(f"extra-{x:04d}", "value", "attempt-1", "request-1", "now") for x in range(1025)],
        )
    with pytest.raises(m.ExportInconsistent, match="bounded SQLite result rows"):
        _verify(m, exported, fenced, finalized)


def test_committed_wal_only_business_effect_is_read_and_torn_wal_rejected(tmp_path: Path):
    """A stable logical fixture must not erase coverage for real WAL-backed exports."""
    import hashlib
    import shutil

    m = _mod()
    exported, fenced, finalized = _fixture(tmp_path)
    wal_source = exported / "fixture.db"
    raw_export = tmp_path / "raw-wal-export"
    raw_export.mkdir()
    with closing(sqlite3.connect(wal_source)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("UPDATE records SET value = 'committed-only-in-wal'")
        writer.commit()
        assert (exported / "fixture.db-wal").stat().st_size > 32
        # No mutations occur during this copy; the writer stays open to prevent
        # SQLite from checkpointing/deleting the WAL on final close.
        for name in ("fixture.db", "fixture.db-wal", "fixture.db-shm"):
            file = exported / name
            if file.exists():
                shutil.copy2(file, raw_export / name)
        columns = ("record_id", "value", "updated_by_attempt", "updated_by_request", "updated_at")
        expected = [
            dict(zip(columns, row, strict=True))
            for row in writer.execute(
                "SELECT record_id,value,updated_by_attempt,updated_by_request,updated_at "
                "FROM records ORDER BY record_id"
            ).fetchall()
        ]
    assert expected[0]["value"] == "committed-only-in-wal"
    # Snapshot a torn variant before SQLite itself can checkpoint a readonly WAL.
    torn = tmp_path / "torn-wal-export"
    torn.mkdir()
    for item in raw_export.iterdir():
        shutil.copy2(item, torn / item.name)
    wal = torn / "fixture.db-wal"
    assert wal.exists()
    wal.write_bytes(wal.read_bytes()[:-1])
    hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in raw_export.iterdir()
    }
    verified = m.verify_exported_fixture_sqlite(
        exported_state=raw_export,
        attempt_id="attempt-1",
        fenced_snapshot=fenced,
        finalized_snapshot=finalized,
        artifact_ceiling_bytes=16_777_216,
        observed_fenced_file_sha256=hashes,
        reviewed_expected_records=expected,
    )
    assert verified["source_export_status"] == "MATCHED_FENCED_SOURCE_DIGESTS_SOURCE_ONLY"
    assert verified["business_effect_status"] == "MATCHED_REVIEWED_PROJECTION_SOURCE_ONLY"
    with pytest.raises(m.ExportInconsistent, match="fenced source/export"):
        m.verify_exported_fixture_sqlite(
            exported_state=torn,
            attempt_id="attempt-1",
            fenced_snapshot=fenced,
            finalized_snapshot=finalized,
            artifact_ceiling_bytes=16_777_216,
            observed_fenced_file_sha256=hashes,
            reviewed_expected_records=expected,
        )
