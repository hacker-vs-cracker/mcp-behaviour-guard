from __future__ import annotations

import importlib.util
import shutil
import sqlite3
import sys
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
    shutil.copytree(live, exported)
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
