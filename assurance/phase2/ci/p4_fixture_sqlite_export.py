"""Read-only reconciliation of a *previously fenced and exported* P4 fixture DB.

This module does not grant runtime authority. Its caller must first attest the
five-role run, writer fencing, source volume, archive transport and provenance.
A SQLite copy without those external proofs is not sufficient for promotion.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from p4_control_audit import ControlUnknown, audit_evidence_digest

from assurance.phase2.fixture.store import FixtureStore


class ExportInconsistent(RuntimeError):
    """Exported database does not agree with the finalized control transcript."""


_ATTEMPT = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_ALLOWED = {"fixture.db", "fixture.db-wal", "fixture.db-shm"}
_TERMINAL = {"COMMITTED", "REJECTED", "ROLLED_BACK", "FAILED"}


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _snapshot_files(source: Path, destination: Path, ceiling: int) -> dict[str, str]:
    """Pin regular inode identity and bytes before/after copying a bounded export.

    Does not by itself prove that an external writer is fenced; the controller
    must separately provide that evidence. A source mutation makes this UNKNOWN.
    """
    if source.is_symlink() or not source.is_dir():
        raise ExportInconsistent("export source must be an ordinary directory")
    entries = sorted(source.iterdir())
    if not entries or {p.name for p in entries} - _ALLOWED or not (source / "fixture.db").exists():
        raise ExportInconsistent("fixture database export contains unexpected paths")
    fingerprints: dict[str, str] = {}
    total = 0
    for item in entries:
        before = item.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_size <= 0 and item.name == "fixture.db")
            or before.st_size > ceiling
        ):
            raise ExportInconsistent("exported fixture file is linked, empty or oversized")
        total += before.st_size
        if total > ceiling:
            raise ExportInconsistent("export exceeds frozen artifact budget")
        # No followed symlinks, even if the name is swapped after the lstat.
        fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ) or opened.st_nlink != 1:
                raise ExportInconsistent("fixture export inode changed before read")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    raise ExportInconsistent("fixture export was truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            named = item.lstat()
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) or (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ):
                raise ExportInconsistent("fixture export changed during read")
            (destination / item.name).write_bytes(raw)
            fingerprints[item.name] = _hash(raw)
        finally:
            os.close(fd)
    if sorted(p.name for p in source.iterdir()) != sorted(fingerprints):
        raise ExportInconsistent("fixture export entries changed during read")
    return fingerprints


def verify_exported_fixture_sqlite(
    *,
    exported_state: Path,
    attempt_id: str,
    fenced_snapshot: dict[str, Any],
    finalized_snapshot: dict[str, Any],
    artifact_ceiling_bytes: int,
    reviewed_expected_records: list[dict[str, Any]] | None = None,
    observed_fenced_file_sha256: dict[str, str] | None = None,
    original_deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Cross-check finalized control RPC evidence with a self-consistent SQLite backup.

    Expected `exported_state` is the already extracted /state directory from
    independently attested paused container export, not an arbitrary live volume.
    No writes to `exported_state`; all SQLite operations use a private copy.
    Never call this after an unknown source export or without writer fencing.
    The optional independently reviewed projection is not inferred from the
    exported DB. The optional source file digests must be independently observed
    by the trusted, already-fenced coordinator, not copied from this export.
    Without those authorities, outcomes are explicitly NOT_EVALUATED.
    """
    if (
        not isinstance(exported_state, Path)
        or type(attempt_id) is not str
        or _ATTEMPT.fullmatch(attempt_id) is None
        or type(artifact_ceiling_bytes) is not int
        or not 0 < artifact_ceiling_bytes <= 16_777_216
        or (
            original_deadline_monotonic is not None
            and (
                type(original_deadline_monotonic) is not float
                or not time.monotonic() < original_deadline_monotonic <= time.monotonic() + 600
            )
        )
    ):
        raise ExportInconsistent("export admission invalid")
    try:
        transcript = audit_evidence_digest(
            final_snapshot=fenced_snapshot,
            finalized_attempt=finalized_snapshot,
            attempt_id=attempt_id,
        )
    except ControlUnknown as exc:
        raise ExportInconsistent("fenced/finalized control transcript invalid") from exc
    # The original coordinator deadline is not reset at export. Offline callers
    # use a tighter local window without manufacturing native time authority.
    until = min(time.monotonic() + 60, original_deadline_monotonic or float("inf"))

    def time_left() -> None:
        if time.monotonic() >= until:
            raise ExportInconsistent("bounded SQLite reconciliation deadline exceeded")

    def rows_bounded(
        db: sqlite3.Connection, statement: str, args: tuple[str, ...] = ()
    ) -> list[sqlite3.Row]:
        time_left()
        cursor = db.execute(statement, args)
        result = cursor.fetchmany(1025)
        if len(result) > 1024:
            raise ExportInconsistent("bounded SQLite result rows exceed frozen JSON array limit")
        time_left()
        return result

    try:
        with tempfile.TemporaryDirectory(prefix="mcpbg-p4-sqlite-") as stage:
            private = Path(stage)
            files = _snapshot_files(exported_state, private, artifact_ceiling_bytes)
            time_left()
            if observed_fenced_file_sha256 is not None and (
                type(observed_fenced_file_sha256) is not dict
                or observed_fenced_file_sha256 != files
                or any(
                    type(x) is not str or re.fullmatch(r"[0-9a-f]{64}", x) is None
                    for x in observed_fenced_file_sha256.values()
                )
            ):
                raise ExportInconsistent("fenced source/export byte identity mismatch")
            # A read-only SQLite connection sees committed WAL frames. We never
            # use immutable=1, which silently ignores WAL content.
            uri = (private / "fixture.db").as_uri() + "?mode=ro"
            with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=1)) as read_db:
                read_db.row_factory = sqlite3.Row
                read_db.set_progress_handler(lambda: int(time.monotonic() >= until), 1000)
                read_db.execute("PRAGMA trusted_schema = OFF")
                read_db.execute("PRAGMA query_only = ON")
                # Check the WAL-aware logical image before allocating the backup.
                # The compressed file ceiling is not a bound on expanded pages.
                source_page_size = rows_bounded(read_db, "PRAGMA page_size")[0][0]
                source_page_count = rows_bounded(read_db, "PRAGMA page_count")[0][0]
                if source_page_size * source_page_count > artifact_ceiling_bytes:
                    raise ExportInconsistent("expanded SQLite memory exceeds artifact cap")
                with contextlib.closing(sqlite3.connect(":memory:")) as snapshot:
                    snapshot.row_factory = sqlite3.Row
                    snapshot.set_progress_handler(lambda: int(time.monotonic() >= until), 1000)
                    snapshot.execute("PRAGMA trusted_schema = OFF")

                    def backup_progress(_status: int, _remaining: int, _total: int) -> None:
                        time_left()

                    read_db.backup(snapshot, pages=32, progress=backup_progress, sleep=0)
                    size_rows = rows_bounded(snapshot, "PRAGMA page_size")
                    page_rows = rows_bounded(snapshot, "PRAGMA page_count")
                    if (
                        len(size_rows) != 1
                        or len(page_rows) != 1
                        or size_rows[0][0] * page_rows[0][0] > artifact_ceiling_bytes
                    ):
                        raise ExportInconsistent("expanded SQLite memory exceeds artifact cap")
                    checks = rows_bounded(snapshot, "PRAGMA integrity_check")
                    if len(checks) != 1 or checks[0][0] != "ok":
                        raise ExportInconsistent("exported SQLite integrity check failed")
                    if snapshot.execute("PRAGMA foreign_key_check").fetchone() is not None:
                        raise ExportInconsistent("exported SQLite foreign key check failed")
                    attempt = snapshot.execute(
                        "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
                    ).fetchone()
                    if attempt is None:
                        raise ExportInconsistent("finalized attempt absent from exported database")
                    record = dict(attempt)
                    controls = finalized_snapshot["attempt"]
                    if (
                        record != controls
                        or record["state"] != "FINALIZED"
                        or record["audit_complete"] != 1
                        or type(record["final_watermark"]) is not int
                        or record["final_watermark"] != record["audit_watermark"]
                        or type(record["final_request_count"]) is not int
                    ):
                        raise ExportInconsistent(
                            "finalized SQLite attempt differs from control state"
                        )
                    active = snapshot.execute(
                        "SELECT active_attempt_id FROM fixture_meta WHERE singleton_id = 1"
                    ).fetchone()
                    if active is None or active[0] is not None:
                        raise ExportInconsistent("fixture still has an active attempt")
                    requests = [
                        dict(x)
                        for x in rows_bounded(
                            snapshot,
                            "SELECT * FROM requests WHERE attempt_id = ? "
                            "ORDER BY created_at, request_id",
                            (attempt_id,),
                        )
                    ]
                    audit_rows = rows_bounded(
                        snapshot,
                        "SELECT * FROM audit_events WHERE attempt_id = ? ORDER BY seq",
                        (attempt_id,),
                    )
                    audit = [dict(x) for x in audit_rows]
                    if (
                        requests != finalized_snapshot["requests"]
                        or audit != finalized_snapshot["audit"]
                        or requests != fenced_snapshot["requests"]
                        or any(x["state"] not in _TERMINAL for x in requests)
                        or len(requests) != record["final_request_count"]
                        or len(audit) != record["final_watermark"]
                    ):
                        raise ExportInconsistent("SQLite request/audit transcript drift")
                    # Reuse the fixture's audited hash-chain validator instead of
                    # maintaining a potentially divergent second implementation.
                    FixtureStore(private / "fixture.db")._validate_ledger(attempt, audit_rows)
                    rows = rows_bounded(
                        snapshot,
                        "SELECT record_id,value,updated_by_attempt,updated_by_request,updated_at "
                        "FROM records ORDER BY record_id",
                    )
                    actual_records = [dict(x) for x in rows]
                    record_digest = _hash(_canonical({"records": actual_records}))
                    effect_status = "NOT_EVALUATED"
                    if reviewed_expected_records is not None:
                        fields = {
                            "record_id",
                            "value",
                            "updated_by_attempt",
                            "updated_by_request",
                            "updated_at",
                        }
                        if (
                            type(reviewed_expected_records) is not list
                            or any(
                                type(x) is not dict or set(x) != fields
                                for x in reviewed_expected_records
                            )
                            or len(reviewed_expected_records) > 1024
                        ):
                            raise ExportInconsistent("reviewed business projection malformed")
                        # Exact equality covers wrong values, missing/extra records,
                        # attribution and timestamp claims, without trusting the
                        # exported rows to define their own expected state.
                        if actual_records != sorted(
                            reviewed_expected_records, key=lambda x: x["record_id"]
                        ):
                            raise ExportInconsistent(
                                "business records differ from reviewed expectation"
                            )
                        effect_status = "MATCHED_REVIEWED_PROJECTION_SOURCE_ONLY"
                    return {
                        "schema_version": 1,
                        "status": "OFFLINE_SQLITE_RECONCILED_SOURCE_ONLY",
                        "attempt_id": attempt_id,
                        "fenced_snapshot_sha256": transcript["fenced_snapshot_sha256"],
                        "finalized_attempt_sha256": transcript["finalized_attempt_sha256"],
                        "export_file_sha256": files,
                        "audit_events": len(audit),
                        "requests": len(requests),
                        "final_watermark": record["final_watermark"],
                        "records_sha256": record_digest,
                        "business_effect_status": effect_status,
                        "source_export_status": (
                            "MATCHED_FENCED_SOURCE_DIGESTS_SOURCE_ONLY"
                            if observed_fenced_file_sha256 is not None
                            else "NOT_EVALUATED"
                        ),
                        "runtime_enforcement_proven": False,
                        "verdict_publication_enabled": False,
                    }
    except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        raise ExportInconsistent("exported SQLite reconciliation UNKNOWN") from exc
