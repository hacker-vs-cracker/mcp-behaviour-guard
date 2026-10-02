from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

_ATTEMPT_STATES = {"PREPARED", "OPEN", "FENCED", "FINALIZED", "ABORTED", "RECOVERY_REQUIRED"}
_REQUEST_TERMINAL = {"COMMITTED", "REJECTED", "ROLLED_BACK", "FAILED"}
_REQUEST_STATES = _REQUEST_TERMINAL | {"ADMITTED"}
_ZERO_HASH = "0" * 64


class FixtureError(RuntimeError):
    """Base error for the trusted synthetic fixture."""


class ActiveAttemptExists(FixtureError):
    pass


class InvalidAttemptState(FixtureError):
    pass


class InvalidCredential(FixtureError):
    pass


class StaleCredential(FixtureError):
    pass


class RequestConflict(FixtureError):
    pass


class DrainIncomplete(FixtureError):
    pass


class LedgerIntegrityError(FixtureError):
    pass


class InjectedFixtureFault(FixtureError):
    pass


class SimulatedResponseLoss(FixtureError):
    pass


@dataclass(frozen=True, slots=True)
class AttemptCredential:
    attempt_id: str
    token: str


@dataclass(frozen=True, slots=True)
class WriteResult:
    attempt_id: str
    request_id: str
    state: Literal["COMMITTED", "REJECTED"]
    committed: bool
    audit_seq: int | None


@dataclass(slots=True)
class WriteBarrier:
    """Deterministic test-only barrier; never exposed by the HTTP data plane."""

    stage: Literal["before_transaction", "after_write_lock"]
    reached: threading.Event
    release: threading.Event
    timeout_seconds: float = 5.0

    def wait(self, stage: str) -> None:
        if self.stage != stage:
            return
        self.reached.set()
        if not self.release.wait(self.timeout_seconds):
            raise TimeoutError(f"write barrier timed out at {stage}")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class FixtureStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def bootstrap(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    credential_sha256 TEXT NOT NULL UNIQUE,
                    principal TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    opened_at TEXT,
                    fenced_at TEXT,
                    finalized_at TEXT,
                    audit_watermark INTEGER NOT NULL DEFAULT 0,
                    final_watermark INTEGER,
                    final_request_count INTEGER,
                    audit_complete INTEGER NOT NULL DEFAULT 0,
                    CHECK (state IN ('PREPARED','OPEN','FENCED','FINALIZED','ABORTED','RECOVERY_REQUIRED')),
                    CHECK (audit_complete IN (0,1))
                );

                CREATE TABLE IF NOT EXISTS fixture_meta (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    active_attempt_id TEXT REFERENCES attempts(attempt_id)
                );

                INSERT OR IGNORE INTO fixture_meta(singleton_id, active_attempt_id)
                VALUES (1, NULL);

                CREATE TABLE IF NOT EXISTS requests (
                    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
                    request_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    state TEXT NOT NULL,
                    asserted_attempt_id TEXT,
                    asserted_principal TEXT,
                    created_at TEXT NOT NULL,
                    finished_at TEXT,
                    rejection_reason TEXT,
                    PRIMARY KEY (attempt_id, request_id),
                    CHECK (state IN ('ADMITTED','COMMITTED','REJECTED','ROLLED_BACK','FAILED'))
                );

                CREATE TABLE IF NOT EXISTS records (
                    record_id TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_by_attempt TEXT NOT NULL REFERENCES attempts(attempt_id),
                    updated_by_request TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
                    seq INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    PRIMARY KEY (attempt_id, seq)
                );

                CREATE TABLE IF NOT EXISTS observer_cursors (
                    attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
                    cursor_seq INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            self._begin_immediate(connection)
            try:
                active = self._active_attempt_id(connection)
                if active is not None:
                    row = connection.execute(
                        "SELECT state FROM attempts WHERE attempt_id = ?", (active,)
                    ).fetchone()
                    if row is None:
                        raise FixtureError(f"active attempt record is missing: {active}")
                    state = str(row["state"])
                    if state in {"PREPARED", "OPEN", "FENCED"}:
                        connection.execute(
                            """
                            UPDATE attempts
                            SET state = 'RECOVERY_REQUIRED',
                                audit_complete = 0,
                                final_watermark = NULL,
                                final_request_count = NULL
                            WHERE attempt_id = ?
                            """,
                            (active,),
                        )
                    elif state in {"FINALIZED", "ABORTED"}:
                        connection.execute(
                            "UPDATE fixture_meta SET active_attempt_id = NULL WHERE singleton_id = 1"
                        )
                    elif state != "RECOVERY_REQUIRED":
                        raise FixtureError(
                            f"unexpected active attempt state during bootstrap: {state}"
                        )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    @staticmethod
    def _begin_immediate(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _active_attempt_id(connection: sqlite3.Connection) -> str | None:
        row = connection.execute(
            "SELECT active_attempt_id FROM fixture_meta WHERE singleton_id = 1"
        ).fetchone()
        return None if row is None else row["active_attempt_id"]

    def active_attempt_id(self) -> str | None:
        with self._connect() as connection:
            return self._active_attempt_id(connection)

    def create_attempt(self, attempt_id: str | None = None) -> AttemptCredential:
        attempt = attempt_id or uuid.uuid4().hex
        token = secrets.token_urlsafe(32)
        now = _utc_now()
        with self._connect() as connection:
            self._begin_immediate(connection)
            try:
                active = self._active_attempt_id(connection)
                if active is not None:
                    raise ActiveAttemptExists(f"active attempt already exists: {active}")
                connection.execute(
                    """
                    INSERT INTO attempts(
                        attempt_id, credential_sha256, principal, state, created_at
                    ) VALUES (?, ?, 'candidate_app', 'PREPARED', ?)
                    """,
                    (attempt, _sha256_text(token), now),
                )
                connection.execute(
                    "INSERT INTO observer_cursors(attempt_id, cursor_seq) VALUES (?, 0)",
                    (attempt,),
                )
                connection.execute(
                    "UPDATE fixture_meta SET active_attempt_id = ? WHERE singleton_id = 1",
                    (attempt,),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return AttemptCredential(attempt_id=attempt, token=token)

    def open_attempt(self, attempt_id: str) -> None:
        with self._connect() as connection:
            self._begin_immediate(connection)
            try:
                self._require_active_state(connection, attempt_id, "PREPARED")
                connection.execute(
                    "UPDATE attempts SET state = 'OPEN', opened_at = ? WHERE attempt_id = ?",
                    (_utc_now(), attempt_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def close_attempt(self, attempt_id: str) -> None:
        with self._connect() as connection:
            self._begin_immediate(connection)
            try:
                self._require_active_state(connection, attempt_id, "OPEN")
                connection.execute(
                    "UPDATE attempts SET state = 'FENCED', fenced_at = ? WHERE attempt_id = ?",
                    (_utc_now(), attempt_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def abort_recovery(self, attempt_id: str) -> None:
        with self._connect() as connection:
            self._begin_immediate(connection)
            try:
                self._require_active_state(connection, attempt_id, "RECOVERY_REQUIRED")
                now = _utc_now()
                connection.execute(
                    """
                    UPDATE requests
                    SET state = 'FAILED',
                        finished_at = COALESCE(finished_at, ?),
                        rejection_reason = COALESCE(rejection_reason, 'recovery_abort')
                    WHERE attempt_id = ? AND state = 'ADMITTED'
                    """,
                    (now, attempt_id),
                )
                connection.execute(
                    """
                    UPDATE attempts
                    SET state = 'ABORTED',
                        audit_complete = 0,
                        final_watermark = NULL,
                        final_request_count = NULL
                    WHERE attempt_id = ?
                    """,
                    (attempt_id,),
                )
                connection.execute(
                    "UPDATE fixture_meta SET active_attempt_id = NULL WHERE singleton_id = 1"
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _require_active_state(
        self,
        connection: sqlite3.Connection,
        attempt_id: str,
        expected: str,
    ) -> sqlite3.Row:
        active = self._active_attempt_id(connection)
        if active != attempt_id:
            raise InvalidAttemptState(
                f"attempt {attempt_id} is not the active attempt (active={active!r})"
            )
        row = connection.execute(
            "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None or row["state"] != expected:
            actual = None if row is None else row["state"]
            raise InvalidAttemptState(
                f"attempt {attempt_id} state is {actual!r}, expected {expected!r}"
            )
        return row

    def _attempt_for_token(
        self,
        connection: sqlite3.Connection,
        token: str,
    ) -> sqlite3.Row:
        token_hash = _sha256_text(token)
        row = connection.execute(
            "SELECT * FROM attempts WHERE credential_sha256 = ?", (token_hash,)
        ).fetchone()
        if row is None:
            raise InvalidCredential("candidate credential is invalid")
        active = self._active_attempt_id(connection)
        if row["attempt_id"] != active:
            raise StaleCredential(f"credential belongs to non-active attempt {row['attempt_id']}")
        return row

    def _audit_event_payload(
        self,
        *,
        attempt_id: str,
        seq: int,
        event_id: str,
        kind: str,
        request_id: str,
        operation: str,
        principal: str,
        details_json: str,
        created_at: str,
        prev_hash: str,
    ) -> dict[str, Any]:
        return {
            "attempt_id": attempt_id,
            "seq": seq,
            "event_id": event_id,
            "kind": kind,
            "request_id": request_id,
            "operation": operation,
            "principal": principal,
            "details_json": details_json,
            "created_at": created_at,
            "prev_hash": prev_hash,
        }

    def _append_audit_event(
        self,
        connection: sqlite3.Connection,
        *,
        attempt_id: str,
        request_id: str,
        operation: str,
        principal: str,
        details: dict[str, Any],
    ) -> int:
        attempt = connection.execute(
            "SELECT audit_watermark FROM attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if attempt is None:
            raise FixtureError(f"attempt disappeared: {attempt_id}")
        seq = int(attempt["audit_watermark"]) + 1
        previous = connection.execute(
            "SELECT event_hash FROM audit_events WHERE attempt_id = ? AND seq = ?",
            (attempt_id, seq - 1),
        ).fetchone()
        prev_hash = _ZERO_HASH if previous is None else str(previous["event_hash"])
        event_id = uuid.uuid4().hex
        created_at = _utc_now()
        details_json = _canonical_json(details)
        payload = self._audit_event_payload(
            attempt_id=attempt_id,
            seq=seq,
            event_id=event_id,
            kind="database_write",
            request_id=request_id,
            operation=operation,
            principal=principal,
            details_json=details_json,
            created_at=created_at,
            prev_hash=prev_hash,
        )
        event_hash = _sha256_text(_canonical_json(payload))
        connection.execute(
            """
            INSERT INTO audit_events(
                attempt_id, seq, event_id, kind, request_id, operation, principal,
                details_json, created_at, prev_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                seq,
                event_id,
                "database_write",
                request_id,
                operation,
                principal,
                details_json,
                created_at,
                prev_hash,
                event_hash,
            ),
        )
        connection.execute(
            "UPDATE attempts SET audit_watermark = ? WHERE attempt_id = ?",
            (seq, attempt_id),
        )
        return seq

    def business_write(
        self,
        token: str,
        *,
        record_id: str,
        value: str,
        request_id: str | None = None,
        asserted_attempt_id: str | None = None,
        asserted_principal: str | None = None,
        barrier: WriteBarrier | None = None,
        fault: Literal["audit_failure", "crash_before_commit", "response_loss"] | None = None,
    ) -> WriteResult:
        request = request_id or uuid.uuid4().hex
        if barrier is not None:
            barrier.wait("before_transaction")

        response: WriteResult
        with self._connect() as connection:
            self._begin_immediate(connection)
            try:
                if barrier is not None:
                    barrier.wait("after_write_lock")
                attempt = self._attempt_for_token(connection, token)
                attempt_id = str(attempt["attempt_id"])
                principal = str(attempt["principal"])
                now = _utc_now()
                existing = connection.execute(
                    "SELECT state FROM requests WHERE attempt_id = ? AND request_id = ?",
                    (attempt_id, request),
                ).fetchone()
                if existing is not None:
                    raise RequestConflict(
                        f"request id already exists for attempt {attempt_id}: {request}"
                    )

                if attempt["state"] != "OPEN":
                    connection.execute(
                        """
                        INSERT INTO requests(
                            attempt_id, request_id, operation, state,
                            asserted_attempt_id, asserted_principal,
                            created_at, finished_at, rejection_reason
                        ) VALUES (?, ?, 'record_write', 'REJECTED', ?, ?, ?, ?, ?)
                        """,
                        (
                            attempt_id,
                            request,
                            asserted_attempt_id,
                            asserted_principal,
                            now,
                            now,
                            f"attempt_state={attempt['state']}",
                        ),
                    )
                    connection.commit()
                    return WriteResult(
                        attempt_id=attempt_id,
                        request_id=request,
                        state="REJECTED",
                        committed=False,
                        audit_seq=None,
                    )

                connection.execute(
                    """
                    INSERT INTO requests(
                        attempt_id, request_id, operation, state,
                        asserted_attempt_id, asserted_principal, created_at
                    ) VALUES (?, ?, 'record_write', 'ADMITTED', ?, ?, ?)
                    """,
                    (attempt_id, request, asserted_attempt_id, asserted_principal, now),
                )
                connection.execute(
                    """
                    INSERT INTO records(
                        record_id, value, updated_by_attempt, updated_by_request, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(record_id) DO UPDATE SET
                        value = excluded.value,
                        updated_by_attempt = excluded.updated_by_attempt,
                        updated_by_request = excluded.updated_by_request,
                        updated_at = excluded.updated_at
                    """,
                    (record_id, value, attempt_id, request, now),
                )
                if fault == "audit_failure":
                    raise InjectedFixtureFault("injected audit failure before audit insert")

                seq = self._append_audit_event(
                    connection,
                    attempt_id=attempt_id,
                    request_id=request,
                    operation="record_write",
                    principal=principal,
                    details={
                        "record_id": record_id,
                        "asserted_attempt_id": asserted_attempt_id,
                        "asserted_principal": asserted_principal,
                    },
                )
                connection.execute(
                    """
                    UPDATE requests
                    SET state = 'COMMITTED', finished_at = ?
                    WHERE attempt_id = ? AND request_id = ?
                    """,
                    (_utc_now(), attempt_id, request),
                )
                if fault == "crash_before_commit":
                    raise InjectedFixtureFault("injected crash before commit")
                connection.commit()
                response = WriteResult(
                    attempt_id=attempt_id,
                    request_id=request,
                    state="COMMITTED",
                    committed=True,
                    audit_seq=seq,
                )
            except Exception:
                connection.rollback()
                raise

        if fault == "response_loss":
            raise SimulatedResponseLoss("simulated response loss after durable commit")
        return response

    def read_record(self, token: str, record_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            attempt = self._attempt_for_token(connection, token)
            if attempt["state"] != "OPEN":
                raise InvalidAttemptState(f"read rejected because attempt is {attempt['state']}")
            row = connection.execute(
                "SELECT * FROM records WHERE record_id = ?", (record_id,)
            ).fetchone()
            return None if row is None else dict(row)

    def reset_observer_cursor(self) -> int:
        with self._connect() as connection:
            self._begin_immediate(connection)
            try:
                attempt_id = self._active_attempt_id(connection)
                if attempt_id is None:
                    raise InvalidAttemptState("no active attempt for observer cursor reset")
                row = connection.execute(
                    "SELECT audit_watermark FROM attempts WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
                if row is None:
                    raise FixtureError("active attempt record is missing")
                watermark = int(row["audit_watermark"])
                connection.execute(
                    "UPDATE observer_cursors SET cursor_seq = ? WHERE attempt_id = ?",
                    (watermark, attempt_id),
                )
                connection.commit()
                return watermark
            except Exception:
                connection.rollback()
                raise

    def observer_events(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            attempt_id = self._active_attempt_id(connection)
            if attempt_id is None:
                raise InvalidAttemptState("no active attempt for observer event collection")
            cursor = connection.execute(
                "SELECT cursor_seq FROM observer_cursors WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if cursor is None:
                raise FixtureError("observer cursor is missing")
            rows = connection.execute(
                """
                SELECT * FROM audit_events
                WHERE attempt_id = ? AND seq > ?
                ORDER BY seq
                """,
                (attempt_id, int(cursor["cursor_seq"])),
            ).fetchall()
            return [self._observer_event(row) for row in rows]

    @staticmethod
    def _observer_event(row: sqlite3.Row) -> dict[str, Any]:
        details = json.loads(row["details_json"])
        return {
            "kind": row["kind"],
            "seq": row["seq"],
            "event_id": row["event_id"],
            "request_id": row["request_id"],
            "operation": row["operation"],
            "principal": row["principal"],
            **details,
        }

    def _validate_ledger(
        self,
        attempt: sqlite3.Row,
        rows: list[sqlite3.Row],
    ) -> None:
        watermark = int(attempt["audit_watermark"])
        if len(rows) != watermark:
            raise LedgerIntegrityError(
                f"audit row count {len(rows)} does not match watermark {watermark}"
            )
        previous_hash = _ZERO_HASH
        for expected_seq, row in enumerate(rows, start=1):
            if int(row["seq"]) != expected_seq:
                raise LedgerIntegrityError(
                    f"audit sequence gap/conflict: expected {expected_seq}, got {row['seq']}"
                )
            if row["prev_hash"] != previous_hash:
                raise LedgerIntegrityError(
                    f"audit previous hash mismatch at sequence {expected_seq}"
                )
            payload = self._audit_event_payload(
                attempt_id=row["attempt_id"],
                seq=int(row["seq"]),
                event_id=row["event_id"],
                kind=row["kind"],
                request_id=row["request_id"],
                operation=row["operation"],
                principal=row["principal"],
                details_json=row["details_json"],
                created_at=row["created_at"],
                prev_hash=row["prev_hash"],
            )
            calculated = _sha256_text(_canonical_json(payload))
            if calculated != row["event_hash"]:
                raise LedgerIntegrityError(f"audit event hash mismatch at sequence {expected_seq}")
            previous_hash = row["event_hash"]

    def snapshot(self, attempt_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            attempt = connection.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            if attempt is None:
                raise FixtureError(f"unknown attempt: {attempt_id}")
            requests = connection.execute(
                "SELECT * FROM requests WHERE attempt_id = ? ORDER BY created_at, request_id",
                (attempt_id,),
            ).fetchall()
            audit = connection.execute(
                "SELECT * FROM audit_events WHERE attempt_id = ? ORDER BY seq", (attempt_id,)
            ).fetchall()
            return {
                "attempt": dict(attempt),
                "requests": [dict(row) for row in requests],
                "audit": [dict(row) for row in audit],
            }

    def final_snapshot(self, attempt_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            self._begin_immediate(connection)
            try:
                self._require_active_state(connection, attempt_id, "FENCED")
                nonterminal = connection.execute(
                    """
                    SELECT request_id, state FROM requests
                    WHERE attempt_id = ? AND state NOT IN ('COMMITTED','REJECTED','ROLLED_BACK','FAILED')
                    ORDER BY request_id
                    """,
                    (attempt_id,),
                ).fetchall()
                if nonterminal:
                    raise DrainIncomplete(
                        "non-terminal requests remain: "
                        + ", ".join(f"{r['request_id']}={r['state']}" for r in nonterminal)
                    )
                attempt = connection.execute(
                    "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
                ).fetchone()
                if attempt is None:
                    raise FixtureError("attempt disappeared during final snapshot")
                audit = connection.execute(
                    "SELECT * FROM audit_events WHERE attempt_id = ? ORDER BY seq", (attempt_id,)
                ).fetchall()
                self._validate_ledger(attempt, list(audit))
                watermark = int(attempt["audit_watermark"])
                requests = connection.execute(
                    "SELECT * FROM requests WHERE attempt_id = ? ORDER BY created_at, request_id",
                    (attempt_id,),
                ).fetchall()
                connection.execute(
                    """
                    UPDATE attempts
                    SET audit_complete = 1, final_watermark = ?, final_request_count = ?
                    WHERE attempt_id = ?
                    """,
                    (watermark, len(requests), attempt_id),
                )
                connection.commit()
                return {
                    "attempt_id": attempt_id,
                    "state": "FENCED",
                    "audit_complete": True,
                    "final_watermark": watermark,
                    "requests": [dict(row) for row in requests],
                    "audit": [self._observer_event(row) for row in audit],
                }
            except Exception:
                connection.rollback()
                raise

    def finalize_attempt(self, attempt_id: str) -> None:
        with self._connect() as connection:
            self._begin_immediate(connection)
            try:
                attempt = self._require_active_state(connection, attempt_id, "FENCED")
                if int(attempt["audit_complete"]) != 1:
                    raise InvalidAttemptState("attempt cannot finalize before final audit snapshot")
                requests = connection.execute(
                    "SELECT request_id, state FROM requests WHERE attempt_id = ? ORDER BY request_id",
                    (attempt_id,),
                ).fetchall()
                nonterminal = [row for row in requests if row["state"] not in _REQUEST_TERMINAL]
                if nonterminal:
                    raise DrainIncomplete(
                        "non-terminal requests remain during finalize: "
                        + ", ".join(f"{r['request_id']}={r['state']}" for r in nonterminal)
                    )
                if attempt["final_request_count"] is None or int(
                    attempt["final_request_count"]
                ) != len(requests):
                    raise InvalidAttemptState("attempt changed after final audit snapshot")
                if attempt["final_watermark"] is None or int(attempt["final_watermark"]) != int(
                    attempt["audit_watermark"]
                ):
                    raise InvalidAttemptState("audit watermark changed after final audit snapshot")
                audit = connection.execute(
                    "SELECT * FROM audit_events WHERE attempt_id = ? ORDER BY seq", (attempt_id,)
                ).fetchall()
                self._validate_ledger(attempt, list(audit))
                connection.execute(
                    "UPDATE attempts SET state = 'FINALIZED', finalized_at = ? WHERE attempt_id = ?",
                    (_utc_now(), attempt_id),
                )
                connection.execute(
                    "UPDATE fixture_meta SET active_attempt_id = NULL WHERE singleton_id = 1"
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def assert_schema_invariants(self) -> None:
        with self._connect() as connection:
            states = {
                row[0]
                for row in connection.execute("SELECT DISTINCT state FROM attempts").fetchall()
            }
            if not states.issubset(_ATTEMPT_STATES):
                raise FixtureError(f"unexpected attempt states: {states - _ATTEMPT_STATES}")
            request_states = {
                row[0]
                for row in connection.execute("SELECT DISTINCT state FROM requests").fetchall()
            }
            if not request_states.issubset(_REQUEST_STATES):
                raise FixtureError(f"unexpected request states: {request_states - _REQUEST_STATES}")
