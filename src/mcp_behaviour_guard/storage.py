from __future__ import annotations

import json
import sqlite3
from datetime import UTC
from pathlib import Path
from typing import Any

from .models import Finding, InvocationRecord, RunSummary
from .util import utc_now


class RunStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self._create_schema()

    def close(self) -> None:
        self.connection.close()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                contract_path TEXT NOT NULL,
                contract_hash TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                summary_json TEXT
            );

            CREATE TABLE IF NOT EXISTS invocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                test_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                identity TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                duration_ms REAL NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                test_id TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                fingerprint TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                test_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                first_sent_at TEXT NOT NULL,
                last_sent_at TEXT NOT NULL,
                send_count INTEGER NOT NULL DEFAULT 1,
                payload_json TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def start_run(
        self,
        run_id: str,
        target: str,
        contract_path: str,
        contract_hash: str,
        started_at: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO runs(run_id, target, contract_path, contract_hash, started_at, status)
            VALUES (?, ?, ?, ?, ?, 'running')
            """,
            (run_id, target, contract_path, contract_hash, started_at),
        )
        self.connection.commit()

    def add_invocation(self, run_id: str, invocation: InvocationRecord) -> None:
        self.connection.execute(
            """
            INSERT INTO invocations(
                run_id, test_id, tool, identity, allowed, duration_ms, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                invocation.test_id,
                invocation.tool,
                invocation.identity,
                int(invocation.allowed),
                invocation.duration_ms,
                invocation.model_dump_json(),
                utc_now(),
            ),
        )
        self.connection.commit()

    def add_finding(self, run_id: str, finding: Finding) -> None:
        self.connection.execute(
            """
            INSERT INTO findings(
                run_id, test_id, category, severity, status, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                finding.test_id,
                finding.category,
                finding.severity.value,
                finding.status.value,
                finding.model_dump_json(),
                utc_now(),
            ),
        )
        self.connection.commit()

    def finish_run(self, summary: RunSummary) -> None:
        status = "failed" if summary.failed else "passed"
        self.connection.execute(
            """
            UPDATE runs
               SET finished_at = ?, status = ?, summary_json = ?
             WHERE run_id = ?
            """,
            (summary.finished_at, status, summary.model_dump_json(), summary.run_id),
        )
        self.connection.commit()

    def recent_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT run_id, target, contract_path, started_at, finished_at, status
              FROM runs
             ORDER BY started_at DESC
             LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def export_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT summary_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row or not row["summary_json"]:
            return None
        return json.loads(row["summary_json"])

    def alert_is_due(self, fingerprint: str, repeat_after_hours: float | None) -> bool:
        row = self.connection.execute(
            "SELECT last_sent_at FROM alerts WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None:
            return True
        if repeat_after_hours is None:
            return False

        from datetime import datetime, timedelta

        last_sent = datetime.fromisoformat(row["last_sent_at"])
        if last_sent.tzinfo is None:
            last_sent = last_sent.replace(tzinfo=UTC)
        return datetime.now(UTC) - last_sent >= timedelta(hours=repeat_after_hours)

    def record_alert(
        self, fingerprint: str, run_id: str, finding: Finding, payload_json: str
    ) -> None:
        now = utc_now()
        self.connection.execute(
            """
            INSERT INTO alerts(
                fingerprint, run_id, test_id, severity, first_sent_at, last_sent_at, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                run_id = excluded.run_id,
                last_sent_at = excluded.last_sent_at,
                send_count = alerts.send_count + 1,
                payload_json = excluded.payload_json
            """,
            (
                fingerprint,
                run_id,
                finding.test_id,
                finding.severity.value,
                now,
                now,
                payload_json,
            ),
        )
        self.connection.commit()
