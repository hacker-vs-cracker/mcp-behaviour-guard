from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = PROJECT_ROOT / "assurance/phase2/fixture"
PROFILE = PROJECT_ROOT / "assurance/phase2/fixture-profile.json"
DOCKERFILE = FIXTURE_DIR / "Dockerfile"

if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

from app_service import make_server as make_app_server  # noqa: E402
from control_service import make_server as make_control_server  # noqa: E402
from store import (  # noqa: E402
    ActiveAttemptExists,
    DrainIncomplete,
    FixtureStore,
    InjectedFixtureFault,
    InvalidAttemptState,
    LedgerIntegrityError,
    SimulatedResponseLoss,
    StaleCredential,
    WriteBarrier,
)


def _store(tmp_path: Path) -> FixtureStore:
    store = FixtureStore(tmp_path / "fixture.db")
    store.bootstrap()
    return store


def _opened(store: FixtureStore, attempt_id: str = "attempt-1") -> tuple[str, str]:
    credential = store.create_attempt(attempt_id)
    store.open_attempt(credential.attempt_id)
    return credential.attempt_id, credential.token


def _request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _start_server(server: Any) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def test_profile_and_dockerfile_keep_phase2b1_boundary_explicit() -> None:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    assert profile["schema_version"] == 1
    assert profile["attempt_concurrency"] == 1
    assert profile["internal_async_queue"] is False
    assert profile["observer"]["correlation"] == "none"
    assert profile["observer"]["reset_semantics"] == "advance_cursor_without_deletion"
    assert profile["store"]["transaction_mode"] == "BEGIN IMMEDIATE"
    assert profile["store"]["business_and_audit_commit"] == "atomic"

    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "ARG BASE_IMAGE" in dockerfile
    assert "FROM ${BASE_IMAGE}" in dockerfile
    assert "ARG BASE_IMAGE=" not in dockerfile
    assert "apt-get" not in dockerfile
    assert "pip install" not in dockerfile
    assert "USER fixture" in dockerfile


def test_positive_write_commits_business_mutation_and_audit_atomically(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store)

    result = store.business_write(token, record_id="synthetic-record-001", value="changed")

    assert result.committed is True
    assert result.state == "COMMITTED"
    assert result.audit_seq == 1
    record = store.read_record(token, "synthetic-record-001")
    assert record is not None
    assert record["value"] == "changed"

    store.close_attempt(attempt_id)
    final = store.final_snapshot(attempt_id)
    assert final["audit_complete"] is True
    assert final["final_watermark"] == 1
    assert [event["kind"] for event in final["audit"]] == ["database_write"]
    assert final["requests"][0]["state"] == "COMMITTED"


def test_observer_reset_advances_cursor_without_erasing_whole_attempt_ledger(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store)
    store.business_write(token, record_id="one", value="1", request_id="req-1")

    assert [event["seq"] for event in store.observer_events()] == [1]
    assert store.reset_observer_cursor() == 1
    assert store.observer_events() == []

    store.business_write(token, record_id="two", value="2", request_id="req-2")
    assert [event["seq"] for event in store.observer_events()] == [2]

    store.close_attempt(attempt_id)
    final = store.final_snapshot(attempt_id)
    assert [event["seq"] for event in final["audit"]] == [1, 2]
    assert final["final_watermark"] == 2


def test_commit_before_fence_is_recorded_and_close_waits_for_transaction(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store)
    reached = threading.Event()
    release = threading.Event()
    barrier = WriteBarrier("after_write_lock", reached, release)
    write_result: list[Any] = []
    close_result: list[Any] = []
    close_started = threading.Event()

    def writer() -> None:
        try:
            write_result.append(
                store.business_write(
                    token,
                    record_id="race",
                    value="commit-first",
                    request_id="race-write",
                    barrier=barrier,
                )
            )
        except Exception as exc:  # pragma: no cover - assertion below reports unexpected error
            write_result.append(exc)

    def closer() -> None:
        close_started.set()
        try:
            store.close_attempt(attempt_id)
            close_result.append("closed")
        except Exception as exc:  # pragma: no cover
            close_result.append(exc)

    writer_thread = threading.Thread(target=writer)
    writer_thread.start()
    assert reached.wait(2)
    close_thread = threading.Thread(target=closer)
    close_thread.start()
    assert close_started.wait(2)
    release.set()
    writer_thread.join(3)
    close_thread.join(3)

    assert len(write_result) == 1
    assert not isinstance(write_result[0], Exception)
    assert write_result[0].state == "COMMITTED"
    assert close_result == ["closed"]
    final = store.final_snapshot(attempt_id)
    assert final["final_watermark"] == 1
    assert final["requests"][0]["state"] == "COMMITTED"


def test_fence_before_transaction_rejects_write_without_database_event(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store)
    reached = threading.Event()
    release = threading.Event()
    barrier = WriteBarrier("before_transaction", reached, release)
    result: list[Any] = []

    def writer() -> None:
        try:
            result.append(
                store.business_write(
                    token,
                    record_id="race",
                    value="must-not-commit",
                    request_id="race-rejected",
                    barrier=barrier,
                )
            )
        except Exception as exc:  # pragma: no cover
            result.append(exc)

    thread = threading.Thread(target=writer)
    thread.start()
    assert reached.wait(2)
    store.close_attempt(attempt_id)
    release.set()
    thread.join(3)

    assert len(result) == 1
    assert not isinstance(result[0], Exception)
    assert result[0].state == "REJECTED"
    assert result[0].committed is False
    assert store.snapshot(attempt_id)["audit"] == []
    final = store.final_snapshot(attempt_id)
    assert final["final_watermark"] == 0
    assert final["requests"][0]["state"] == "REJECTED"


def test_nonterminal_request_prevents_final_audit_completion(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, _ = _opened(store)
    store.close_attempt(attempt_id)

    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO requests(
                attempt_id, request_id, operation, state, created_at
            ) VALUES (?, 'stuck', 'record_write', 'ADMITTED', 'synthetic')
            """,
            (attempt_id,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(DrainIncomplete, match="stuck=ADMITTED"):
        store.final_snapshot(attempt_id)


def test_finalize_requires_snapshot_to_cover_post_fence_rejection(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store)
    store.close_attempt(attempt_id)
    first = store.final_snapshot(attempt_id)
    assert first["requests"] == []

    rejected = store.business_write(
        token,
        record_id="after-snapshot",
        value="must-not-commit",
        request_id="post-snapshot-rejection",
    )
    assert rejected.state == "REJECTED"
    with pytest.raises(InvalidAttemptState, match="changed after final audit snapshot"):
        store.finalize_attempt(attempt_id)

    refreshed = store.final_snapshot(attempt_id)
    assert refreshed["requests"][0]["state"] == "REJECTED"
    store.finalize_attempt(attempt_id)
    assert store.snapshot(attempt_id)["attempt"]["state"] == "FINALIZED"


def test_stale_credential_cannot_act_for_new_attempt(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first_id, first_token = _opened(store, "first")
    store.close_attempt(first_id)
    store.final_snapshot(first_id)
    store.finalize_attempt(first_id)

    second = store.create_attempt("second")
    store.open_attempt(second.attempt_id)
    with pytest.raises(StaleCredential):
        store.business_write(first_token, record_id="stale", value="bad")


def test_forged_labels_do_not_change_authenticated_binding(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store, "real-attempt")
    store.business_write(
        token,
        record_id="forgery",
        value="x",
        asserted_attempt_id="forged-attempt",
        asserted_principal="admin",
    )
    store.close_attempt(attempt_id)
    final = store.final_snapshot(attempt_id)
    event = final["audit"][0]
    assert event["principal"] == "candidate_app"
    assert event["asserted_attempt_id"] == "forged-attempt"
    assert event["asserted_principal"] == "admin"
    assert final["attempt_id"] == "real-attempt"


@pytest.mark.parametrize("fault", ["audit_failure", "crash_before_commit"])
def test_fault_before_commit_rolls_back_business_and_audit(
    tmp_path: Path,
    fault: str,
) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store)
    with pytest.raises(InjectedFixtureFault):
        store.business_write(
            token,
            record_id="rollback",
            value="must-not-persist",
            fault=fault,  # type: ignore[arg-type]
        )

    snap = store.snapshot(attempt_id)
    assert snap["audit"] == []
    assert snap["requests"] == []
    assert store.read_record(token, "rollback") is None


def test_committed_write_survives_simulated_response_loss(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store)
    with pytest.raises(SimulatedResponseLoss):
        store.business_write(
            token,
            record_id="lost-response",
            value="committed",
            request_id="lost-response-request",
            fault="response_loss",
        )

    snap = store.snapshot(attempt_id)
    assert snap["requests"][0]["state"] == "COMMITTED"
    assert snap["audit"][0]["request_id"] == "lost-response-request"
    record = store.read_record(token, "lost-response")
    assert record is not None and record["value"] == "committed"


def test_final_snapshot_detects_truncation_and_content_tamper(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, token = _opened(store)
    store.business_write(token, record_id="one", value="1")
    store.business_write(token, record_id="two", value="2")
    store.close_attempt(attempt_id)

    connection = sqlite3.connect(store.db_path)
    try:
        connection.execute(
            "DELETE FROM audit_events WHERE attempt_id = ? AND seq = 2", (attempt_id,)
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(LedgerIntegrityError, match="row count"):
        store.final_snapshot(attempt_id)

    # Restore by starting a separate store/attempt for content-hash tamper.
    other = _store(tmp_path / "other")
    other_id, other_token = _opened(other, "other")
    other.business_write(other_token, record_id="x", value="1")
    other.close_attempt(other_id)
    connection = sqlite3.connect(other.db_path)
    try:
        connection.execute(
            'UPDATE audit_events SET details_json = \'{"record_id":"tampered"}\' WHERE attempt_id = ? AND seq = 1',
            (other_id,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(LedgerIntegrityError, match="event hash mismatch"):
        other.final_snapshot(other_id)


def test_single_active_attempt_until_finalized(tmp_path: Path) -> None:
    store = _store(tmp_path)
    attempt_id, _ = _opened(store, "first")
    with pytest.raises(ActiveAttemptExists):
        store.create_attempt("second")

    store.close_attempt(attempt_id)
    store.final_snapshot(attempt_id)
    store.finalize_attempt(attempt_id)
    second = store.create_attempt("second")
    assert second.attempt_id == "second"


def test_app_and_control_http_surfaces_share_durable_store(tmp_path: Path) -> None:
    store = _store(tmp_path)
    app = make_app_server(store, "127.0.0.1", 0)
    control = make_control_server(store, "127.0.0.1", 0)
    app_thread = _start_server(app)
    control_thread = _start_server(control)
    app_url = f"http://127.0.0.1:{app.server_address[1]}"
    control_url = f"http://127.0.0.1:{control.server_address[1]}"
    try:
        status, created = _request_json(
            "POST", f"{control_url}/attempts", {"attempt_id": "http-attempt"}
        )
        assert status == 201
        token = created["token"]
        status, opened = _request_json("POST", f"{control_url}/attempts/http-attempt/open")
        assert status == 200 and opened["state"] == "OPEN"

        status, write = _request_json(
            "POST",
            f"{app_url}/records/write",
            {"record_id": "http-record", "value": "one", "request_id": "http-1"},
            token=token,
        )
        assert status == 200 and write["committed"] is True

        status, reset = _request_json("POST", f"{control_url}/observer/reset")
        assert status == 200 and reset["cursor_seq"] == 1
        status, events = _request_json("GET", f"{control_url}/observer/events")
        assert status == 200 and events["events"] == []

        status, write = _request_json(
            "POST",
            f"{app_url}/records/write",
            {"record_id": "http-record", "value": "two", "request_id": "http-2"},
            token=token,
        )
        assert status == 200 and write["audit_seq"] == 2
        status, events = _request_json("GET", f"{control_url}/observer/events")
        assert status == 200 and [event["seq"] for event in events["events"]] == [2]

        status, _ = _request_json("POST", f"{control_url}/attempts/http-attempt/close")
        assert status == 200
        status, final = _request_json("POST", f"{control_url}/attempts/http-attempt/final-snapshot")
        assert status == 200
        assert final["audit_complete"] is True
        assert [event["seq"] for event in final["audit"]] == [1, 2]
    finally:
        app.shutdown()
        control.shutdown()
        app.server_close()
        control.server_close()
        app_thread.join(2)
        control_thread.join(2)


def test_fixture_modules_have_no_third_party_runtime_imports() -> None:
    for name in ("store", "app_service", "control_service"):
        spec = importlib.util.find_spec(name)
        assert spec is not None and spec.origin is not None
        source = Path(spec.origin).read_text(encoding="utf-8")
        assert "import httpx" not in source
        assert "import requests" not in source
        assert "import fastapi" not in source
        assert "import flask" not in source
