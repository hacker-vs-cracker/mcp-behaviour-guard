from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcp_behaviour_guard.correlation import CORRELATION_META_KEY
from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import (
    Contract,
    Finding,
    FindingStatus,
    InvocationRecord,
    ObservationStatus,
    SideEffectKind,
)
from mcp_behaviour_guard.observers.base import ObserverCollectionError, SideEffectEvent
from mcp_behaviour_guard.storage import RunStore
from mcp_behaviour_guard.util import utc_now


class _Observer:
    def __init__(
        self,
        name: str,
        events: list[SideEffectEvent],
        observes: set[SideEffectKind],
        *,
        correlation: str = "none",
    ) -> None:
        self.name = name
        self.events = events
        self.observes = set(observes)
        self.complete_observes = set(observes)
        self.correlation = correlation

    async def begin(self) -> None:
        return None

    async def collect(self) -> list[SideEffectEvent]:
        return list(self.events)


class _PartialObserver(_Observer):
    async def collect(self) -> list[SideEffectEvent]:
        raise ObserverCollectionError("partial replay collection", self.events)


def _contract_data(
    *,
    allowed_network_destinations: list[str] | None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "server": {
            "name": "offline",
            "url": "http://127.0.0.1:8000/mcp",
        },
        "identities": {"user": {}},
        "tools": {
            "write": {
                "permitted_identities": ["user"],
                "allowed_network_destinations": allowed_network_destinations,
                "replay_probe": {
                    "arguments": {},
                    "attempts": 2,
                    "event_kind": "database_write",
                    "minimum_events": 1,
                    "maximum_events": 1,
                },
            }
        },
        "safety": {
            "destructive_tests": True,
            "require_lab_mode": False,
        },
    }


def _guard(
    tmp_path: Path,
    *,
    allowed_network_destinations: list[str] | None,
) -> tuple[GuardEngine, RunStore]:
    contract = Contract.model_validate(
        _contract_data(
            allowed_network_destinations=allowed_network_destinations,
        )
    )
    store = RunStore(tmp_path / "guard.db")
    guard = GuardEngine(
        contract,
        tmp_path / "contract.yaml",
        store,
        tmp_path / "reports",
        False,
    )
    guard.run_dir.mkdir(parents=True)
    guard.trace_path.parent.mkdir(parents=True)
    store.start_run(
        guard.run_id,
        contract.server.target_label,
        "contract.yaml",
        "hash",
        utc_now(),
    )
    return guard, store


def _event(
    observer: str,
    kind: SideEffectKind,
    **details: Any,
) -> SideEffectEvent:
    return SideEffectEvent(observer=observer, kind=kind, details=details)


def _finding(findings: list[Finding], test_id: str) -> Finding:
    matches = [item for item in findings if item.test_id == test_id]
    assert len(matches) == 1, f"expected one {test_id} finding, got {len(matches)}"
    return matches[0]


async def _exercise(
    tmp_path: Path,
    *,
    observers: list[object],
    allowed_network_destinations: list[str] | None,
) -> tuple[list[Finding], list[str]]:
    guard, store = _guard(
        tmp_path,
        allowed_network_destinations=allowed_network_destinations,
    )
    guard.observers = observers
    calls: list[str] = []

    async def accepted(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del identity, arguments
        calls.append(tool)
        return InvocationRecord(
            test_id=test_id,
            tool=tool,
            identity=identity_name,
            arguments={},
            allowed=True,
            duration_ms=0,
        )

    guard._invoke = accepted  # type: ignore[method-assign]

    try:
        await guard._check_replay_protection()
        return list(guard.findings), calls
    finally:
        store.close()


@pytest.mark.asyncio
async def test_forbidden_secondary_effect_fails_separate_effects_finding_while_count_passes(
    tmp_path: Path,
) -> None:
    findings, calls = await _exercise(
        tmp_path,
        allowed_network_destinations=[],
        observers=[
            _Observer(
                "audit",
                [
                    _event("audit", SideEffectKind.DATABASE_WRITE, tool="write"),
                    _event(
                        "audit",
                        SideEffectKind.NETWORK_REQUEST,
                        tool="write",
                        destination="https://blocked.example",
                    ),
                ],
                {
                    SideEffectKind.DATABASE_WRITE,
                    SideEffectKind.NETWORK_REQUEST,
                },
            )
        ],
    )

    replay = _finding(findings, "REPLAY-WRITE")
    assert calls == ["write", "write"], "N1 must not add target invocations"
    assert replay.status == FindingStatus.PASSED
    assert replay.observation == ObservationStatus.COMPLETE
    assert replay.observed["matching_side_effects"] == 1

    effects = _finding(findings, "REPLAY-WRITE-EFFECTS")
    assert effects.category == "runtime_behaviour"
    assert effects.status == FindingStatus.FAILED
    assert effects.observation == ObservationStatus.COMPLETE
    assert any(
        item["reason"] == "network destination is not allowlisted"
        for item in effects.observed["violations"]
    )


@pytest.mark.asyncio
async def test_allowed_secondary_effect_does_not_create_effect_policy_failure(
    tmp_path: Path,
) -> None:
    findings, calls = await _exercise(
        tmp_path,
        allowed_network_destinations=["https://allowed.example"],
        observers=[
            _Observer(
                "audit",
                [
                    _event("audit", SideEffectKind.DATABASE_WRITE, tool="write"),
                    _event(
                        "audit",
                        SideEffectKind.NETWORK_REQUEST,
                        tool="write",
                        destination="https://allowed.example",
                    ),
                ],
                {
                    SideEffectKind.DATABASE_WRITE,
                    SideEffectKind.NETWORK_REQUEST,
                },
            )
        ],
    )

    replay = _finding(findings, "REPLAY-WRITE")
    assert calls == ["write", "write"]
    assert replay.status == FindingStatus.PASSED
    assert replay.observation == ObservationStatus.COMPLETE
    assert not any(item.test_id == "REPLAY-WRITE-EFFECTS" for item in findings)


@pytest.mark.asyncio
async def test_duplicate_replay_and_forbidden_secondary_effect_fail_independently(
    tmp_path: Path,
) -> None:
    findings, calls = await _exercise(
        tmp_path,
        allowed_network_destinations=[],
        observers=[
            _Observer(
                "audit",
                [
                    _event("audit", SideEffectKind.DATABASE_WRITE, tool="write"),
                    _event("audit", SideEffectKind.DATABASE_WRITE, tool="write"),
                    _event(
                        "audit",
                        SideEffectKind.NETWORK_REQUEST,
                        tool="write",
                        destination="https://blocked.example",
                    ),
                ],
                {
                    SideEffectKind.DATABASE_WRITE,
                    SideEffectKind.NETWORK_REQUEST,
                },
            )
        ],
    )

    replay = _finding(findings, "REPLAY-WRITE")
    assert calls == ["write", "write"]
    assert replay.status == FindingStatus.FAILED
    assert replay.observed["matching_side_effects"] == 2

    effects = _finding(findings, "REPLAY-WRITE-EFFECTS")
    assert effects.status == FindingStatus.FAILED


@pytest.mark.asyncio
async def test_partial_collection_retains_confirmed_secondary_violation(
    tmp_path: Path,
) -> None:
    findings, calls = await _exercise(
        tmp_path,
        allowed_network_destinations=[],
        observers=[
            _PartialObserver(
                "audit",
                [
                    _event("audit", SideEffectKind.DATABASE_WRITE, tool="write"),
                    _event(
                        "audit",
                        SideEffectKind.NETWORK_REQUEST,
                        tool="write",
                        destination="https://blocked.example",
                    ),
                ],
                {
                    SideEffectKind.DATABASE_WRITE,
                    SideEffectKind.NETWORK_REQUEST,
                },
            )
        ],
    )

    replay = _finding(findings, "REPLAY-WRITE")
    assert calls == ["write", "write"]
    assert replay.status == FindingStatus.ERROR
    assert replay.observation == ObservationStatus.PARTIAL

    effects = _finding(findings, "REPLAY-WRITE-EFFECTS")
    assert effects.status == FindingStatus.FAILED
    assert effects.observation == ObservationStatus.PARTIAL
    assert effects.observed["observer_errors"]


@pytest.mark.asyncio
async def test_foreign_correlated_secondary_violation_is_not_attributed(
    tmp_path: Path,
) -> None:
    foreign_meta = {
        "_meta": {
            CORRELATION_META_KEY: {
                "version": 1,
                "run_id": "foreign-run",
                "guard_operation_id": "foreign-operation",
            }
        }
    }
    findings, calls = await _exercise(
        tmp_path,
        allowed_network_destinations=[],
        observers=[
            _Observer(
                "database",
                [_event("database", SideEffectKind.DATABASE_WRITE, tool="write")],
                {SideEffectKind.DATABASE_WRITE},
            ),
            _Observer(
                "network",
                [
                    _event(
                        "network",
                        SideEffectKind.NETWORK_REQUEST,
                        tool="write",
                        destination="https://blocked.example",
                        **foreign_meta,
                    )
                ],
                {SideEffectKind.NETWORK_REQUEST},
                correlation="mcp_meta",
            ),
        ],
    )

    replay = _finding(findings, "REPLAY-WRITE")
    assert calls == ["write", "write"]
    assert replay.status == FindingStatus.PASSED
    assert replay.observation == ObservationStatus.COMPLETE
    assert not any(item.test_id == "REPLAY-WRITE-EFFECTS" for item in findings)


@pytest.mark.asyncio
async def test_partial_collection_without_confirmed_violation_emits_inconclusive_effects_finding(
    tmp_path: Path,
) -> None:
    findings, calls = await _exercise(
        tmp_path,
        allowed_network_destinations=["https://allowed.example"],
        observers=[
            _PartialObserver(
                "audit",
                [
                    _event("audit", SideEffectKind.DATABASE_WRITE, tool="write"),
                    _event(
                        "audit",
                        SideEffectKind.NETWORK_REQUEST,
                        tool="write",
                        destination="https://allowed.example",
                    ),
                ],
                {
                    SideEffectKind.DATABASE_WRITE,
                    SideEffectKind.NETWORK_REQUEST,
                },
            )
        ],
    )

    replay = _finding(findings, "REPLAY-WRITE")
    assert calls == ["write", "write"]
    assert replay.status == FindingStatus.ERROR
    assert replay.observation == ObservationStatus.PARTIAL

    effects = _finding(findings, "REPLAY-WRITE-EFFECTS")
    assert effects.status == FindingStatus.ERROR
    assert effects.observation == ObservationStatus.PARTIAL
    assert effects.observed["violations"] == []
    assert effects.observed["observer_errors"]


@pytest.mark.asyncio
async def test_replay_count_uncertainty_does_not_create_policy_uncertainty(
    tmp_path: Path,
) -> None:
    findings, calls = await _exercise(
        tmp_path,
        allowed_network_destinations=["https://allowed.example"],
        observers=[
            _PartialObserver(
                "database",
                [_event("database", SideEffectKind.DATABASE_WRITE, tool="write")],
                {SideEffectKind.DATABASE_WRITE},
            ),
            _Observer(
                "network",
                [
                    _event(
                        "network",
                        SideEffectKind.NETWORK_REQUEST,
                        tool="write",
                        destination="https://allowed.example",
                    )
                ],
                {SideEffectKind.NETWORK_REQUEST},
            ),
        ],
    )

    replay = _finding(findings, "REPLAY-WRITE")
    assert calls == ["write", "write"]
    assert replay.status == FindingStatus.ERROR
    assert replay.observation == ObservationStatus.PARTIAL
    assert not any(item.test_id == "REPLAY-WRITE-EFFECTS" for item in findings)
