from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest

from mcp_behaviour_guard.correlation import observer_correlation_mode
from mcp_behaviour_guard.models import (
    Contract,
    HttpAuditObserverSpec,
    RunSummary,
    SideEffectKind,
)
from mcp_behaviour_guard.observers.base import ObserverCollectionError
from mcp_behaviour_guard.observers.http_audit import HttpAuditObserver

CORRELATION_META_KEY = "io.github.hacker-vs-cracker.mcp-behaviour-guard/correlation"


def _meta(run_id: str, operation_id: str) -> dict[str, Any]:
    return {
        CORRELATION_META_KEY: {
            "version": 1,
            "run_id": run_id,
            "guard_operation_id": operation_id,
        }
    }


class _SequencedAsyncClient:
    snapshots: list[list[Any]] = []
    get_count = 0
    post_count = 0
    post_urls: list[str] = []

    def __init__(self, **kwargs: Any) -> None:
        del kwargs

    async def __aenter__(self) -> _SequencedAsyncClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        del args

    async def get(self, url: str) -> Any:
        del url
        type(self).get_count += 1
        index = min(type(self).get_count - 1, len(type(self).snapshots) - 1)
        payload = deepcopy(type(self).snapshots[index])
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"events": payload},
        )

    async def post(self, url: str) -> Any:
        type(self).post_count += 1
        type(self).post_urls.append(url)
        return SimpleNamespace(raise_for_status=lambda: None)


def _install_http(
    monkeypatch: pytest.MonkeyPatch,
    snapshots: list[list[Any]],
) -> None:
    _SequencedAsyncClient.snapshots = deepcopy(snapshots)
    _SequencedAsyncClient.get_count = 0
    _SequencedAsyncClient.post_count = 0
    _SequencedAsyncClient.post_urls = []
    monkeypatch.setattr(
        "mcp_behaviour_guard.observers.http_audit.httpx.AsyncClient",
        _SequencedAsyncClient,
    )


def _correlated_spec(
    *,
    reset_url: str | None = None,
    settle_timeout_seconds: float = 0,
    quiet_period_seconds: float = 0,
) -> HttpAuditObserverSpec:
    payload: dict[str, Any] = {
        "type": "http_audit",
        "events_url": "https://example.test/audit/events",
        "correlation": "mcp_meta",
        "settle_timeout_seconds": settle_timeout_seconds,
        "quiet_period_seconds": quiet_period_seconds,
        "observes": [SideEffectKind.DATABASE_WRITE],
    }
    if reset_url is not None:
        payload["reset_url"] = reset_url
    return HttpAuditObserverSpec.model_validate(payload)


def test_http_correlation_is_opt_in_additive_and_keeps_contract_version_1() -> None:
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "local",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {"write": {"permitted_identities": ["user"]}},
            "observers": {
                "audit": {
                    "type": "http_audit",
                    "events_url": "https://example.test/audit/events",
                    "correlation": "mcp_meta",
                    "observes": ["database_write"],
                }
            },
        }
    )

    spec = contract.observers["audit"]
    assert isinstance(spec, HttpAuditObserverSpec)
    assert spec.correlation == "mcp_meta"
    assert spec.reset_url is None
    assert contract.version == 1
    assert RunSummary.model_fields["schema_version"].default == 2


def test_legacy_http_remains_uncorrelated_and_requires_reset_url() -> None:
    spec = HttpAuditObserverSpec(
        type="http_audit",
        events_url="https://example.test/audit/events",
        reset_url="https://example.test/audit/reset",
        observes=[SideEffectKind.DATABASE_WRITE],
    )
    assert spec.correlation == "none"

    with pytest.raises(ValueError, match="reset_url"):
        HttpAuditObserverSpec.model_validate(
            {
                "type": "http_audit",
                "events_url": "https://example.test/audit/events",
                "observes": ["database_write"],
            }
        )


def test_correlated_http_may_keep_legacy_reset_url_but_does_not_require_it() -> None:
    without_reset = _correlated_spec()
    with_reset = _correlated_spec(reset_url="https://example.test/audit/reset")

    assert without_reset.reset_url is None
    assert with_reset.reset_url == "https://example.test/audit/reset"
    assert without_reset.correlation == "mcp_meta"
    assert with_reset.correlation == "mcp_meta"


def test_real_http_observer_exposes_correlation_mode_from_spec() -> None:
    observer = HttpAuditObserver("audit", _correlated_spec())
    assert observer_correlation_mode(observer) == "mcp_meta"


@pytest.mark.asyncio
async def test_correlated_http_begin_snapshots_without_posting_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = {"kind": "database_write", "record": "before"}
    _install_http(monkeypatch, [[old]])

    observer = HttpAuditObserver(
        "audit",
        _correlated_spec(reset_url="https://example.test/audit/reset"),
    )
    await observer.begin()

    assert _SequencedAsyncClient.get_count == 1
    assert _SequencedAsyncClient.post_count == 0
    assert _SequencedAsyncClient.post_urls == []


@pytest.mark.asyncio
async def test_legacy_http_begin_still_posts_reset_without_fetching_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_http(monkeypatch, [[]])

    observer = HttpAuditObserver(
        "audit",
        HttpAuditObserverSpec(
            type="http_audit",
            events_url="https://example.test/audit/events",
            reset_url="https://example.test/audit/reset",
            observes=[SideEffectKind.DATABASE_WRITE],
        ),
    )
    await observer.begin()

    assert _SequencedAsyncClient.post_count == 1
    assert _SequencedAsyncClient.post_urls == ["https://example.test/audit/reset"]
    assert _SequencedAsyncClient.get_count == 0


@pytest.mark.asyncio
async def test_correlated_http_collect_returns_only_suffix_after_begin_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"kind": "database_write", "record": "before"}
    current = {
        "kind": "database_write",
        "record": "current",
        "_meta": _meta("run-a", "op-a"),
    }
    _install_http(monkeypatch, [[before], [before, current]])

    observer = HttpAuditObserver("audit", _correlated_spec())
    await observer.begin()
    events = await observer.collect()

    assert len(events) == 1
    assert events[0].details["record"] == "current"
    assert events[0].details["_meta"] == _meta("run-a", "op-a")


@pytest.mark.asyncio
async def test_preexisting_malformed_http_history_does_not_poison_new_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed_history = {"record": "old-without-kind"}
    current = {
        "kind": "database_write",
        "record": "current",
        "_meta": _meta("run-a", "op-a"),
    }
    _install_http(
        monkeypatch,
        [[malformed_history], [malformed_history, current]],
    )

    observer = HttpAuditObserver("audit", _correlated_spec())
    await observer.begin()
    events = await observer.collect()

    assert len(events) == 1
    assert events[0].details["record"] == "current"


@pytest.mark.asyncio
async def test_correlated_http_detects_rewrite_of_begin_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"kind": "database_write", "record": "before"}
    rewritten = {"kind": "database_write", "record": "rewritten"}
    _install_http(monkeypatch, [[before], [rewritten]])

    observer = HttpAuditObserver("audit", _correlated_spec())
    await observer.begin()

    with pytest.raises(ObserverCollectionError, match="append position"):
        await observer.collect()


@pytest.mark.asyncio
async def test_correlated_http_detects_shrink_from_begin_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {"kind": "database_write", "record": "first"}
    second = {"kind": "database_write", "record": "second"}
    _install_http(monkeypatch, [[first, second], [first]])

    observer = HttpAuditObserver("audit", _correlated_spec())
    await observer.begin()

    with pytest.raises(ObserverCollectionError, match="shrank"):
        await observer.collect()


@pytest.mark.asyncio
async def test_correlated_http_settling_uses_begin_snapshot_and_no_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"kind": "database_write", "record": "before"}
    current = {
        "kind": "database_write",
        "record": "current",
        "_meta": _meta("run-a", "op-a"),
    }
    _install_http(
        monkeypatch,
        [
            [before],
            [before],
            [before, current],
            [before, current],
            [before, current],
        ],
    )

    observer = HttpAuditObserver(
        "audit",
        _correlated_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.03,
        ),
    )
    await observer.begin()
    events = await observer.collect()

    assert [event.details["record"] for event in events] == ["current"]


@pytest.mark.asyncio
async def test_correlated_http_collect_without_begin_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = {
        "kind": "database_write",
        "record": "current",
        "_meta": _meta("run-a", "op-a"),
    }
    _install_http(monkeypatch, [[current]])

    observer = HttpAuditObserver("audit", _correlated_spec())

    with pytest.raises(ObserverCollectionError, match="begin|baseline|initialized"):
        await observer.collect()


def test_correlated_http_ownership_does_not_claim_unused_reset_resource() -> None:
    observer = HttpAuditObserver(
        "audit",
        _correlated_spec(reset_url="https://example.test/audit/reset"),
    )

    assert len(observer.ownership_keys) == 1
    assert "events" in observer.ownership_keys[0]


def test_correlated_http_contract_still_rejects_duplicate_event_streams() -> None:
    with pytest.raises(ValueError, match="share one HTTP event stream"):
        Contract.model_validate(
            {
                "version": 1,
                "server": {
                    "name": "local",
                    "url": "http://127.0.0.1:8000/mcp",
                },
                "identities": {"user": {}},
                "tools": {"write": {"permitted_identities": ["user"]}},
                "observers": {
                    "first": {
                        "type": "http_audit",
                        "events_url": "https://example.test/audit/events",
                        "correlation": "mcp_meta",
                        "observes": ["database_write"],
                    },
                    "second": {
                        "type": "http_audit",
                        "events_url": "https://example.test/audit/events",
                        "correlation": "mcp_meta",
                        "observes": ["database_write"],
                    },
                },
            }
        )


def test_correlated_http_ignored_reset_does_not_conflict_with_live_event_resource() -> None:
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "local",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {"write": {"permitted_identities": ["user"]}},
            "observers": {
                "first": {
                    "type": "http_audit",
                    "events_url": "https://example.test/audit/events-a",
                    "reset_url": "https://example.test/audit/events-b",
                    "correlation": "mcp_meta",
                    "observes": ["database_write"],
                },
                "second": {
                    "type": "http_audit",
                    "events_url": "https://example.test/audit/events-b",
                    "correlation": "mcp_meta",
                    "observes": ["database_write"],
                },
            },
        }
    )

    first = contract.observers["first"]
    second = contract.observers["second"]
    assert isinstance(first, HttpAuditObserverSpec)
    assert isinstance(second, HttpAuditObserverSpec)
    assert first.correlation == "mcp_meta"
    assert second.correlation == "mcp_meta"


@pytest.mark.asyncio
async def test_correlated_http_settling_preserves_suffix_on_later_rewrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"kind": "database_write", "record": "before"}
    current = {
        "kind": "database_write",
        "record": "current",
        "_meta": _meta("run-a", "op-a"),
    }
    rewritten = {
        "kind": "database_write",
        "record": "rewritten-current",
        "_meta": _meta("run-a", "op-a"),
    }
    _install_http(
        monkeypatch,
        [
            [before],
            [before, current],
            [before, rewritten],
        ],
    )

    observer = HttpAuditObserver(
        "audit",
        _correlated_spec(
            settle_timeout_seconds=0.20,
            quiet_period_seconds=0.10,
        ),
    )
    await observer.begin()

    with pytest.raises(ObserverCollectionError) as captured:
        await observer.collect()

    assert "append position" in str(captured.value)
    assert len(captured.value.events) == 1
    assert captured.value.events[0].details["record"] == "current"
