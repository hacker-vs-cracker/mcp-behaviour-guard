from pathlib import Path

from mcp_behaviour_guard.models import (
    Finding,
    FindingStatus,
    InvocationRecord,
    RunSummary,
    Severity,
)
from mcp_behaviour_guard.storage import RunStore


def test_sqlite_store_round_trip(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "guard.db")
    try:
        store.start_run("run-1", "http://target/mcp", "contract.yaml", "hash", "start")
        invocation = InvocationRecord(
            test_id="AUTH-1",
            tool="lookup",
            identity="user",
            arguments={},
            allowed=True,
            response={"ok": True},
            duration_ms=1.2,
        )
        finding = Finding(
            test_id="AUTH-1",
            category="authorization",
            title="allowed",
            status=FindingStatus.PASSED,
            severity=Severity.INFO,
            expected=True,
            observed=True,
        )
        store.add_invocation("run-1", invocation)
        store.add_finding("run-1", finding)
        summary = RunSummary(
            run_id="run-1",
            target="http://target/mcp",
            contract_path="contract.yaml",
            started_at="start",
            finished_at="finish",
            findings=[finding],
            invocations=[invocation],
        )
        store.finish_run(summary)

        exported = store.export_run("run-1")
        assert exported is not None
        assert exported["run_id"] == "run-1"
        assert store.recent_runs()[0]["status"] == "passed"
    finally:
        store.close()
