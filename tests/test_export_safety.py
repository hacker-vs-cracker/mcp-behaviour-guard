from __future__ import annotations

from pathlib import Path

import pytest

from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import Contract, ServerSpec
from mcp_behaviour_guard.reporting import write_reports
from mcp_behaviour_guard.storage import RunStore


@pytest.mark.asyncio
async def test_exported_target_does_not_leak_http_credentials(
    tmp_path: Path,
) -> None:
    marker = "DUMMY_TARGET_SECRET_20260917"
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "support-service",
                "url": (f"https://user:{marker}@localhost/mcp/{marker}?token={marker}&mode=test"),
            },
            "identities": {"user": {}},
            "tools": {},
        }
    )
    store = RunStore(tmp_path / "guard.db")
    guard = GuardEngine(
        contract,
        tmp_path / "contract.yaml",
        store,
        tmp_path / "reports",
        False,
    )

    async def discover_without_network() -> list[dict]:
        guard._discovery_ok = True
        return []

    guard._discover_tools = discover_without_network  # type: ignore[method-assign]

    try:
        summary = await guard.run()
        write_reports(summary, guard.run_dir, ["json", "html"])

        exported = "\n".join(
            [
                summary.target,
                (guard.run_dir / "report.json").read_text(encoding="utf-8"),
                (guard.run_dir / "index.html").read_text(encoding="utf-8"),
                str(store.recent_runs()[0]["target"]),
            ]
        )

        assert marker not in exported
        assert "user:" not in summary.target
    finally:
        store.close()


def test_stdio_target_label_does_not_export_argument_values() -> None:
    marker = "DUMMY_STDIO_SECRET_20260917"
    server = ServerSpec(
        name="local-worker",
        transport="stdio",
        command="python",
        args=["server.py", "--token", marker],
    )

    assert marker not in server.target_label
