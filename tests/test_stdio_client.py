import sys
from pathlib import Path

import pytest

from mcp_behaviour_guard.client import McpClient
from mcp_behaviour_guard.models import IdentitySpec, ServerSpec


@pytest.mark.asyncio
async def test_stdio_transport_discovers_demo_tools(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    server = ServerSpec(
        name="stdio-test",
        transport="stdio",
        command=sys.executable,
        args=["-m", "demo.stdio_server.app"],
        cwd=project_root,
        environment={
            "DEMO_STDIO_ROOT": str(tmp_path / "stdio"),
            "DEMO_STDIO_AUDIT": str(tmp_path / "stdio" / "audit.jsonl"),
            "DEMO_AGENT_TOKEN": "test-token",
        },
    )
    client = McpClient(server, "local_developer", IdentitySpec(role="developer"))

    tools = await client.list_tools()

    assert {item["name"] for item in tools} >= {
        "workspace_read",
        "diagnostics",
        "run_project_task",
    }
