from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcp_behaviour_guard.client import McpClient
from mcp_behaviour_guard.models import IdentitySpec, ServerSpec, TemporalIntegritySpec


class _Dumpable:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def model_dump(self, **_: object) -> dict[str, object]:
        return self.payload


class _PromptSession:
    def __init__(self) -> None:
        self.requested_prompts: list[str] = []

    def get_server_capabilities(self) -> SimpleNamespace:
        return SimpleNamespace(prompts=object(), resources=None)

    async def list_prompts(self, *_: object, **__: object) -> SimpleNamespace:
        return SimpleNamespace(
            prompts=[
                _Dumpable(
                    {
                        "name": "no_args",
                        "description": "safe demo",
                        "arguments": [],
                    }
                ),
                _Dumpable(
                    {
                        "name": "needs_topic",
                        "description": "requires an argument",
                        "arguments": [{"name": "topic", "required": True}],
                    }
                ),
            ],
            nextCursor=None,
        )

    async def get_prompt(self, name: str, arguments: dict[str, str]) -> _Dumpable:
        self.requested_prompts.append(name)
        return _Dumpable({"description": name, "messages": [], "arguments": arguments})


@pytest.mark.asyncio
async def test_metadata_snapshot_auto_probes_only_argumentless_prompts() -> None:
    client = McpClient(
        ServerSpec(name="test", transport="stdio", command="python"),
        "reviewer",
        IdentitySpec(),
    )
    session = _PromptSession()
    temporal = TemporalIntegritySpec(
        monitor_tools=False,
        monitor_prompts=True,
        monitor_resources=False,
        probe_argumentless_prompts=True,
    )

    snapshot = await client.metadata_snapshot(session, temporal)  # type: ignore[arg-type]

    assert session.requested_prompts == ["no_args"]
    assert list(snapshot["prompt_payloads"]) == ["no_args"]
