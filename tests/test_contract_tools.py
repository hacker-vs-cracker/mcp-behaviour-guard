from pathlib import Path

import pytest
import yaml

from mcp_behaviour_guard.contract_tools import (
    expand_tenants,
    generate_contract_draft,
    write_yaml,
)
from mcp_behaviour_guard.models import IdentitySpec, ServerSpec


def test_expand_tenants_applies_role_permissions(tmp_path: Path) -> None:
    base = tmp_path / "base.yaml"
    base.write_text(
        """
version: 1
server:
  name: demo
  transport: streamable-http
  url: http://127.0.0.1:8000/mcp
identities:
  anonymous: {}
tools:
  lookup:
    permitted_identities: []
  update:
    permitted_identities: []
""",
        encoding="utf-8",
    )
    tenants = tmp_path / "tenants.csv"
    tenants.write_text(
        "tenant,identity,role,credential_env,description,allow_tools,deny_tools\n"
        "tenant-a,tenant_a_reader,reader,TENANT_A_TOKEN,Reader A,update,lookup\n"
        "tenant-b,tenant_b_operator,operator,TENANT_B_TOKEN,Operator B,,\n",
        encoding="utf-8",
    )
    roles = tmp_path / "roles.yaml"
    roles.write_text(
        """
credential:
  http_header: Authorization
  http_prefix: Bearer
roles:
  reader:
    permitted_tools: [lookup]
  operator:
    permitted_tools: [lookup, update]
""",
        encoding="utf-8",
    )

    expanded = expand_tenants(base, tenants, roles)

    assert expanded["identities"]["tenant_a_reader"]["headers"]["Authorization"] == (
        "Bearer ${TENANT_A_TOKEN}"
    )
    assert "tenant_a_reader" not in expanded["tools"]["lookup"]["permitted_identities"]
    assert "tenant_a_reader" in expanded["tools"]["update"]["permitted_identities"]
    assert "tenant_b_operator" in expanded["tools"]["update"]["permitted_identities"]
    assert yaml.safe_dump(expanded)


@pytest.mark.asyncio
async def test_generated_draft_preserves_explicit_null_side_effect_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def fake_list_tools(self):
        del self
        return [
            {
                "name": "lookup",
                "description": "Read one record",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]

    monkeypatch.setattr(
        "mcp_behaviour_guard.contract_tools.McpClient.list_tools",
        fake_list_tools,
    )

    server = ServerSpec(
        name="demo",
        transport="streamable-http",
        url="http://127.0.0.1:8000/mcp",
    )
    identity = IdentitySpec()

    payload = await generate_contract_draft(
        server=server,
        discovery_identity=identity,
        contract_identity=identity,
    )

    tool = payload["tools"]["lookup"]
    for key in (
        "allowed_network_destinations",
        "allowed_filesystem_writes",
        "allowed_process_commands",
    ):
        assert key in tool
        assert tool[key] is None

    output = tmp_path / "generated.yaml"
    write_yaml(payload, output)
    loaded = yaml.safe_load(output.read_text(encoding="utf-8"))
    loaded_tool = loaded["tools"]["lookup"]

    for key in (
        "allowed_network_destinations",
        "allowed_filesystem_writes",
        "allowed_process_commands",
    ):
        assert key in loaded_tool
        assert loaded_tool[key] is None
