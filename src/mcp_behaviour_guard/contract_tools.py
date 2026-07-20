from __future__ import annotations

import csv
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from .client import McpClient
from .models import IdentitySpec, ServerSpec
from .util import utc_now


async def generate_contract_draft(
    server: ServerSpec,
    discovery_identity: IdentitySpec,
    contract_identity: IdentitySpec,
    infer_read_only: bool = False,
    contract_server: ServerSpec | None = None,
) -> dict[str, Any]:
    tools = await McpClient(server, "discovery", discovery_identity).list_tools()
    generated_tools: dict[str, Any] = {}
    for tool in tools:
        name = str(tool.get("name", "unnamed_tool"))
        description = str(tool.get("description") or "")
        input_schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        generated_tools[name] = {
            "description": description or None,
            "permitted_identities": ["review_identity"],
            "probe_arguments": _example_from_schema(input_schema),
            "read_only": _looks_read_only(name, description) if infer_read_only else False,
            "allowed_network_destinations": [],
            "allowed_filesystem_writes": [],
            "allowed_process_commands": [],
            "forbidden_side_effects": [],
        }

    server_payload = (contract_server or server).model_dump(mode="json", exclude_none=True)
    if server.transport == "stdio":
        for field in ("url", "verify_tls", "allowed_hosts"):
            server_payload.pop(field, None)
    else:
        for field in ("command", "args", "cwd", "environment"):
            server_payload.pop(field, None)

    payload: dict[str, Any] = {
        "version": 1,
        "metadata": {
            "generated_draft": True,
            "generated_at": utc_now(),
            "notes": [
                "Generated from MCP discovery metadata. Review every identity, probe, side-effect rule and destructive operation before running.",
                "The target server is not trusted to define its own authorization policy.",
            ],
        },
        "server": server_payload,
        "identities": {
            "review_identity": contract_identity.model_dump(mode="json", exclude_none=True)
        },
        "tools": generated_tools,
        "session_tests": [],
        "observers": {},
        "safety": {
            "destructive_tests": False,
            "require_lab_mode": True,
            "target_allowlist": server.allowed_hosts
            if server.transport == "streamable-http"
            else [],
            "allowed_stdio_commands": [Path(server.command).name]
            if server.command
            else ["python", "python3", "uv", "node", "npx", "docker"],
        },
        "reports": {"formats": ["json", "html", "junit", "sarif"]},
        "alerts": {
            "enabled": False,
            "minimum_severity": "high",
            "only_new": True,
        },
    }
    return _drop_none(payload)


def write_yaml(payload: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def expand_tenants(
    base_contract_path: Path,
    tenant_csv_path: Path,
    role_policy_path: Path,
) -> dict[str, Any]:
    base = _read_mapping(base_contract_path)
    role_policy = _read_mapping(role_policy_path)
    roles = role_policy.get("roles")
    if not isinstance(roles, dict):
        raise ValueError("role policy must contain a roles mapping")

    credential = role_policy.get("credential", {})
    if not isinstance(credential, dict):
        raise ValueError("role policy credential must be a mapping")

    result = deepcopy(base)
    identities = result.setdefault("identities", {})
    tools = result.setdefault("tools", {})
    if not isinstance(identities, dict) or not isinstance(tools, dict):
        raise ValueError("base contract identities and tools must be mappings")

    transport = str(result.get("server", {}).get("transport", "streamable-http"))
    with tenant_csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"tenant", "identity", "role", "credential_env"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"tenant CSV is missing columns: {sorted(missing)}")

        for row_number, row in enumerate(reader, start=2):
            identity_name = row["identity"].strip()
            tenant = row["tenant"].strip()
            role = row["role"].strip()
            credential_env = row["credential_env"].strip()
            if not all([identity_name, tenant, role, credential_env]):
                raise ValueError(f"tenant CSV row {row_number} contains an empty required field")
            if role not in roles or not isinstance(roles[role], dict):
                raise ValueError(f"tenant CSV row {row_number} references unknown role {role!r}")

            role_spec = roles[role]
            identity: dict[str, Any] = {
                "tenant": tenant,
                "role": role,
                "description": row.get("description", "").strip() or f"{role} for {tenant}",
            }
            if transport == "streamable-http":
                header_name = str(credential.get("http_header", "Authorization"))
                prefix = str(credential.get("http_prefix", "Bearer")).strip()
                value = f"{prefix} ${{{credential_env}}}".strip()
                identity["headers"] = {header_name: value}
            else:
                env_name = str(credential.get("stdio_env", "MCP_GUARD_TOKEN"))
                identity["environment"] = {
                    env_name: f"${{{credential_env}}}",
                    "MCP_GUARD_IDENTITY": identity_name,
                    "MCP_GUARD_TENANT": tenant,
                    "MCP_GUARD_ROLE": role,
                }
            identities[identity_name] = identity

            permitted_tools = role_spec.get("permitted_tools", [])
            if not isinstance(permitted_tools, list):
                raise ValueError(f"role {role!r} permitted_tools must be a list")

            effective_tools = {str(tool_name) for tool_name in permitted_tools}
            effective_tools.update(_split_tool_overrides(row.get("allow_tools", "")))
            effective_tools.difference_update(_split_tool_overrides(row.get("deny_tools", "")))

            for tool_name in sorted(effective_tools):
                if tool_name not in tools:
                    raise ValueError(
                        f"tenant CSV row {row_number} or role {role!r} references "
                        f"unknown tool {tool_name!r}"
                    )
                current = tools[tool_name].setdefault("permitted_identities", [])
                if identity_name not in current:
                    current.append(identity_name)

    metadata = result.setdefault("metadata", {})
    if isinstance(metadata, dict):
        metadata.setdefault("notes", []).append(
            f"Tenant identities compiled from {tenant_csv_path.name} and {role_policy_path.name}."
        )
    return result


def _split_tool_overrides(value: str | None) -> set[str]:
    if not value:
        return set()
    normalized = value.replace(",", ";")
    return {item.strip() for item in normalized.split(";") if item.strip()}


def parse_key_value(items: list[str], *, read_environment: bool = False) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        key, separator, value = item.partition("=")
        if not separator or not key or not value:
            raise ValueError(f"expected NAME=VALUE, received {item!r}")
        if read_environment:
            if value not in os.environ:
                raise ValueError(f"environment variable {value!r} is not set")
            result[key] = os.environ[value]
        else:
            result[key] = value
    return result


def contract_placeholders(items: list[str], *, prefix: str = "") -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        key, separator, env_name = item.partition("=")
        if not separator or not key or not env_name:
            raise ValueError(f"expected NAME=ENV_NAME, received {item!r}")
        result[key] = f"{prefix}${{{env_name}}}" if prefix else f"${{{env_name}}}"
    return result


def _read_mapping(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return payload


def _example_from_schema(schema: Any) -> Any:
    if not isinstance(schema, dict):
        return {}
    if "default" in schema:
        return schema["default"]
    if "example" in schema:
        return schema["example"]
    if "const" in schema:
        return schema["const"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]

    schema_type = schema.get("type")
    if schema_type == "object" or "properties" in schema:
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        if not isinstance(properties, dict):
            return {}
        return {
            name: _example_from_schema(child)
            for name, child in properties.items()
            if name in required or "default" in child or "example" in child
        }
    if schema_type == "array":
        return []
    if schema_type == "integer":
        return int(schema.get("minimum", 0))
    if schema_type == "number":
        return float(schema.get("minimum", 0))
    if schema_type == "boolean":
        return False
    if schema_type == "string":
        if schema.get("format") == "email":
            return "review@example.test"
        return "REVIEW_REQUIRED"
    return None


def _looks_read_only(name: str, description: str) -> bool:
    lowered = f"{name} {description}".lower()
    mutating = ("create", "update", "delete", "write", "send", "run", "execute", "apply")
    if any(word in lowered for word in mutating):
        return False
    return name.lower().startswith(("get", "list", "read", "search", "find", "lookup", "query"))


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _drop_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_drop_none(item) for item in value]
    return value
