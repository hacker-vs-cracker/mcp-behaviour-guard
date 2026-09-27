from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import __version__
from .evidence import contract_secrets
from .models import Contract, RunSummary
from .util import file_sha256, stable_hash

_RECEIPT_SCHEMA_VERSION = 1
_NORMALIZATION_VERSION = 1
_SENSITIVE_KEY = re.compile(
    r"(?:authorization|password|secret|token|api.?key|cookie|credential)",
    re.I,
)
_BEARER = re.compile(r"\bBearer\s+[^\s,;\"']+", re.I)
_URL_CREDENTIAL = re.compile(r"(?<=://)[^/@\s]+:[^/@\s]+@")
_QUERY_SECRET = re.compile(
    r"([?&](?:token|api_key|secret|password)=)[^&#\s]+",
    re.I,
)
_STRUCTURAL_NAME_MAP_KEYS = frozenset(
    {
        "identities",
        "tools",
        "observers",
        "tenant_probes",
    }
)


def write_run_receipt(
    *,
    summary: RunSummary,
    run_dir: Path,
    contract: Contract,
    contract_path: Path,
    lab_mode: bool,
) -> Path:
    safe_contract = _secret_insensitive_contract(contract)
    report_path = run_dir / "report.json"
    inventory_path = run_dir / "tool-inventory.json"

    protocol_versions = sorted(
        {item.protocol_version for item in summary.invocations if item.protocol_version is not None}
    )

    receipt: dict[str, Any] = {
        "schema_version": _RECEIPT_SCHEMA_VERSION,
        "normalization_version": _NORMALIZATION_VERSION,
        "report_schema_version": summary.schema_version,
        "run": {
            "run_id": summary.run_id,
            "attempt_id": None,
            "started_at": summary.started_at,
            "finished_at": summary.finished_at,
            "completion": "completed",
        },
        "context": {
            "logical_target": summary.target,
            "deployment_identity": None,
            "credential_principal": None,
            "contract_source_sha256": file_sha256(contract_path),
            "target_input_sha256": stable_hash(
                _target_input_projection(safe_contract.get("server", {}))
            ),
            "effective_policy_sha256": stable_hash(_effective_policy_projection(safe_contract)),
            "identity_profile_sha256": stable_hash(safe_contract.get("identities", {})),
            "observer_scope_sha256": stable_hash(safe_contract.get("observers", {})),
            "fixture_profile": {"lab_mode": lab_mode},
        },
        "runner": {
            "version": __version__,
            "mcp_sdk_version": summary.sdk_version,
            "transport": summary.transport,
            "state_strategy": summary.state_strategy,
            "protocol_versions": protocol_versions or None,
        },
        "checks": {
            "finding_ids": sorted(item.test_id for item in summary.findings),
            "definition_sha256": stable_hash(_check_definition_projection(safe_contract)),
        },
        "artifacts": {
            "report_json_sha256": (file_sha256(report_path) if report_path.exists() else None),
            "tool_inventory_sha256": (
                file_sha256(inventory_path) if inventory_path.exists() else None
            ),
        },
    }

    path = run_dir / "receipt.json"
    path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def _secret_insensitive_contract(contract: Contract) -> dict[str, Any]:
    secrets = contract_secrets(contract)
    payload = contract.model_dump(mode="json")
    scrubbed = _scrub(payload, secrets)
    if not isinstance(scrubbed, dict):
        raise TypeError("contract normalization must produce a mapping")
    return scrubbed


def _scrub(
    value: Any,
    secrets: set[str],
    *,
    key: str | None = None,
) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for raw_key, item in value.items():
            label = str(raw_key)
            is_structural_name = key in _STRUCTURAL_NAME_MAP_KEYS
            if _SENSITIVE_KEY.search(label) and not is_structural_name:
                cleaned[label] = "[credential]"
            else:
                cleaned[label] = _scrub(item, secrets, key=label)
        return cleaned

    if isinstance(value, list):
        return [_scrub(item, secrets, key=key) for item in value]

    if isinstance(value, tuple):
        return [_scrub(item, secrets, key=key) for item in value]

    if isinstance(value, str):
        text = _BEARER.sub("Bearer [credential]", value)
        text = _URL_CREDENTIAL.sub("[credential]@", text)
        text = _QUERY_SECRET.sub(r"\1[credential]", text)
        for secret in sorted(secrets, key=len, reverse=True):
            if secret:
                text = text.replace(secret, "[credential]")
        return text

    return value


def _target_input_projection(server: Any) -> dict[str, Any]:
    if not isinstance(server, dict):
        return {}
    return {
        key: server[key]
        for key in ("url", "command", "args", "cwd", "environment")
        if key in server
    }


def _server_policy_projection(server: Any) -> dict[str, Any]:
    if not isinstance(server, dict):
        return {}
    return {
        key: server[key]
        for key in (
            "timeout_seconds",
            "verify_tls",
            "allowed_hosts",
            "http_destination",
            "stdio_launch",
        )
        if key in server
    }


def _effective_policy_projection(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": contract.get("version"),
        "server": _server_policy_projection(contract.get("server", {})),
        "identities": contract.get("identities", {}),
        "tools": contract.get("tools", {}),
        "session_tests": contract.get("session_tests", []),
        "observers": contract.get("observers", {}),
        "safety": contract.get("safety", {}),
        "temporal_integrity": contract.get("temporal_integrity", {}),
    }


def _check_definition_projection(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": contract.get("version"),
        "identities": contract.get("identities", {}),
        "tools": contract.get("tools", {}),
        "session_tests": contract.get("session_tests", []),
        "temporal_integrity": contract.get("temporal_integrity", {}),
    }
