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
_NORMALIZATION_VERSION = 3
_CREDENTIAL_MARKER = "[credential]"
_UNVERIFIED_SENSITIVE_STRING = "[unverified-sensitive-string]"
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


def write_run_receipt(
    *,
    summary: RunSummary,
    run_dir: Path,
    contract: Contract,
    contract_path: Path,
    lab_mode: bool,
) -> Path:
    safe_contract, unverified_sensitive_fields = _normalize_contract(contract)
    report_path = run_dir / "report.json"
    inventory_path = run_dir / "tool-inventory.json"

    protocol_versions = sorted(
        {item.protocol_version for item in summary.invocations if item.protocol_version is not None}
    )

    receipt: dict[str, Any] = {
        "schema_version": _RECEIPT_SCHEMA_VERSION,
        "normalization_version": _NORMALIZATION_VERSION,
        "normalization": {
            "unverified_sensitive_fields": unverified_sensitive_fields,
        },
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
    normalized, _ = _normalize_contract(contract)
    return normalized


def _normalize_contract(contract: Contract) -> tuple[dict[str, Any], list[str]]:
    secrets = contract_secrets(contract)
    payload = contract.model_dump(mode="json")
    unverified_sensitive_fields: set[str] = set()
    scrubbed = _scrub(
        payload,
        secrets,
        path=(),
        semantic_arguments=False,
        sensitive_semantic_context=False,
        unverified_sensitive_fields=unverified_sensitive_fields,
    )
    if not isinstance(scrubbed, dict):
        raise TypeError("contract normalization must produce a mapping")
    return scrubbed, sorted(unverified_sensitive_fields)


def _is_credential_map_path(path: tuple[str, ...]) -> bool:
    if path == ("server", "environment"):
        return True
    return len(path) == 3 and path[0] == "identities" and path[2] in {"headers", "environment"}


def _is_semantic_argument_path(path: tuple[str, ...]) -> bool:
    if len(path) == 3 and path[0] == "tools" and path[2] == "probe_arguments":
        return True
    if (
        len(path) == 5
        and path[0] == "tools"
        and path[2] == "tenant_probes"
        and path[4] == "arguments"
    ):
        return True
    if (
        len(path) == 5
        and path[0] == "tools"
        and path[2] == "policy_probes"
        and path[4] == "arguments"
    ):
        return True
    if (
        len(path) == 4
        and path[0] == "tools"
        and path[2] == "replay_probe"
        and path[3] == "arguments"
    ):
        return True
    if (
        len(path) == 4
        and path[0] == "session_tests"
        and path[2] in {"write", "read"}
        and path[3] == "arguments"
    ):
        return True
    if path == ("temporal_integrity", "driver_arguments"):
        return True
    return len(path) == 3 and path[0] == "temporal_integrity" and path[1] == "prompt_probes"


def _scrub(
    value: Any,
    secrets: set[str],
    *,
    path: tuple[str, ...],
    semantic_arguments: bool,
    sensitive_semantic_context: bool,
    unverified_sensitive_fields: set[str],
) -> Any:
    if isinstance(value, dict):
        if _is_credential_map_path(path):
            return _scrub_credential_map(
                value,
                secrets,
                path=path,
                unverified_sensitive_fields=unverified_sensitive_fields,
            )

        semantic_here = semantic_arguments or _is_semantic_argument_path(path)
        cleaned: dict[str, Any] = {}
        for raw_key, item in value.items():
            label = str(raw_key)
            child_path = (*path, label)
            child_sensitive = (
                sensitive_semantic_context or bool(_SENSITIVE_KEY.search(label))
                if semantic_here
                else False
            )
            cleaned[label] = _scrub(
                item,
                secrets,
                path=child_path,
                semantic_arguments=semantic_here,
                sensitive_semantic_context=child_sensitive,
                unverified_sensitive_fields=unverified_sensitive_fields,
            )
        return cleaned

    if isinstance(value, list):
        return [
            _scrub(
                item,
                secrets,
                path=(*path, str(index)),
                semantic_arguments=semantic_arguments,
                sensitive_semantic_context=sensitive_semantic_context,
                unverified_sensitive_fields=unverified_sensitive_fields,
            )
            for index, item in enumerate(value)
        ]

    if isinstance(value, tuple):
        return [
            _scrub(
                item,
                secrets,
                path=(*path, str(index)),
                semantic_arguments=semantic_arguments,
                sensitive_semantic_context=sensitive_semantic_context,
                unverified_sensitive_fields=unverified_sensitive_fields,
            )
            for index, item in enumerate(value)
        ]

    if isinstance(value, str):
        text = _scrub_string(value, secrets)
        if semantic_arguments and sensitive_semantic_context and text == value:
            unverified_sensitive_fields.add(".".join(path))
            return _UNVERIFIED_SENSITIVE_STRING
        return text

    return value


def _scrub_credential_map(
    value: dict[Any, Any],
    secrets: set[str],
    *,
    path: tuple[str, ...],
    unverified_sensitive_fields: set[str],
) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for raw_key, item in value.items():
        label = str(raw_key)
        child_path = (*path, label)
        if _SENSITIVE_KEY.search(label):
            cleaned[label] = _CREDENTIAL_MARKER
        else:
            cleaned[label] = _scrub(
                item,
                secrets,
                path=child_path,
                semantic_arguments=False,
                sensitive_semantic_context=False,
                unverified_sensitive_fields=unverified_sensitive_fields,
            )
    return cleaned


def _scrub_string(value: str, secrets: set[str]) -> str:
    text = _BEARER.sub(f"Bearer {_CREDENTIAL_MARKER}", value)
    text = _URL_CREDENTIAL.sub(f"{_CREDENTIAL_MARKER}@", text)
    text = _QUERY_SECRET.sub(rf"\1{_CREDENTIAL_MARKER}", text)
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            text = text.replace(secret, _CREDENTIAL_MARKER)
    return text


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
