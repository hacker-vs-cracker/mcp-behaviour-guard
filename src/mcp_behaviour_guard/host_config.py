from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import yaml

from .util import stable_hash, utc_now

_SERVER_KEYS = ("servers", "mcpServers")
_SECRETISH_KEYS = {
    "authorization",
    "token",
    "access_token",
    "api_key",
    "apikey",
    "password",
    "secret",
}


def snapshot_host_config(path: Path, host_label: str | None = None) -> dict[str, Any]:
    payload = _load_json_config(path)
    if not isinstance(payload, dict):
        raise ValueError("MCP host configuration must be a JSON object")

    server_mapping = _find_server_mapping(payload)
    if server_mapping is None:
        raise ValueError("No 'servers' or 'mcpServers' mapping was found")

    servers: dict[str, Any] = {}
    for server_name, raw_server in sorted(server_mapping.items(), key=lambda item: str(item[0])):
        if not isinstance(raw_server, dict):
            continue
        servers[str(server_name)] = _normalise_server_entry(raw_server)

    host_controls = _normalise_host_controls(payload)
    snapshot = {
        "format_version": 1,
        "captured_at": utc_now(),
        "host": host_label or path.stem,
        "source": path.name,
        "servers": servers,
        "host_controls": host_controls,
    }
    snapshot["fingerprint"] = stable_hash(
        {
            "host": snapshot["host"],
            "servers": servers,
            "host_controls": host_controls,
        }
    )
    return snapshot


def compare_host_config_snapshots(
    approved: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    approved_servers = approved.get("servers", {})
    current_servers = current.get("servers", {})
    if not isinstance(approved_servers, dict) or not isinstance(current_servers, dict):
        raise ValueError("Host config snapshots must contain a servers mapping")

    approved_names = set(approved_servers)
    current_names = set(current_servers)
    changed: dict[str, Any] = {}
    for name in sorted(approved_names & current_names):
        before = approved_servers[name]
        after = current_servers[name]
        if stable_hash(before) != stable_hash(after):
            changed[name] = {"before": before, "after": after}

    approved_controls = approved.get("host_controls", {})
    current_controls = current.get("host_controls", {})
    controls_changed = stable_hash(approved_controls) != stable_hash(current_controls)

    diff = {
        "added_servers": sorted(current_names - approved_names),
        "removed_servers": sorted(approved_names - current_names),
        "changed_servers": changed,
        "host_controls_changed": controls_changed,
    }
    if controls_changed:
        diff["host_controls"] = {
            "before": approved_controls,
            "after": current_controls,
        }
    diff["drift_detected"] = bool(
        diff["added_servers"] or diff["removed_servers"] or changed or controls_changed
    )
    return diff


def write_host_config_snapshot(snapshot: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")


def load_host_config_snapshot(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Host config snapshot must be a JSON object")
    return payload


def _find_server_mapping(payload: dict[str, Any]) -> dict[str, Any] | None:
    for key in _SERVER_KEYS:
        candidate = payload.get(key)
        if isinstance(candidate, dict):
            return candidate

    mcp_section = payload.get("mcp")
    if isinstance(mcp_section, dict):
        for key in _SERVER_KEYS:
            candidate = mcp_section.get(key)
            if isinstance(candidate, dict):
                return candidate
    return None


def _normalise_server_entry(raw_server: dict[str, Any]) -> dict[str, Any]:
    url = raw_server.get("url") or raw_server.get("serverUrl")
    command = raw_server.get("command")
    transport = raw_server.get("type") or raw_server.get("transport")
    if not transport:
        transport = "streamable-http" if url else "stdio" if command else "unknown"

    normalised: dict[str, Any] = {
        "transport": str(transport),
        "url": _redact_url(str(url)) if url else None,
        "command": str(command) if command else None,
        "args": _redact_args(raw_server.get("args", [])),
        "cwd": str(raw_server.get("cwd")) if raw_server.get("cwd") else None,
        "environment": _redacted_mapping(raw_server.get("env") or raw_server.get("environment")),
        "headers": _redacted_mapping(raw_server.get("headers")),
    }

    handled = {
        "url",
        "serverUrl",
        "command",
        "type",
        "transport",
        "args",
        "cwd",
        "env",
        "environment",
        "headers",
    }
    extra_fields = {
        str(key): raw_server[key] for key in sorted(raw_server, key=str) if key not in handled
    }
    if extra_fields:
        # Host formats keep growing (sandbox flags, envFile, OAuth, tool filters, TLS, timeouts).
        # Keep those changes in the provenance fingerprint without persisting their raw values.
        normalised["other"] = _redact_structure(extra_fields)

    return {key: value for key, value in normalised.items() if value not in (None, {}, [])}


def _redact_url(raw_url: str) -> str:
    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
    except ValueError:
        # A malformed endpoint still needs a stable, non-secret provenance value.
        return f"sha256:{stable_hash(raw_url)[:16]}"

    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    if port is not None:
        hostname = f"{hostname}:{port}"
    if parsed.username is not None or parsed.password is not None:
        hostname = f"<redacted>@{hostname}"

    query_items: list[tuple[str, str]] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _looks_secretish(key):
            safe_value = "<redacted>"
        elif value.startswith("${") and value.endswith("}"):
            safe_value = value
        else:
            safe_value = f"sha256:{stable_hash(value)[:16]}"
        query_items.append((key, safe_value))

    return urlunsplit((parsed.scheme, hostname, parsed.path, urlencode(query_items), ""))


def _redact_args(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []

    arguments = [str(item) for item in value]
    redacted: list[str] = []
    hide_next_value = False
    for argument in arguments:
        if hide_next_value:
            redacted.append(argument if argument.startswith("${") else "<redacted>")
            hide_next_value = False
            continue

        key, separator, inline_value = argument.partition("=")
        lowered_key = key.lstrip("-").lower().replace("-", "_")
        if separator and _looks_secretish(lowered_key):
            safe_value = inline_value if inline_value.startswith("${") else "<redacted>"
            redacted.append(f"{key}={safe_value}")
            continue
        if argument.startswith("-") and _looks_secretish(lowered_key):
            redacted.append(argument)
            hide_next_value = True
            continue
        if argument in {"--header", "-H"}:
            redacted.append(argument)
            hide_next_value = True
            continue
        redacted.append(argument)
    return redacted


def _looks_secretish(value: str) -> bool:
    normalised = value.lower().replace("-", "_").replace(".", "_")
    return normalised in _SECRETISH_KEYS or any(
        secretish in normalised for secretish in _SECRETISH_KEYS
    )


def _redacted_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}

    redacted: dict[str, str] = {}
    for key, raw_value in sorted(value.items(), key=lambda item: str(item[0])):
        key_text = str(key)
        value_text = str(raw_value)
        if value_text.startswith("${") and value_text.endswith("}"):
            redacted[key_text] = value_text
        elif _looks_secretish(key_text):
            redacted[key_text] = "<redacted>"
        else:
            # Configuration provenance only needs to know that a value changed. Avoid persisting
            # credentials or private endpoints accidentally embedded in environment values.
            redacted[key_text] = f"sha256:{stable_hash(value_text)[:16]}"
    return redacted


def _normalise_host_controls(payload: dict[str, Any]) -> dict[str, Any]:
    controls: dict[str, Any] = {}
    for key in ("sandbox", "inputs"):
        if key in payload:
            controls[key] = _redact_structure(payload[key])
    return controls


def _redact_structure(value: Any, key_hint: str | None = None) -> Any:
    if key_hint and _looks_secretish(key_hint):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(key): _redact_structure(value[key], str(key)) for key in sorted(value, key=str)}
    if isinstance(value, list):
        return [_redact_structure(item) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value

    text = str(value)
    if text.startswith("${") and text.endswith("}"):
        return text
    return f"sha256:{stable_hash(text)[:16]}"


def _load_json_config(path: Path) -> dict[str, Any]:
    raw_text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        # Host configs commonly use JSONC or JSON5-style syntax. We only need the object
        # structure here, so strip comments first and prefer strict JSON before the YAML parser's
        # small JSON5-compatible subset (unquoted keys, single quotes, trailing commas).
        cleaned = _strip_json_comments(raw_text)
        try:
            payload = json.loads(_strip_trailing_commas(cleaned))
        except json.JSONDecodeError:
            payload = yaml.safe_load(cleaned)
    if not isinstance(payload, dict):
        raise ValueError("MCP host configuration must be a JSON object")
    return payload


def _strip_json_comments(raw_text: str) -> str:
    cleaned: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(raw_text):
        current = raw_text[index]
        following = raw_text[index + 1] if index + 1 < len(raw_text) else ""

        if quote:
            cleaned.append(current)
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = None
            index += 1
            continue

        if current in {'"', "'"}:
            quote = current
            cleaned.append(current)
            index += 1
            continue

        if current == "/" and following == "/":
            index += 2
            while index < len(raw_text) and raw_text[index] not in "\r\n":
                index += 1
            continue

        if current == "/" and following == "*":
            index += 2
            while index + 1 < len(raw_text):
                if raw_text[index] == "*" and raw_text[index + 1] == "/":
                    index += 2
                    break
                if raw_text[index] in "\r\n":
                    cleaned.append(raw_text[index])
                index += 1
            continue

        cleaned.append(current)
        index += 1

    return "".join(cleaned)


def _strip_trailing_commas(raw_text: str) -> str:
    cleaned: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(raw_text):
        current = raw_text[index]
        if quote:
            cleaned.append(current)
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = None
            index += 1
            continue

        if current in {'"', "'"}:
            quote = current
            cleaned.append(current)
            index += 1
            continue

        if current == ",":
            lookahead = index + 1
            while lookahead < len(raw_text) and raw_text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(raw_text) and raw_text[lookahead] in "]}":
                index += 1
                continue

        cleaned.append(current)
        index += 1
    return "".join(cleaned)
