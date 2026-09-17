from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from pydantic import ValidationError

from .models import Contract

_ENV_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-(.*?))?\}")


class ContractError(ValueError):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc

        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate mapping key: {key!r}",
                key_node.start_mark,
            )

        mapping[key] = loader.construct_object(value_node, deep=deep)

    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _expand_env(value: Any, resolved_values: set[str] | None = None) -> Any:
    if isinstance(value, dict):
        return {key: _expand_env(item, resolved_values) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env(item, resolved_values) for item in value]
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in os.environ:
            replacement = os.environ[name]
        elif default is not None:
            replacement = default
        else:
            raise ContractError(f"environment variable {name!r} is required by the contract")

        if resolved_values is not None and replacement:
            resolved_values.add(replacement)
        return replacement

    return _ENV_PATTERN.sub(replace, value)


def _redact_resolved_values(message: str, values: set[str]) -> str:
    for value in sorted(values, key=len, reverse=True):
        if value:
            message = message.replace(value, "<redacted>")
    return message


def _safe_validation_message(
    error: ValidationError,
    resolved_values: set[str],
) -> str:
    rendered: list[str] = []
    for item in error.errors(
        include_url=False,
        include_context=False,
        include_input=False,
    ):
        location = ".".join(str(part) for part in item.get("loc", ()))
        message = str(item.get("msg", "invalid value"))
        rendered.append(f"{location}: {message}" if location else message)

    return _redact_resolved_values("; ".join(rendered), resolved_values)


def load_contract(path: Path) -> Contract:
    try:
        raw = yaml.load(
            path.read_text(encoding="utf-8"),
            Loader=_UniqueKeyLoader,
        )
    except FileNotFoundError as exc:
        raise ContractError(f"contract not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ContractError("the contract root must be a mapping")

    resolved_values: set[str] = set()
    expanded = _expand_env(raw, resolved_values)

    try:
        return Contract.model_validate(expanded)
    except ValidationError as exc:
        raise ContractError(_safe_validation_message(exc, resolved_values)) from exc
    except Exception as exc:
        raise ContractError(_redact_resolved_values(str(exc), resolved_values)) from exc


def validate_target(contract: Contract, lab_mode: bool) -> None:
    del lab_mode  # destructive gating is enforced by the engine
    server = contract.server
    if server.transport == "streamable-http":
        parsed = urlparse(server.url or "")
        host = parsed.hostname or ""
        allowed = set(contract.safety.target_allowlist) | set(server.allowed_hosts)
        if host not in allowed:
            raise ContractError(
                f"target host {host!r} is not allowlisted; add it to safety.target_allowlist"
            )
        return

    command = server.command or ""
    command_name = Path(command).name
    allowed_commands = {Path(item).name for item in contract.safety.allowed_stdio_commands}
    if command_name not in allowed_commands:
        raise ContractError(
            f"stdio command {command_name!r} is not allowlisted; "
            "add it to safety.allowed_stdio_commands"
        )
    if not Path(command).is_absolute() and shutil.which(command) is None:
        raise ContractError(f"stdio command {command!r} was not found on PATH")
    if server.cwd is not None and not server.cwd.exists():
        raise ContractError(f"stdio working directory does not exist: {server.cwd}")
