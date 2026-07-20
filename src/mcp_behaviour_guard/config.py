from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .models import Contract

_ENV_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-(.*?))?\}")


class ContractError(ValueError):
    pass


def _expand_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in os.environ:
            return os.environ[name]
        if default is not None:
            return default
        raise ContractError(f"environment variable {name!r} is required by the contract")

    return _ENV_PATTERN.sub(replace, value)


def load_contract(path: Path) -> Contract:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractError(f"contract not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ContractError("the contract root must be a mapping")

    try:
        return Contract.model_validate(_expand_env(raw))
    except Exception as exc:
        raise ContractError(str(exc)) from exc


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
