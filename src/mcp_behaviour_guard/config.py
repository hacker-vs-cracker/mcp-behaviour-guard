from __future__ import annotations

import ipaddress
import os
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit

import yaml
from pydantic import ValidationError

from .models import Contract, ServerSpec

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


def resolve_restricted_stdio_launch(server: ServerSpec) -> tuple[str, Path]:
    if server.transport != "stdio":
        raise ContractError("restricted STDIO launch requires stdio transport")

    launch = server.stdio_launch
    if launch is None or launch.mode != "restricted":
        raise ContractError("restricted STDIO launch policy is not enabled")

    if not launch.allowed_executables:
        raise ContractError("restricted STDIO launch requires allowed executables")

    canonical_allowed: set[Path] = set()
    for configured in launch.allowed_executables:
        if not configured.is_absolute():
            raise ContractError("restricted STDIO allowed executable paths must be absolute")
        try:
            resolved = configured.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ContractError(
                f"restricted STDIO allowed executable is unavailable: {configured}"
            ) from exc
        if resolved != configured:
            raise ContractError(
                "restricted STDIO allowed executable paths must already be canonical"
            )
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise ContractError(
                f"restricted STDIO allowed executable is not executable: {configured}"
            )
        canonical_allowed.add(resolved)

    command = server.command or ""
    command_path = Path(command)
    if command_path.is_absolute():
        candidate = command_path
    else:
        if command_path.name != command:
            raise ContractError(
                "restricted STDIO command must be an absolute path or executable basename"
            )
        located = shutil.which(command)
        if located is None:
            raise ContractError(f"restricted STDIO command {command!r} was not found")
        candidate = Path(located)

    launch_command = Path(os.path.abspath(candidate))

    try:
        canonical_command = launch_command.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ContractError(
            f"restricted STDIO executable {command!r} could not be resolved"
        ) from exc

    if not canonical_command.is_file() or not os.access(canonical_command, os.X_OK):
        raise ContractError(
            f"restricted STDIO executable {str(canonical_command)!r} is not executable"
        )
    if canonical_command not in canonical_allowed:
        raise ContractError(
            f"restricted STDIO executable {str(canonical_command)!r} is not allowlisted"
        )

    if server.cwd is None:
        raise ContractError("restricted STDIO launch requires an explicit cwd")
    if not server.cwd.is_absolute():
        raise ContractError("restricted STDIO cwd must be absolute")

    if not launch.allowed_cwd_roots:
        raise ContractError("restricted STDIO launch requires allowed cwd roots")

    canonical_roots: list[Path] = []
    for configured_root in launch.allowed_cwd_roots:
        if not configured_root.is_absolute():
            raise ContractError("restricted STDIO allowed cwd roots must be absolute")
        try:
            root = configured_root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ContractError(
                f"restricted STDIO allowed cwd root is unavailable: {configured_root}"
            ) from exc
        if root != configured_root:
            raise ContractError("restricted STDIO allowed cwd roots must already be canonical")
        if not root.is_dir():
            raise ContractError(
                f"restricted STDIO allowed cwd root is not a directory: {configured_root}"
            )
        canonical_roots.append(root)

    try:
        canonical_cwd = server.cwd.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ContractError(f"restricted STDIO cwd is unavailable: {server.cwd}") from exc

    if not canonical_cwd.is_dir():
        raise ContractError("restricted STDIO cwd must resolve to a directory")

    if not any(
        canonical_cwd == root or canonical_cwd.is_relative_to(root) for root in canonical_roots
    ):
        raise ContractError("restricted STDIO cwd is outside allowed roots")

    return str(launch_command), canonical_cwd


_HttpOrigin = tuple[str, str, int]


def _normalize_http_hostname(hostname: str, *, label: str) -> str:
    candidate = hostname.rstrip(".")
    if not candidate:
        raise ContractError(f"{label} is missing a hostname")

    try:
        return ipaddress.ip_address(candidate).compressed.lower()
    except ValueError:
        try:
            return candidate.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ContractError(f"{label} contains an invalid hostname") from exc


def _parse_http_origin(
    value: str,
    *,
    origin_only: bool,
    label: str,
) -> _HttpOrigin:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ContractError(f"{label} contains an invalid host or port") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ContractError(f"{label} must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ContractError(f"{label} must not contain URL userinfo")

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ContractError(f"{label} contains an invalid host or port") from exc

    if not hostname:
        raise ContractError(f"{label} is missing a hostname")

    if origin_only and (parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ContractError(f"{label} must be an origin without path, query, or fragment")

    normalized_host = _normalize_http_hostname(hostname, label=label)
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    return scheme, normalized_host, effective_port


def _render_http_origin(origin: _HttpOrigin) -> str:
    scheme, hostname, port = origin
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{scheme}://{rendered_host}:{port}"


def resolve_restricted_http_destination(
    server: ServerSpec,
) -> tuple[frozenset[_HttpOrigin], bool]:
    policy = server.http_destination
    if server.transport != "streamable-http" or policy is None:
        raise ContractError("restricted HTTP destination policy is not configured")
    if not policy.allowed_origins:
        raise ContractError("restricted HTTP destination policy requires allowed origins")
    if not server.url:
        raise ContractError("restricted HTTP destination policy requires server.url")

    allowed = frozenset(
        _parse_http_origin(
            origin,
            origin_only=True,
            label="restricted HTTP allowed origin",
        )
        for origin in policy.allowed_origins
    )
    target = _parse_http_origin(
        server.url,
        origin_only=False,
        label="restricted HTTP target URL",
    )
    if target not in allowed:
        raise ContractError(
            f"restricted HTTP target origin {_render_http_origin(target)!r} is not allowlisted"
        )
    return allowed, policy.allow_redirects


def validate_restricted_http_request_url(
    url: str,
    allowed_origins: frozenset[_HttpOrigin],
) -> None:
    origin = _parse_http_origin(
        url,
        origin_only=False,
        label="restricted HTTP request URL",
    )
    if origin not in allowed_origins:
        raise ContractError(
            f"restricted HTTP request origin {_render_http_origin(origin)!r} is not allowlisted"
        )


def validate_target(contract: Contract, lab_mode: bool) -> None:
    del lab_mode  # destructive gating is enforced by the engine
    server = contract.server
    if server.transport == "streamable-http":
        if server.http_destination is not None:
            resolve_restricted_http_destination(server)
            return

        parsed = urlparse(server.url or "")
        host = parsed.hostname or ""
        allowed = set(contract.safety.target_allowlist) | set(server.allowed_hosts)
        if host not in allowed:
            raise ContractError(
                f"target host {host!r} is not allowlisted; add it to safety.target_allowlist"
            )
        return

    launch = server.stdio_launch
    if launch is not None and launch.mode == "restricted":
        resolve_restricted_stdio_launch(server)
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
