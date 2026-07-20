from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_path(value: Any, dotted_path: str) -> Any:
    current = value
    for part in dotted_path.removeprefix("$.").split("."):
        if not part:
            continue
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            return None
    return current


def matches_any(value: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch(value, pattern) for pattern in patterns)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def response_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: response_shape(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [response_shape(item) for item in value[:3]]
    return type(value).__name__
