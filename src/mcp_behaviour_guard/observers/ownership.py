from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import os
import stat
import tempfile
import threading
import weakref
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager, suppress
from contextvars import ContextVar
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..models import ServerSpec

_fcntl: Any | None = importlib.import_module("fcntl") if os.name == "posix" else None
_registry_guard = threading.Lock()
_local_locks: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop,
    dict[str, asyncio.Lock],
] = weakref.WeakKeyDictionary()
_held_keys: ContextVar[frozenset[str]] = ContextVar(
    "mcp_behaviour_guard_held_observer_keys",
    default=frozenset(),
)


def _canonical_http_target(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    port = parsed.port
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return scheme, (parsed.hostname or "").lower(), port


def server_ownership_key(server: ServerSpec) -> str:
    material: dict[str, Any]
    if server.transport == "streamable-http":
        material = {
            "transport": server.transport,
            "target": _canonical_http_target(server.url or ""),
        }
    else:
        material = {
            "transport": server.transport,
            "target": server.target_label,
            "command": server.command,
            "args": server.args,
            "cwd": (
                str(server.cwd.expanduser().resolve(strict=False))
                if server.cwd is not None
                else None
            ),
        }

    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"mcp-target:{hashlib.sha256(encoded).hexdigest()}"


def _ownership_keys(
    observers: Iterable[object],
    extra_keys: Iterable[str] = (),
) -> tuple[str, ...]:
    keys = {str(key) for key in extra_keys}
    for observer in observers:
        raw = getattr(observer, "ownership_keys", ())
        if callable(raw):
            raw = raw()
        for key in raw:
            keys.add(str(key))
    return tuple(sorted(keys))


def _local_lock(key: str) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    with _registry_guard:
        per_loop = _local_locks.setdefault(loop, {})
        lock = per_loop.get(key)
        if lock is None:
            lock = asyncio.Lock()
            per_loop[key] = lock
        return lock


def _secure_directory(path: Path) -> None:
    with suppress(FileExistsError):
        path.mkdir(mode=0o700)

    if path.is_symlink():
        raise PermissionError(f"observer lease directory must not be a symlink: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"observer lease path is not a directory: {path}")

    info = path.stat()
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError(f"observer lease directory is not owned by the current user: {path}")

    if stat.S_IMODE(info.st_mode) != 0o700:
        path.chmod(0o700)


def _lease_base_dir() -> Path:
    if os.name == "posix" and hasattr(os, "getuid"):
        return Path("/tmp")
    return Path(tempfile.gettempdir())


def _lock_path(key: str) -> Path:
    uid = str(os.getuid()) if hasattr(os, "getuid") else "local"
    root = _lease_base_dir() / f"mcp-behaviour-guard-{uid}"
    _secure_directory(root)
    directory = root / "observer-leases"
    _secure_directory(directory)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return directory / f"{digest}.lock"


async def _acquire_os_lock(key: str) -> int | None:
    if _fcntl is None:
        return None

    path = _lock_path(key)
    while True:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            os.close(fd)
            await asyncio.sleep(0.02)
        except BaseException:
            os.close(fd)
            raise


def _release_os_lock(fd: int | None) -> None:
    if fd is None:
        return
    try:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_UN)
    finally:
        os.close(fd)


@asynccontextmanager
async def observer_ownership(
    observers: Iterable[object],
    *,
    extra_keys: Iterable[str] = (),
) -> AsyncIterator[None]:
    requested = frozenset(_ownership_keys(observers, extra_keys))
    already_held = _held_keys.get()
    missing = tuple(sorted(requested - already_held))

    if not missing:
        yield
        return

    local: list[asyncio.Lock] = []
    file_descriptors: list[int | None] = []
    token = None

    try:
        for key in missing:
            lock = _local_lock(key)
            await lock.acquire()
            local.append(lock)

        for key in missing:
            file_descriptors.append(await _acquire_os_lock(key))

        token = _held_keys.set(already_held | requested)
        yield
    finally:
        if token is not None:
            _held_keys.reset(token)
        for fd in reversed(file_descriptors):
            _release_os_lock(fd)
        for lock in reversed(local):
            lock.release()
