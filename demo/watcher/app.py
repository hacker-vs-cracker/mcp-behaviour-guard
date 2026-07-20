from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

ROOT = Path(os.getenv("WATCH_ROOT", "/runtime"))
_lock = threading.Lock()
_before: dict[str, tuple[int, str]] = {}


def _fingerprint(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return path.stat().st_size, digest.hexdigest()


def _snapshot() -> dict[str, tuple[int, str]]:
    if not ROOT.exists():
        return {}
    return {
        path.relative_to(ROOT).as_posix(): _fingerprint(path)
        for path in ROOT.rglob("*")
        if path.is_file()
    }


async def reset(_: Request) -> JSONResponse:
    global _before
    with _lock:
        _before = _snapshot()
    return JSONResponse({"reset": True, "files": len(_before)})


async def events(_: Request) -> JSONResponse:
    with _lock:
        after = _snapshot()
        previous = dict(_before)

    observed = []
    for path, fingerprint in after.items():
        old = previous.get(path)
        if old == fingerprint:
            continue
        observed.append(
            {
                "kind": "filesystem_write",
                "path": f"runtime/{path}",
                "operation": "created" if old is None else "modified",
            }
        )
    return JSONResponse({"events": observed})


async def healthz(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "filesystem-watcher"})


app = Starlette(
    routes=[
        Route("/reset", reset, methods=["POST"]),
        Route("/events", events, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
    ]
)
