from __future__ import annotations

import threading
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

_lock = threading.Lock()
_events: list[dict[str, Any]] = []


async def collect(request: Request) -> JSONResponse:
    payload = await request.json()
    with _lock:
        _events.append(payload)
    return JSONResponse({"accepted": True})


async def events(_: Request) -> JSONResponse:
    with _lock:
        return JSONResponse({"events": list(_events)})


async def reset(_: Request) -> JSONResponse:
    with _lock:
        _events.clear()
    return JSONResponse({"reset": True})


async def healthz(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "mock-telemetry"})


app = Starlette(
    routes=[
        Route("/collect", collect, methods=["POST"]),
        Route("/events", events, methods=["GET"]),
        Route("/reset", reset, methods=["POST"]),
        Route("/healthz", healthz, methods=["GET"]),
    ]
)
