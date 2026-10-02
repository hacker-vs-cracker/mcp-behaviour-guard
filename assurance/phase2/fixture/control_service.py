from __future__ import annotations

import argparse
import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from store import FixtureError, FixtureStore

_ATTEMPT_ACTION = re.compile(r"^/attempts/([A-Za-z0-9._-]+)/([A-Za-z-]+)$")
_ATTEMPT_GET = re.compile(r"^/attempts/([A-Za-z0-9._-]+)$")


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ControlHandler(BaseHTTPRequestHandler):
    store: FixtureStore

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: HTTPStatus, payload: object) -> None:
        body = _json_bytes(payload)
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        value = json.loads(raw or b"{}")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            if path == "/health":
                self._send(HTTPStatus.OK, {"status": "ok", "service": "fixture-control"})
                return
            if path == "/observer/events":
                self._send(HTTPStatus.OK, {"events": self.store.observer_events()})
                return
            match = _ATTEMPT_GET.fullmatch(path)
            if match:
                self._send(HTTPStatus.OK, self.store.snapshot(match.group(1)))
                return
        except FixtureError as exc:
            self._send(HTTPStatus.CONFLICT, {"error": type(exc).__name__, "detail": str(exc)})
            return
        self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            if path == "/attempts":
                body = self._read_json()
                requested = body.get("attempt_id")
                if requested is not None and not isinstance(requested, str):
                    raise ValueError("attempt_id must be a string")
                credential = self.store.create_attempt(requested)
                self._send(
                    HTTPStatus.CREATED,
                    {"attempt_id": credential.attempt_id, "token": credential.token},
                )
                return
            if path == "/observer/reset":
                cursor = self.store.reset_observer_cursor()
                self._send(HTTPStatus.OK, {"cursor_seq": cursor})
                return
            match = _ATTEMPT_ACTION.fullmatch(path)
            if match:
                attempt_id, action = match.groups()
                if action == "open":
                    self.store.open_attempt(attempt_id)
                    self._send(HTTPStatus.OK, {"attempt_id": attempt_id, "state": "OPEN"})
                    return
                if action == "close":
                    self.store.close_attempt(attempt_id)
                    self._send(HTTPStatus.OK, {"attempt_id": attempt_id, "state": "FENCED"})
                    return
                if action == "abort-recovery":
                    self.store.abort_recovery(attempt_id)
                    self._send(HTTPStatus.OK, {"attempt_id": attempt_id, "state": "ABORTED"})
                    return
                if action == "final-snapshot":
                    self._send(HTTPStatus.OK, self.store.final_snapshot(attempt_id))
                    return
                if action == "finalize":
                    self.store.finalize_attempt(attempt_id)
                    self._send(HTTPStatus.OK, {"attempt_id": attempt_id, "state": "FINALIZED"})
                    return
        except ValueError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except FixtureError as exc:
            self._send(HTTPStatus.CONFLICT, {"error": type(exc).__name__, "detail": str(exc)})
            return
        self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})


def make_server(store: FixtureStore, host: str, port: int) -> ThreadingHTTPServer:
    handler = type("BoundControlHandler", (ControlHandler,), {"store": store})
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 2 trusted fixture control/audit plane")
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    store = FixtureStore(args.db)
    store.bootstrap()
    server = make_server(store, args.host, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
