from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from store import (
    FixtureError,
    FixtureStore,
    InvalidCredential,
    SimulatedResponseLoss,
    StaleCredential,
)


def _json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AppHandler(BaseHTTPRequestHandler):
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

    def _token(self) -> str:
        value = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if not value.startswith(prefix) or not value[len(prefix) :].strip():
            raise InvalidCredential("missing bearer credential")
        return value[len(prefix) :].strip()

    def _read_json(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        value = json.loads(raw or b"{}")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/health":
            self._send(HTTPStatus.OK, {"status": "ok", "service": "fixture-app"})
            return
        if path.startswith("/records/"):
            try:
                token = self._token()
                record_id = unquote(path.removeprefix("/records/"))
                record = self.store.read_record(token, record_id)
            except (InvalidCredential, StaleCredential) as exc:
                self._send(HTTPStatus.UNAUTHORIZED, {"error": type(exc).__name__})
                return
            except FixtureError as exc:
                self._send(HTTPStatus.CONFLICT, {"error": type(exc).__name__})
                return
            if record is None:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            else:
                self._send(HTTPStatus.OK, {"record": record})
            return
        self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != "/records/write":
            self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        try:
            token = self._token()
            body = self._read_json()
            record_id = body.get("record_id")
            value = body.get("value")
            request_id = body.get("request_id")
            if not isinstance(record_id, str) or not record_id:
                raise ValueError("record_id must be a non-empty string")
            if not isinstance(value, str):
                raise ValueError("value must be a string")
            if request_id is not None and not isinstance(request_id, str):
                raise ValueError("request_id must be a string")
            asserted_attempt_id = body.get("asserted_attempt_id")
            asserted_principal = body.get("asserted_principal")
            if asserted_attempt_id is not None and not isinstance(asserted_attempt_id, str):
                raise ValueError("asserted_attempt_id must be a string")
            if asserted_principal is not None and not isinstance(asserted_principal, str):
                raise ValueError("asserted_principal must be a string")
            result = self.store.business_write(
                token,
                record_id=record_id,
                value=value,
                request_id=request_id,
                asserted_attempt_id=asserted_attempt_id,
                asserted_principal=asserted_principal,
            )
        except (InvalidCredential, StaleCredential) as exc:
            self._send(HTTPStatus.UNAUTHORIZED, {"error": type(exc).__name__})
            return
        except ValueError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except SimulatedResponseLoss:
            self.close_connection = True
            return
        except FixtureError as exc:
            self._send(HTTPStatus.CONFLICT, {"error": type(exc).__name__})
            return

        status = HTTPStatus.OK if result.committed else HTTPStatus.CONFLICT
        self._send(
            status,
            {
                "attempt_id": result.attempt_id,
                "request_id": result.request_id,
                "state": result.state,
                "committed": result.committed,
                "audit_seq": result.audit_seq,
            },
        )


def make_server(store: FixtureStore, host: str, port: int) -> ThreadingHTTPServer:
    handler = type("BoundAppHandler", (AppHandler,), {"store": store})
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 2 trusted fixture application data plane")
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()

    store = FixtureStore(args.db)
    store.bootstrap()
    server = make_server(store, args.host, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
