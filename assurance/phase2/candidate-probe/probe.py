from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def _tcp(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_ok(url: str, timeout: float = 1.2) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status == 200
    except Exception:
        return False


def _rootfs_write_blocked() -> bool:
    path = Path("/phase2-candidate-rootfs-write-test")
    try:
        path.write_text("unexpected", encoding="utf-8")
    except OSError:
        return True
    else:
        with contextlib.suppress(OSError):
            path.unlink()
        return False


def _tmp_writable() -> bool:
    path = Path("/tmp/phase2-candidate-tmp-test")
    try:
        path.write_text("ok", encoding="utf-8")
        return path.read_text(encoding="utf-8") == "ok"
    except OSError:
        return False
    finally:
        with contextlib.suppress(OSError):
            path.unlink()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_response(HTTPStatus.NOT_FOUND.value)
            self.end_headers()
            return
        body = b'{"status":"ok","service":"candidate-probe"}'
        self.send_response(HTTPStatus.OK.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(port: int) -> None:
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


def checks(args: argparse.Namespace) -> None:
    results: dict[str, Any] = {
        "uid": os.getuid(),
        "app_http_ok": _http_ok(f"http://{args.app_host}:{args.app_port}/health"),
        "control_hostname_tcp": _tcp(args.control_host, args.control_port),
        "control_ip_tcp": _tcp(args.control_ip, args.control_port),
        "internet_tcp": _tcp(args.internet_ip, args.internet_port),
        "host_service_tcp": _tcp(args.host_name, args.host_port),
        "docker_socket_exists": Path("/var/run/docker.sock").exists(),
        "rootfs_write_blocked": _rootfs_write_blocked(),
        "tmp_writable": _tmp_writable(),
        "trusted_output_visible": Path("/trusted-output").exists(),
    }
    print(json.dumps(results, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    server = sub.add_parser("server")
    server.add_argument("--port", type=int, default=7000)
    check = sub.add_parser("checks")
    check.add_argument("--app-host", required=True)
    check.add_argument("--app-port", type=int, required=True)
    check.add_argument("--control-host", required=True)
    check.add_argument("--control-ip", required=True)
    check.add_argument("--control-port", type=int, required=True)
    check.add_argument("--internet-ip", default="1.1.1.1")
    check.add_argument("--internet-port", type=int, default=443)
    check.add_argument("--host-name", default="host.docker.internal")
    check.add_argument("--host-port", type=int, required=True)
    args = parser.parse_args()
    if args.command == "server":
        serve(args.port)
    else:
        checks(args)


if __name__ == "__main__":
    main()
