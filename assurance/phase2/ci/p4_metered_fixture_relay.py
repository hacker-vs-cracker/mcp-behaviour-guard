"""Trusted P4 source-only fixture relay with unavoidable raw-byte accounting.

The relay is designed for an isolated two-network topology: subjects can reach
only this listener; only this trusted process can reach the fixture service.
Docker role/image/mount/network attestation is a separate prerequisite.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import re
import time
from dataclasses import dataclass


class RelayError(RuntimeError):
    pass


@dataclass(frozen=True)
class RelayLimits:
    requests: int = 512
    request_bytes: int = 65_536
    response_bytes: int = 262_144
    aggregate_bytes: int = 8_388_608
    deadline_seconds: int = 600


class MeteredFixtureRelay:
    """Serialises bounded HTTP/1.1 exchanges and fails closed on uncertain I/O."""

    def __init__(
        self, *, upstream_host: str, upstream_port: int, limits: RelayLimits | None = None
    ) -> None:
        if (
            not isinstance(upstream_host, str)
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", upstream_host)
            or type(upstream_port) is not int
            or not 1 <= upstream_port <= 65535
        ):
            raise RelayError("invalid trusted fixture endpoint")
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.limits = limits or RelayLimits()
        self._validate_limits()
        self.deadline = time.monotonic() + self.limits.deadline_seconds
        self.lock = asyncio.Lock()
        self.requests = 0
        self.bytes = 0
        self.failed = False
        self.active: set[asyncio.Task[object]] = set()

    def _validate_limits(self) -> None:
        values = self.limits
        upper = RelayLimits()
        for field in (
            "requests",
            "request_bytes",
            "response_bytes",
            "aggregate_bytes",
            "deadline_seconds",
        ):
            value = getattr(values, field)
            if type(value) is not int or not 0 < value <= getattr(upper, field):
                raise RelayError("relay limits exceed frozen P4 bounds")

    def remaining(self) -> float:
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise RelayError("shared relay deadline exhausted")
        return value

    async def _read_header(self, reader: asyncio.StreamReader, *, ceiling: int) -> bytes:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.remaining())
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise RelayError("HTTP header missing, oversized or stalled") from exc
        if len(raw) > ceiling:
            raise RelayError("HTTP header byte budget exceeded")
        return raw

    @staticmethod
    def _body_length(header: bytes) -> int:
        lines = header.removesuffix(b"\r\n\r\n").split(b"\r\n")
        if (
            not lines
            or not lines[0]
            or b"\x00" in header
            or b"\r\n " in header
            or b"\r\n\t" in header
        ):
            raise RelayError("malformed HTTP header")
        fields: dict[bytes, bytes] = {}
        for line in lines[1:]:
            if b":" not in line:
                raise RelayError("malformed HTTP field")
            name, raw = line.split(b":", 1)
            if not re.fullmatch(rb"[A-Za-z0-9-]+", name):
                raise RelayError("malformed HTTP field name")
            key = name.lower()
            if key in fields:
                raise RelayError("duplicate HTTP field")
            fields[key] = raw.strip()
        if (
            b"transfer-encoding" in fields
            or b"upgrade" in fields
            or b"proxy-authorization" in fields
        ):
            raise RelayError("streaming, upgrade or proxy authority is not permitted")
        raw_length = fields.get(b"content-length", b"0")
        if not re.fullmatch(rb"[0-9]{1,9}", raw_length):
            raise RelayError("invalid HTTP content length")
        return int(raw_length)

    @staticmethod
    def _response(header: bytes) -> None:
        first = header.split(b"\r\n", 1)[0]
        parts = first.split(b" ", 2)
        if (
            len(parts) < 2
            or parts[0] not in {b"HTTP/1.0", b"HTTP/1.1"}
            or not re.fullmatch(rb"[2-5][0-9][0-9]", parts[1])
        ):
            raise RelayError("unapproved upstream HTTP response")

    @staticmethod
    def _route(header: bytes) -> None:
        first = header.split(b"\r\n", 1)[0]
        parts = first.split(b" ")
        if len(parts) != 3 or parts[2] != b"HTTP/1.1":
            raise RelayError("unapproved HTTP protocol")
        method, path, _ = parts
        if not (
            (method == b"GET" and (path == b"/health" or path.startswith(b"/records/")))
            or (method == b"POST" and path == b"/records/write")
        ):
            raise RelayError("unapproved fixture route")
        if b"#" in path or b"//" in path or b".." in path or b"%" in path:
            raise RelayError("ambiguous fixture path")

    async def _forward(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        size: int,
        allowance: int,
    ) -> int:
        total = 0
        while total < size:
            chunk = await asyncio.wait_for(reader.read(min(8192, size - total)), self.remaining())
            if not chunk:
                raise RelayError("incomplete fixture transport body")
            total += len(chunk)
            if total > allowance:
                raise RelayError("fixture transport byte limit")
            if self.bytes + len(chunk) > self.limits.aggregate_bytes:
                raise RelayError("fixture aggregate traffic budget")
            # Account before forwarding; a failed drain makes the whole relay unusable.
            self.bytes += len(chunk)
            writer.write(chunk)
            await asyncio.wait_for(writer.drain(), self.remaining())
        return total

    async def handle(
        self, client_in: asyncio.StreamReader, client_out: asyncio.StreamWriter
    ) -> None:
        fixture_out: asyncio.StreamWriter | None = None
        current = asyncio.current_task()
        if current is not None:
            self.active.add(current)
        admitted = False
        try:
            async with self.lock:
                if self.failed or self.requests >= self.limits.requests:
                    raise RelayError("fixture relay unavailable")
                self.requests += 1  # Count malformed or incomplete admitted requests.
                admitted = True
                header = await self._read_header(
                    client_in, ceiling=min(8192, self.limits.request_bytes)
                )
                self._route(header)
                body_size = self._body_length(header)
                if len(header) + body_size > self.limits.request_bytes:
                    raise RelayError("request byte limit")
                if self.bytes + len(header) + body_size > self.limits.aggregate_bytes:
                    raise RelayError("fixture aggregate traffic budget")
                fixture_in, fixture_out = await asyncio.wait_for(
                    asyncio.open_connection(self.upstream_host, self.upstream_port),
                    self.remaining(),
                )
                if fixture_in is None or fixture_out is None:
                    raise RelayError("fixture transport unavailable")
                self.bytes += len(header)
                fixture_out.write(header)
                await asyncio.wait_for(fixture_out.drain(), self.remaining())
                await self._forward(
                    client_in,
                    fixture_out,
                    size=body_size,
                    allowance=self.limits.request_bytes - len(header),
                )
                response = await self._read_header(
                    fixture_in, ceiling=min(8192, self.limits.response_bytes)
                )
                self._response(response)
                content_length = self._body_length(response)
                if len(response) + content_length > self.limits.response_bytes:
                    raise RelayError("response byte limit")
                if self.bytes + len(response) + content_length > self.limits.aggregate_bytes:
                    raise RelayError("fixture aggregate traffic budget")
                self.bytes += len(response)
                client_out.write(response)
                await asyncio.wait_for(client_out.drain(), self.remaining())
                await self._forward(
                    fixture_in,
                    client_out,
                    size=content_length,
                    allowance=self.limits.response_bytes - len(response),
                )
        except asyncio.CancelledError:
            # Cancellation after admission is never healthy, including during drain.
            if admitted:
                self.failed = True
            raise
        except (TimeoutError, OSError, RelayError):
            # One ambiguous transfer invalidates this relay's authority.
            self.failed = True
        finally:
            if current is not None:
                self.active.discard(current)
            # A stalled peer must not hang cleanup after the traffic deadline.
            if fixture_out is not None:
                fixture_out.close()
                with contextlib.suppress(OSError, asyncio.TimeoutError):
                    await asyncio.wait_for(fixture_out.wait_closed(), timeout=1.0)
            client_out.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(client_out.wait_closed(), timeout=1.0)


async def serve_trusted_relay(
    listen_host: str, listen_port: int, relay: MeteredFixtureRelay
) -> None:
    if listen_host != "0.0.0.0" or type(listen_port) is not int or not 1 <= listen_port <= 65535:
        raise RelayError("invalid isolated relay listener")
    server = await asyncio.start_server(relay.handle, listen_host, listen_port, limit=16384)
    async with server:
        try:
            await asyncio.wait_for(server.serve_forever(), relay.remaining())
        finally:
            # Active clients are owned, not silently abandoned on listener stop.
            relay.failed = relay.failed or bool(relay.active)
            clients = list(relay.active)
            for task in clients:
                task.cancel()
            if clients:
                done, pending = await asyncio.wait(clients, timeout=2.0)
                if pending:
                    relay.failed = True
                for task in done:
                    if task.cancelled():
                        continue
                    with contextlib.suppress(Exception):
                        task.result()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-host", required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--listen-port", type=int, default=8001)
    parser.add_argument("--remaining-seconds", type=int, required=True)
    args = parser.parse_args()
    # The trusted controller supplies remaining pipeline time at launch. Starting
    # this countdown after launch only makes it shorter, never a fresh 600s window.
    relay = MeteredFixtureRelay(
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        limits=RelayLimits(deadline_seconds=args.remaining_seconds),
    )
    try:
        asyncio.run(serve_trusted_relay("0.0.0.0", args.listen_port, relay))
    finally:
        # A missing or truncated final counter line is UNKNOWN for the controller.
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "p4_fixture_relay_counters",
                    "attempted_requests": relay.requests,
                    "forwarded_bytes": relay.bytes,
                    "failed": relay.failed,
                },
                sort_keys=True,
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
