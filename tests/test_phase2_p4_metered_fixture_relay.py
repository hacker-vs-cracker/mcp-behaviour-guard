from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RELAY = ROOT / "assurance/phase2/ci/p4_metered_fixture_relay.py"


def _module():
    spec = importlib.util.spec_from_file_location("p4_test_relay", RELAY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_real_local_socket_relay_counts_and_forwards_without_buffered_bypass():
    module = _module()
    received = []

    async def fixture(reader, writer):
        header = await reader.readuntil(b"\r\n\r\n")
        received.append(header)
        body = b'{"record":"ok"}'
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n" + body)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    upstream = await asyncio.start_server(fixture, "127.0.0.1", 0)
    upstream_port = upstream.sockets[0].getsockname()[1]
    relay = module.MeteredFixtureRelay(upstream_host="127.0.0.1", upstream_port=upstream_port)
    listener = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
    listener_port = listener.sockets[0].getsockname()[1]
    async with upstream, listener:
        for _ in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", listener_port)
            writer.write(b"GET /records/synthetic HTTP/1.1\r\nHost: fixture-app\r\n\r\n")
            await writer.drain()
            payload = await asyncio.wait_for(reader.read(), 2)
            writer.close()
            await writer.wait_closed()
            assert b"200 OK" in payload and payload.endswith(b'{"record":"ok"}')
    assert len(received) == 2
    assert relay.requests == 2 and relay.bytes > 100 and not relay.failed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "data",
    [
        b"POST /records/write HTTP/1.1\r\nContent-Length: 65536\r\n\r\n",
        b"GET /control/finalize HTTP/1.1\r\nHost: fixture-app\r\n\r\n",
        b"GET http://other/records/id HTTP/1.1\r\nHost: fixture-app\r\n\r\n",
        b"GET /records/id HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET /records/id HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
    ],
)
async def test_relay_rejects_bypass_and_poisoning_without_upstream_contact(data):
    module = _module()
    calls = []

    async def fixture(reader, writer):
        calls.append(1)
        writer.close()
        await writer.wait_closed()

    upstream = await asyncio.start_server(fixture, "127.0.0.1", 0)
    relay = module.MeteredFixtureRelay(
        upstream_host="127.0.0.1", upstream_port=upstream.sockets[0].getsockname()[1]
    )
    listener = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
    async with upstream, listener:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )
        writer.write(data)
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 2) == b""
        writer.close()
        await writer.wait_closed()
    assert calls == []
    assert relay.requests == 1 and relay.failed


def test_relay_rejects_relaxed_frozen_limits_and_nonliteral_endpoint():
    module = _module()
    for limits in (
        module.RelayLimits(request_bytes=65537),
        module.RelayLimits(deadline_seconds=601),
        module.RelayLimits(requests=513),
    ):
        with pytest.raises(module.RelayError, match="frozen"):
            module.MeteredFixtureRelay(
                upstream_host="fixture-real", upstream_port=8001, limits=limits
            )
    for name in ("http://candidate", "fixture:8001", "fixture/../remote"):
        with pytest.raises(module.RelayError, match="endpoint"):
            module.MeteredFixtureRelay(upstream_host=name, upstream_port=8001)


def test_p4_relay_source_hash_is_consumed_without_execution_authority():
    import hashlib
    import json

    ci = ROOT / "assurance/phase2/ci"
    trust = json.loads((ci / "trust-boundary.json").read_text())
    binding = trust["p4_metered_fixture_relay"]
    assert binding["module_sha256"] == hashlib.sha256(RELAY.read_bytes()).hexdigest()
    assert trust["consumed_trusted_inputs"].count(binding["module_path"]) == 1
    assert binding["runtime_enforcement_proven"] is False
    assert binding["candidate_execution_enabled"] is False
    assert binding["verdict_publication_enabled"] is False


@pytest.mark.asyncio
async def test_relay_rejects_invalid_upstream_response_as_unknown():
    module = _module()

    async def fixture(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"garbage\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    upstream = await asyncio.start_server(fixture, "127.0.0.1", 0)
    relay = module.MeteredFixtureRelay(
        upstream_host="127.0.0.1", upstream_port=upstream.sockets[0].getsockname()[1]
    )
    listener = await asyncio.start_server(relay.handle, "127.0.0.1", 0)
    async with upstream, listener:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )
        writer.write(b"GET /health HTTP/1.1\r\nHost: fixture-app\r\n\r\n")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), 2) == b""
        writer.close()
        await writer.wait_closed()
    assert relay.failed


def test_relay_cli_rejects_missing_or_extended_pipeline_deadline():
    import subprocess
    from sys import executable

    common = [
        executable,
        str(RELAY),
        "--upstream-host",
        "fixture-app",
        "--upstream-port",
        "8001",
        "--listen-port",
        "8001",
    ]
    for args in ([], ["--remaining-seconds", "0"], ["--remaining-seconds", "601"]):
        outcome = subprocess.run(common + args, capture_output=True, timeout=4, check=False)
        assert outcome.returncode != 0
        assert len(outcome.stdout) + len(outcome.stderr) < 8192
