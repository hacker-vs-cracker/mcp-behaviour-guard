"""Offline R31 regression probes against real trust parsers and native byte pump."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parents[1] / "assurance/phase2/ci"
sys.path.insert(0, str(CI))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name + "_r31_test", CI / (name + ".py"))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_complete_40015_byte_structured_engine_response(monkeypatch):
    m = _load("p4_native_build_execution")
    original = m.subprocess.Popen
    payload = json.dumps({"value": "x" * 40002}, separators=(",", ":")).encode()
    assert len(payload) == 40014
    payload += b" "
    assert len(payload) == 40015

    def command(_argv, **kw):
        return original(
            [sys.executable, "-c", "import sys;sys.stdout.buffer.write(" + repr(payload) + ")"],
            **kw,
        )

    monkeypatch.setattr(m.subprocess, "Popen", command)
    ep = "unix:///run/mcpbg-p4-1/engine.sock"
    result = m.bounded_native_command(
        ["docker", "--host", ep, "container", "inspect", "example"],
        endpoint=ep,
        remaining=5,
        byte_budget=262144,
    )
    assert result.returncode == 0
    assert result.bytes_seen == len(payload)
    assert result.stdout == payload
    assert json.loads(result.stdout)["value"] == "x" * 40002


def test_native_output_cap_plus_one_rejects(monkeypatch):
    m = _load("p4_native_build_execution")
    original = m.subprocess.Popen

    def command(_argv, **kw):
        return original([sys.executable, "-c", "import sys;sys.stdout.write('x'*257)"], **kw)

    monkeypatch.setattr(m.subprocess, "Popen", command)
    ep = "unix:///run/mcpbg-p4-1/engine.sock"
    with pytest.raises(m.P4BuildUnknown, match="output budget"):
        m.bounded_native_command(
            ["docker", "--host", ep, "inspect", "example"],
            endpoint=ep,
            remaining=5,
            byte_budget=256,
        )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"x":1e10000}',
        b'{"schema_version":1,"nested":' + b"[" * 40 + b"0" + b"]" * 40 + b"}",
        b'{"schema_version":1,"x":[' + b"0," * 1024 + b"0]}",
        b'{"schema_version":1,"x":1,"x":2}',
        b'{"schema_version":true}',
        b'{"schema_version":2}',
        b'{"schema_version":1,"x":"' + b"a" * 65537 + b'"}',
        b'{"schema_version":1,"x":"' + b"a" * 1048576 + b'"}',
    ],
)
def test_strict_comparison_intake_rejects_untrusted_shapes(tmp_path, raw):
    m = _load("p4_reference_bridge")
    f = tmp_path / "sidecar.json"
    f.write_bytes(raw)
    with pytest.raises(m.P4BridgeError):
        m._json_file(f)


def test_fd_reader_refuses_symlink(tmp_path):
    m = _load("p4_reference_bridge")
    real = tmp_path / "real.json"
    real.write_bytes(b'{"schema_version":1}')
    alias = tmp_path / "alias.json"
    alias.symlink_to(real)
    with pytest.raises(m.P4BridgeError):
        m._json_file(alias)
