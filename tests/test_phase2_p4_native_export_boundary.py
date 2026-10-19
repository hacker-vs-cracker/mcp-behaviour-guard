"""Source-only negative cases for native streamed archive endpoint binding."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parents[1] / "assurance/phase2/ci"
sys.path.insert(0, str(CI))
import p4_trusted_runtime_adapter as adapter  # noqa: E402


def test_ambient_docker_export_forbidden_before_subprocess():
    with pytest.raises(adapter.P4AdapterError, match="ambient Docker"):
        list(
            adapter._bounded_archive_process(
                ["docker", "container", "cp", "a" * 64 + ":/state", "-"],
                deadline=float(time.monotonic() + 8),
                byte_limit=16384,
            )
        )


def test_native_archive_rejects_endpoint_or_path_substitution():
    endpoint = "unix:///run/mcpbg-p4-a/engine.sock"
    cases = [
        [
            "docker",
            "--host",
            "unix:///var/run/docker.sock",
            "container",
            "cp",
            "a" * 64 + ":/state",
            "-",
        ],
        ["docker", "--host", endpoint, "container", "cp", "a" * 64 + ":/etc/shadow", "-"],
        ["docker", "--host", endpoint, "container", "cp", "../../etc/passwd", "-"],
        ["docker", "--host", endpoint, "container", "cp", "a" * 64 + ":/state", "bad"],
    ]
    for argv in cases:
        with pytest.raises(adapter.P4AdapterError, match="archive endpoint"):
            list(
                adapter._bounded_archive_process(
                    argv,
                    deadline=float(time.monotonic() + 8),
                    byte_limit=16384,
                    private_endpoint=endpoint,
                )
            )
