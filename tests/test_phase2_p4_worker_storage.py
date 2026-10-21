"""Worker storage admission tests; no Docker daemon or privileged mount is used."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

CI = Path(__file__).resolve().parents[1] / "assurance/phase2/ci"


def _module():
    spec = importlib.util.spec_from_file_location(
        "p4_worker_storage_tests", CI / "p4_worker_storage.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _setup(tmp_path, monkeypatch):
    m = _module()
    root = tmp_path / "docker"
    root.mkdir(mode=0o700)
    names = (
        "containerd_content",
        "containerd_snapshots",
        "containerd_state",
        "buildkit",
        "image_transfer",
        "temporary",
        "daemon_logs",
    )
    for name in names:
        (root / name).mkdir(mode=0o700)
    info = {
        "DockerRootDir": str(root),
        "OSType": "linux",
        "Architecture": "amd64",
        "ID": "private-worker",
    }
    daemon = hashlib.sha256(info["ID"].encode()).hexdigest()
    layout = m.WorkerStorageLayout(root, *(root / n for n in names), "classic-overlay2", daemon)
    monkeypatch.setattr(m.platform, "system", lambda: "Linux")
    monkeypatch.setattr(m.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(m, "_mount_points", lambda: {str(root)})
    monkeypatch.setattr(m.os.path, "ismount", lambda p: p == root)
    # Path ownership is verified separately by production. Only this test
    # fixture bypasses it, without using privileged filesystem operations.
    actual_stat = Path.stat

    def stat_for_test(p, *args, **kwargs):
        item = actual_stat(p, *args, **kwargs)
        data = list(item)
        data[4] = 0
        return os.stat_result(data)

    monkeypatch.setattr(Path, "stat", stat_for_test)
    monkeypatch.setattr(m.os, "statvfs", lambda p: SimpleNamespace(f_frsize=4096, f_blocks=262144))
    monkeypatch.setattr(m.re, "fullmatch", _replacement_root_match(m.re.fullmatch, root))
    return m, layout, info, daemon


def _replacement_root_match(original, root):
    def wrapped(pattern, value, *args, **kwargs):
        if pattern.startswith("/mnt/mcpbg-p4-") and value == str(root):
            return original(".*", value, *args, **kwargs)
        return original(pattern, value, *args, **kwargs)

    return wrapped


def test_admits_single_owned_mounted_worker_boundary(tmp_path, monkeypatch):
    m, layout, info, daemon = _setup(tmp_path, monkeypatch)
    result = m.verify_worker_storage(layout, docker_info=info, expected_daemon_sha256=daemon)
    assert result["filesystem_bytes"] == 1_073_741_824
    assert len(result["whole_worker_storage_sha256"]) == 64
    assert result["backend"] == "classic-overlay2"


def test_rejects_containerd_outside_root(tmp_path, monkeypatch):
    from dataclasses import replace

    m, layout, info, daemon = _setup(tmp_path, monkeypatch)
    other = tmp_path / "outside"
    other.mkdir(mode=0o700)
    with pytest.raises(m.StorageUncertain, match="external writable-backend"):
        m.verify_worker_storage(
            replace(layout, containerd_snapshots=other),
            docker_info=info,
            expected_daemon_sha256=daemon,
        )


def test_rejects_nested_mount_or_oversized_storage(tmp_path, monkeypatch):
    m, layout, info, daemon = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_mount_points", lambda: {str(layout.docker_root), str(layout.buildkit)})
    with pytest.raises(m.StorageUncertain, match="crosses mount"):
        m.verify_worker_storage(layout, docker_info=info, expected_daemon_sha256=daemon)
    monkeypatch.setattr(m, "_mount_points", lambda: {str(layout.docker_root)})
    monkeypatch.setattr(m.os, "statvfs", lambda p: SimpleNamespace(f_frsize=4096, f_blocks=262145))
    with pytest.raises(m.StorageUncertain, match="exceeds 1GiB"):
        m.verify_worker_storage(layout, docker_info=info, expected_daemon_sha256=daemon)


def test_rejects_daemon_substitution_and_duplicate_paths(tmp_path, monkeypatch):
    from dataclasses import replace

    m, layout, info, daemon = _setup(tmp_path, monkeypatch)
    with pytest.raises(m.StorageUncertain, match="daemon identity"):
        m.verify_worker_storage(
            layout, docker_info={**info, "ID": "other"}, expected_daemon_sha256=daemon
        )
    with pytest.raises(m.StorageUncertain, match="duplicate"):
        m.verify_worker_storage(
            replace(layout, buildkit=layout.containerd_content),
            docker_info=info,
            expected_daemon_sha256=daemon,
        )
