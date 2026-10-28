"""Source-only archive reconciliation, not actual Docker/worker transfer proof."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "assurance/phase2/ci"))
import p4_image_handover as handover  # noqa: E402
from p4_image_handover import HandoverUnknown, reconcile_staged_image  # noqa: E402

IMAGE = "sha256:" + "a" * 64


def reconcile(tmp_path: Path, *, content: bytes = b"image-bytes"):
    first = tmp_path / "source.tar"
    second = tmp_path / "destination.tar"
    first.write_bytes(content)
    second.write_bytes(content)
    kw = {
        "source_archive": first,
        "destination_archive": second,
        "source_image_inspect": {"Id": IMAGE, "Os": "linux", "Architecture": "amd64"},
        "destination_image_inspect": {"Id": IMAGE, "Os": "linux", "Architecture": "amd64"},
        "remaining_transfer_bytes": 1024,
        "original_deadline_monotonic": time.monotonic() + 10.0,
    }
    return kw


def test_staged_byte_and_resolved_identity_positive(tmp_path: Path):
    result = reconcile_staged_image(**reconcile(tmp_path))
    assert result["status"] == "MATCHED_STAGE_ARCHIVE_BYTES_SOURCE_ONLY"
    assert result["transfer_bytes"] == 11
    assert result["runtime_enforcement_proven"] is False
    assert result["build_disposal_proven"] is False


@pytest.mark.parametrize(
    "change",
    [
        "different-bytes",
        "wrong-image",
        "wrong-platform",
        "time-expired",
        "cap",
        "same-path",
        "bool-cap",
    ],
)
def test_negative_identity_and_budget(tmp_path: Path, change: str):
    args = reconcile(tmp_path)
    if change == "different-bytes":
        args["destination_archive"].write_bytes(b"image-bytex")
    elif change == "wrong-image":
        args["destination_image_inspect"]["Id"] = "sha256:" + "b" * 64
    elif change == "wrong-platform":
        args["destination_image_inspect"]["Architecture"] = "arm64"
    elif change == "time-expired":
        args["original_deadline_monotonic"] = time.monotonic() - 1.0
    elif change == "cap":
        args["remaining_transfer_bytes"] = 10
    elif change == "bool-cap":
        args["remaining_transfer_bytes"] = True
    else:
        args["destination_archive"] = args["source_archive"]
    with pytest.raises(HandoverUnknown):
        reconcile_staged_image(**args)


def test_symlink_and_hardlink_refused(tmp_path: Path):
    args = reconcile(tmp_path)
    args["destination_archive"].unlink()
    args["destination_archive"].symlink_to(args["source_archive"])
    with pytest.raises(HandoverUnknown):
        reconcile_staged_image(**args)
    args["destination_archive"].unlink()
    os.link(args["source_archive"], args["destination_archive"])
    with pytest.raises(HandoverUnknown):
        reconcile_staged_image(**args)


def test_archive_path_aliases_cannot_masquerade_as_cross_worker_transfer(tmp_path: Path):
    args = reconcile(tmp_path)
    # The second lexical path resolves to the same inode as the first.
    args["destination_archive"] = tmp_path / "unused" / ".." / "source.tar"
    (tmp_path / "unused").mkdir()
    with pytest.raises(HandoverUnknown, match="alias the same file"):
        reconcile_staged_image(**args)


def test_archive_rewrite_with_restored_mtime_is_rejected(tmp_path: Path, monkeypatch):
    args = reconcile(tmp_path, content=b"0123456789")
    target = args["source_archive"]
    stamp = target.stat()
    original_read = os.read
    changed = False

    def changed_during_read(fd: int, size: int) -> bytes:
        nonlocal changed
        data = original_read(fd, size)
        if not changed:
            changed = True
            target.write_bytes(b"9876543210")
            os.utime(target, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return data

    monkeypatch.setattr(os, "read", changed_during_read)
    with pytest.raises(HandoverUnknown, match="changed during read"):
        reconcile_staged_image(**args)
    assert changed


def test_source_replaced_between_source_and_destination_observation(tmp_path: Path, monkeypatch):
    args = reconcile(tmp_path)
    original_fingerprint = handover._fingerprint
    calls = 0

    def swap_after_source(*fargs, **fkwargs):
        nonlocal calls
        result = original_fingerprint(*fargs, **fkwargs)
        calls += 1
        if calls == 1:
            source = args["source_archive"]
            source.unlink()
            source.write_bytes(b"image-bytes")
        return result

    monkeypatch.setattr(handover, "_fingerprint", swap_after_source)
    with pytest.raises(HandoverUnknown, match="changed after first observation"):
        reconcile_staged_image(**args)
    assert calls == 2


def test_source_rewritten_with_restored_mtime_after_source_read(tmp_path: Path, monkeypatch):
    args = reconcile(tmp_path)
    original_fingerprint = handover._fingerprint
    source = args["source_archive"]
    stamp = source.stat()
    calls = 0

    def mutate_after_source(*fargs, **fkwargs):
        nonlocal calls
        result = original_fingerprint(*fargs, **fkwargs)
        calls += 1
        if calls == 1:
            source.write_bytes(b"image-bytex")
            os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return result

    monkeypatch.setattr(handover, "_fingerprint", mutate_after_source)
    with pytest.raises(HandoverUnknown, match="changed after first observation"):
        reconcile_staged_image(**args)
    assert calls == 2


def test_source_disappears_during_second_observation(tmp_path: Path, monkeypatch):
    args = reconcile(tmp_path)
    original_fingerprint = handover._fingerprint
    calls = 0

    def remove_after_source(*fargs, **fkwargs):
        nonlocal calls
        result = original_fingerprint(*fargs, **fkwargs)
        calls += 1
        if calls == 1:
            args["source_archive"].unlink()
        return result

    monkeypatch.setattr(handover, "_fingerprint", remove_after_source)
    with pytest.raises(HandoverUnknown, match="unavailable after destination read"):
        reconcile_staged_image(**args)
    assert calls == 2
