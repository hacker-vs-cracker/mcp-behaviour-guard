"""Source-only archive reconciliation, not actual Docker/worker transfer proof."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "assurance/phase2/ci"))
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
