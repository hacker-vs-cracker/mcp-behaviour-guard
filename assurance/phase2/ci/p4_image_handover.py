"""Read-only, bounded *source* image archive identity across native worker stages.

The controller supplies independently observed build/runtime image inspection and
staged archive paths after the transfer. This verifier reads both archived byte
streams via no-follow file descriptors; it does not attest their producer,
worker disposal, Engine admission, a physical transfer or a runnable image.
No candidate, Docker, subprocess or network execution occurs here.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from pathlib import Path
from typing import Any


class HandoverUnknown(RuntimeError):
    """Handover identity, continuity or bounded file observation is unresolved."""


_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BYTES = 1_073_741_824  # No increase to the frozen whole-worker 1 GiB ceiling.


def _image_readback(value: dict[str, Any]) -> str:
    """Bind resolved Engine image ID, separately from a requested manifest ref."""
    if (
        type(value) is not dict
        or value.get("Os") != "linux"
        or value.get("Architecture") != "amd64"
        or type(value.get("Id")) is not str
        or _IMAGE.fullmatch(value["Id"]) is None
    ):
        raise HandoverUnknown("resolved native AMD64 image readback missing")
    return value["Id"]


def _fingerprint(
    path: Path, *, remaining_bytes: int, deadline: float
) -> tuple[str, int, tuple[int, int]]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or type(remaining_bytes) is not int
        or not 0 < remaining_bytes <= _MAX_BYTES
        or type(deadline) is not float
        or time.monotonic() >= deadline
    ):
        raise HandoverUnknown("immutable image archive read admission invalid")
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= remaining_bytes
        ):
            raise HandoverUnknown("nonregular, linked or oversized image archive")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            stamp = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            actual = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            if actual != stamp or opened.st_nlink != 1:
                raise HandoverUnknown("image archive changed before open")
            h = hashlib.sha256()
            total = 0
            while total < before.st_size:
                if time.monotonic() >= deadline:
                    raise HandoverUnknown("image archive exceeded original deadline")
                data = os.read(fd, min(65536, before.st_size - total))
                if not data:
                    raise HandoverUnknown("image archive truncated during read")
                h.update(data)
                total += len(data)
            after = os.fstat(fd)
            named = path.lstat()
            for item in (after, named):
                if (
                    item.st_dev,
                    item.st_ino,
                    item.st_size,
                    item.st_mtime_ns,
                    item.st_ctime_ns,
                ) != stamp or item.st_nlink != 1:
                    raise HandoverUnknown("image archive changed during read")
            return h.hexdigest(), total, (opened.st_dev, opened.st_ino)
        finally:
            os.close(fd)
    except OSError as exc:
        raise HandoverUnknown("cannot safely read staged image archive") from exc


def reconcile_staged_image(
    *,
    source_archive: Path,
    destination_archive: Path,
    source_image_inspect: dict[str, Any],
    destination_image_inspect: dict[str, Any],
    remaining_transfer_bytes: int,
    original_deadline_monotonic: float,
) -> dict[str, Any]:
    """Compare two distinct bounded readbacks, never self-asserted clean flags.

    The caller must separately prove archive origin, bounded transport, worker
    disposal and fresh destination Engine identity. Byte equality here does not
    prove those properties or authorize runtime creation.
    """
    if (
        source_archive == destination_archive
        or type(remaining_transfer_bytes) is not int
        or not 0 < remaining_transfer_bytes <= _MAX_BYTES
        or type(original_deadline_monotonic) is not float
        or not time.monotonic() < original_deadline_monotonic <= time.monotonic() + 600
    ):
        raise HandoverUnknown("stage transfer must have separate bounded contexts")
    build_id = _image_readback(source_image_inspect)
    runtime_id = _image_readback(destination_image_inspect)
    source_digest, source_size, source_file_identity = _fingerprint(
        source_archive,
        remaining_bytes=remaining_transfer_bytes,
        deadline=original_deadline_monotonic,
    )
    dest_digest, dest_size, dest_file_identity = _fingerprint(
        destination_archive,
        remaining_bytes=remaining_transfer_bytes,
        deadline=original_deadline_monotonic,
    )
    # A lexical pathname difference does not prove a cross-worker transfer.
    # The same inode observed through aliases is one local archive, not two.
    # Distinct inodes do NOT prove physical isolation or producer provenance.
    if source_file_identity == dest_file_identity:
        raise HandoverUnknown("source and destination archives alias the same file")
    if source_digest != dest_digest or source_size != dest_size or build_id != runtime_id:
        raise HandoverUnknown("stage transfer archive or resolved image identity drift")
    return {
        "schema_version": 1,
        "status": "MATCHED_STAGE_ARCHIVE_BYTES_SOURCE_ONLY",
        "platform": "linux/amd64",
        "source_archive_sha256": source_digest,
        "destination_archive_sha256": dest_digest,
        "source_image_id": build_id,
        "destination_image_id": runtime_id,
        "transfer_bytes": dest_size,
        "runtime_enforcement_proven": False,
        "build_disposal_proven": False,
        "image_transport_physically_proven": False,
        "approval_outcome": "NOT_EVALUATED",
    }
