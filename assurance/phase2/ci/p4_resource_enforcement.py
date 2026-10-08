from __future__ import annotations

import argparse
import bz2
import contextlib
import fcntl
import gzip
import hashlib
import json
import lzma
import math
import os
import stat
import struct
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


class P4ResourceEnforcementError(RuntimeError):
    pass


POLICY_REL = "assurance/phase2/ci/p4-resource-policy.json"
MODULE_REL = "assurance/phase2/ci/p4_resource_enforcement.py"
IMPLEMENTED_PRIMITIVES = [
    "docker_log_options_builder",
    "build_command_limits",
    "artifact_tree_budget",
    "safe_archive_extraction",
    "bounded_json_parser",
    "fixture_traffic_budget",
    "attempt_deadline_and_single_attempt_lock",
    "owned_docker_resource_budget",
    "fail_closed_cleanup_classification",
]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise P4ResourceEnforcementError(f"duplicate JSON key: {key[:80]!r}")
        value[key] = item
    return value


def _preparse_json(raw: str, *, depth: int, array: int, members: int, string: int) -> None:
    # Scan structure before json.loads can allocate a large nested object.
    stack: list[list[int | str | bool]] = []
    quoted = False
    escaped = False
    token_bytes = 0
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
                token_bytes += len(char.encode("utf-8", errors="surrogatepass"))
            elif char == "\\":
                escaped = True
                token_bytes += 1
            elif char == '"':
                quoted = False
            else:
                token_bytes += len(char.encode("utf-8", errors="surrogatepass"))
            if token_bytes > string * 6:
                raise P4ResourceEnforcementError("JSON string exceeds policy")
            continue
        if char == '"':
            quoted = True
            token_bytes = 0
        elif char in "{[":
            stack.append([char, 0, False])
            if len(stack) > depth:
                raise P4ResourceEnforcementError("JSON nesting depth exceeds policy")
        elif char in "}]":
            if not stack or (stack[-1][0], char) not in (("{", "}"), ("[", "]")):
                raise P4ResourceEnforcementError("JSON invalid structure")
            kind, commas, content = stack.pop()
            length = int(commas) + bool(content)
            if length > (members if kind == "{" else array):
                raise P4ResourceEnforcementError("JSON member/item count exceeds policy")
        elif char == "," and stack:
            stack[-1][1] = int(stack[-1][1]) + 1
            bound = members if stack[-1][0] == "{" else array
            if int(stack[-1][1]) >= bound:
                raise P4ResourceEnforcementError("JSON member/item count exceeds policy")
        if stack and char not in " \t\r\n":
            stack[-1][2] = True
    if quoted or stack:
        raise P4ResourceEnforcementError("JSON truncated input")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise P4ResourceEnforcementError("non-finite JSON number rejected")
    return parsed


def _reject_constant(_value: str) -> None:
    raise P4ResourceEnforcementError("non-finite JSON constant rejected")


def _load_object_bytes(
    raw: bytes, *, max_bytes: int, label: str, shape: dict[str, Any] | None = None
) -> dict[str, Any]:
    if len(raw) > max_bytes:
        raise P4ResourceEnforcementError(f"{label} exceeds {max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise P4ResourceEnforcementError(f"{label} is not UTF-8") from exc
    if shape is not None:
        _preparse_json(
            text,
            depth=_positive_int(shape.get("max_depth"), "json.max_depth"),
            array=_positive_int(shape.get("max_array_items"), "json.max_array_items"),
            members=_positive_int(shape.get("max_object_members"), "json.max_object_members"),
            string=_positive_int(shape.get("max_string_bytes"), "json.max_string_bytes"),
        )
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_finite_float,
            parse_constant=_reject_constant,
        )
    except P4ResourceEnforcementError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError, UnicodeError, OverflowError) as exc:
        raise P4ResourceEnforcementError(f"{label} is not valid bounded JSON") from exc
    if not isinstance(value, dict):
        raise P4ResourceEnforcementError(f"{label} must be a JSON object")
    return value


def load_policy(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise P4ResourceEnforcementError(f"cannot read policy {path}: {exc}") from exc
    return _load_object_bytes(raw, max_bytes=131_072, label="resource policy")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise P4ResourceEnforcementError(f"{label} must be an object")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise P4ResourceEnforcementError(f"{label} must be a positive integer")
    return value


def _limits(policy: dict[str, Any], key: str) -> dict[str, Any]:
    return _mapping(_mapping(policy.get("limits"), "limits").get(key), f"limits.{key}")


def _validate_json_shape(value: Any, policy: dict[str, Any]) -> None:
    max_depth = _positive_int(policy.get("max_depth"), "json.max_depth")
    max_string = _positive_int(policy.get("max_string_bytes"), "json.max_string_bytes")
    max_array = _positive_int(policy.get("max_array_items"), "json.max_array_items")
    max_members = _positive_int(policy.get("max_object_members"), "json.max_object_members")

    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise P4ResourceEnforcementError("JSON nesting depth exceeds policy")
        if isinstance(current, str):
            try:
                length = len(current.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise P4ResourceEnforcementError("JSON invalid Unicode string") from exc
            if length > max_string:
                raise P4ResourceEnforcementError("JSON string exceeds policy")
        elif isinstance(current, list):
            if len(current) > max_array:
                raise P4ResourceEnforcementError("JSON array length exceeds policy")
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, dict):
            if len(current) > max_members:
                raise P4ResourceEnforcementError("JSON object member count exceeds policy")
            for key, item in current.items():
                try:
                    key_length = len(key.encode("utf-8"))
                except UnicodeEncodeError as exc:
                    raise P4ResourceEnforcementError("JSON invalid Unicode key") from exc
                if key_length > max_string:
                    raise P4ResourceEnforcementError("JSON key exceeds policy")
                stack.append((item, depth + 1))


def load_bounded_json(
    raw: bytes,
    policy: dict[str, Any],
    *,
    expected_schema_version: int,
    field_types: Mapping[str, type | tuple[type, ...]] | None = None,
) -> dict[str, Any]:
    json_policy = _mapping(policy.get("json_intake"), "json_intake")
    max_bytes = _positive_int(json_policy.get("max_bytes"), "json.max_bytes")
    if type(expected_schema_version) is not int:
        raise P4ResourceEnforcementError("expected schema_version must be an integer")
    value = _load_object_bytes(raw, max_bytes=max_bytes, label="JSON intake", shape=json_policy)
    _validate_json_shape(value, json_policy)
    if json_policy.get("schema_version_required") is not True:
        raise P4ResourceEnforcementError("JSON policy must require schema_version")
    schema_version = value.get("schema_version")
    if type(schema_version) is not int or schema_version != expected_schema_version:
        raise P4ResourceEnforcementError("JSON schema_version mismatch")
    if json_policy.get("field_types") != "strict":
        raise P4ResourceEnforcementError("JSON policy must require strict field types")
    for key, expected in (field_types or {}).items():
        if key not in value:
            raise P4ResourceEnforcementError(f"JSON field type mismatch: {key}")
        item = value[key]
        expected_types = expected if isinstance(expected, tuple) else (expected,)
        if type(item) not in expected_types:
            raise P4ResourceEnforcementError(f"JSON field type mismatch: {key}")
    return value


def _directory_depth(root: Path, path: Path) -> int:
    rel = path.relative_to(root)
    return len(rel.parts)


def validate_directory_budget(
    root: Path,
    *,
    total_bytes: int,
    per_file_bytes: int,
    max_files: int,
    max_depth: int,
) -> dict[str, int]:
    # The caller must fence writers before interpreting this as complete evidence.
    try:
        root_stat = root.lstat()
        if not stat.S_ISDIR(root_stat.st_mode):
            raise P4ResourceEnforcementError("artifact root must be a real directory")
        root = root.absolute()
        total = 0
        files = 0
        entries = 0

        def visit(folder: Path, depth: int) -> None:
            nonlocal total, files, entries
            with os.scandir(folder) as iterator:
                for entry in iterator:
                    entries += 1
                    if entries > max_files:
                        raise P4ResourceEnforcementError("artifact entry count exceeds policy")
                    if depth + 1 > max_depth:
                        raise P4ResourceEnforcementError("artifact depth exceeds policy")
                    st = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        visit(Path(entry.path), depth + 1)
                    elif stat.S_ISREG(st.st_mode):
                        if st.st_size > per_file_bytes:
                            raise P4ResourceEnforcementError("artifact file exceeds policy")
                        files += 1
                        total += st.st_size
                        if total > total_bytes:
                            raise P4ResourceEnforcementError("artifact total bytes exceeds policy")
                    else:
                        raise P4ResourceEnforcementError("non-regular artifact rejected")

        visit(root, 0)
        return {"files": files, "bytes": total}
    except (OSError, RecursionError) as exc:
        raise P4ResourceEnforcementError("artifact traversal failed") from exc


def validate_artifact_tree(root: Path, policy: dict[str, Any]) -> dict[str, int]:
    limits = _limits(policy, "artifacts")
    return validate_directory_budget(
        root,
        total_bytes=_positive_int(limits.get("total_bytes"), "artifacts.total_bytes"),
        per_file_bytes=_positive_int(limits.get("per_file_bytes"), "artifacts.per_file_bytes"),
        max_files=_positive_int(limits.get("max_files"), "artifacts.max_files"),
        max_depth=_positive_int(limits.get("max_depth"), "artifacts.max_depth"),
    )


def validate_build_context(root: Path, policy: dict[str, Any]) -> dict[str, int]:
    build = _limits(policy, "build")
    candidate = _limits(policy, "candidate_source")
    return validate_directory_budget(
        root,
        total_bytes=_positive_int(build.get("context_bytes"), "build.context_bytes"),
        per_file_bytes=_positive_int(build.get("context_bytes"), "build.context_bytes"),
        max_files=_positive_int(candidate.get("allowed_files"), "candidate.allowed_files") + 1,
        max_depth=2,
    )


def _archive_name(raw_name: str, *, max_depth: int) -> tuple[str, bool]:
    if not raw_name or "\x00" in raw_name or "\\" in raw_name:
        raise P4ResourceEnforcementError("archive member name is invalid")
    if raw_name.startswith("/"):
        raise P4ResourceEnforcementError("absolute archive path rejected")
    path = PurePosixPath(raw_name)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise P4ResourceEnforcementError("archive path traversal rejected")
    clean_parts = tuple(part for part in path.parts if part not in ("", "."))
    if not clean_parts:
        raise P4ResourceEnforcementError("empty archive path rejected")
    if len(clean_parts) > max_depth:
        raise P4ResourceEnforcementError("archive depth exceeds policy")
    clean = "/".join(clean_parts)
    return clean, raw_name.endswith("/")


def _register_archive_path(
    name: str,
    *,
    is_dir: bool,
    seen: dict[str, str],
) -> None:
    if name in seen:
        raise P4ResourceEnforcementError("duplicate archive name rejected")
    parts = name.split("/")
    for idx in range(1, len(parts)):
        parent = "/".join(parts[:idx])
        if seen.get(parent) == "file":
            raise P4ResourceEnforcementError("archive file/directory collision rejected")
    prefix = name + "/"
    if not is_dir and any(existing.startswith(prefix) for existing in seen):
        raise P4ResourceEnforcementError("archive file/directory collision rejected")
    seen[name] = "dir" if is_dir else "file"


def _copy_limited(
    source: Any, target: Any, *, expected: int, deadline: float | None = None
) -> None:
    remaining = expected
    while remaining:
        if deadline is not None and time.monotonic() > deadline:
            raise P4ResourceEnforcementError("archive extraction deadline exceeded")
        chunk = source.read(min(65_536, remaining))
        if not chunk:
            raise P4ResourceEnforcementError("archive member ended before declared size")
        target.write(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise P4ResourceEnforcementError("archive member exceeds declared size")


def _prepare_destination(destination: Path) -> Path:
    if destination.is_symlink():
        raise P4ResourceEnforcementError("archive destination symlink rejected")
    destination = destination.resolve()
    if destination.exists():
        if not destination.is_dir():
            raise P4ResourceEnforcementError("archive destination must be a directory")
        if any(destination.iterdir()):
            raise P4ResourceEnforcementError("archive destination must be absent or empty")
    else:
        destination.mkdir(parents=True, mode=0o700)
    return destination


def _safe_target(destination: Path, name: str) -> Path:
    target = (destination / name).resolve()
    try:
        target.relative_to(destination)
    except ValueError as exc:
        raise P4ResourceEnforcementError("archive target escapes destination") from exc
    return target


def _archive_limits(policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    archive = _mapping(policy.get("archive_extraction"), "archive_extraction")
    artifacts = _limits(policy, "artifacts")
    for key in (
        "reject_absolute_paths",
        "reject_parent_traversal",
        "reject_symlinks",
        "reject_hardlinks",
        "reject_device_entries",
        "reject_duplicate_names",
        "reject_type_collisions",
    ):
        if archive.get(key) is not True:
            raise P4ResourceEnforcementError(f"archive hardening flag is not enabled: {key}")
    return archive, artifacts


def _check_archive_totals(
    *,
    compressed_size: int,
    expanded_size: int,
    file_count: int,
    archive: dict[str, Any],
    artifacts: dict[str, Any],
) -> None:
    compressed_limit = _positive_int(archive.get("compressed_bytes"), "archive.compressed_bytes")
    expanded_limit = _positive_int(archive.get("expanded_bytes"), "archive.expanded_bytes")
    ratio = _positive_int(archive.get("max_expansion_ratio"), "archive.max_expansion_ratio")
    max_files = min(
        _positive_int(archive.get("max_files"), "archive.max_files"),
        _positive_int(artifacts.get("max_files"), "artifacts.max_files"),
    )
    artifact_total = _positive_int(artifacts.get("total_bytes"), "artifacts.total_bytes")
    if compressed_size > compressed_limit:
        raise P4ResourceEnforcementError("archive compressed bytes exceed policy")
    if expanded_size > expanded_limit or expanded_size > artifact_total:
        raise P4ResourceEnforcementError("archive expanded bytes exceed policy")
    if file_count > max_files:
        raise P4ResourceEnforcementError("archive file count exceeds policy")
    if compressed_size == 0:
        if expanded_size:
            raise P4ResourceEnforcementError("archive expansion ratio exceeds policy")
    elif expanded_size > compressed_size * ratio:
        raise P4ResourceEnforcementError("archive expansion ratio exceeds policy")


def _archive_entry_limit(archive: dict[str, Any], artifacts: dict[str, Any]) -> int:
    return min(
        _positive_int(archive.get("max_files"), "archive.max_files"),
        _positive_int(artifacts.get("max_files"), "artifacts.max_files"),
    )


def _zip_preflight(path: Path, limit: int) -> None:
    # Read EOCD before ZipFile builds its unbounded central-directory list.
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - 65_557))
        tail = stream.read(65_557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise P4ResourceEnforcementError("ZIP central directory missing")
    (_, disk, cd_disk, disk_count, count, cd_size, cd_start, comment) = struct.unpack_from(
        "<4s4H2LH", tail, offset
    )
    if disk or cd_disk or disk_count != count or count == 0xFFFF:
        raise P4ResourceEnforcementError("ZIP multi-disk/ZIP64 rejected")
    if len(tail) - offset != 22 + comment:
        raise P4ResourceEnforcementError("ZIP trailing data rejected")
    if count > limit or cd_size > min(1_048_576, limit * 8192):
        raise P4ResourceEnforcementError("archive entry/metadata budget exceeded")
    if cd_start + cd_size > size - (len(tail) - offset):
        raise P4ResourceEnforcementError("ZIP central directory range rejected")


def _extract_zip(archive_path: Path, destination: Path, policy: dict[str, Any]) -> dict[str, int]:
    archive, artifacts = _archive_limits(policy)
    limit = _archive_entry_limit(archive, artifacts)
    _zip_preflight(archive_path, limit)
    max_depth = min(
        _positive_int(archive.get("max_depth"), "archive.max_depth"),
        _positive_int(artifacts.get("max_depth"), "artifacts.max_depth"),
    )
    per_file = _positive_int(artifacts.get("per_file_bytes"), "artifacts.per_file_bytes")
    seen: dict[str, str] = {}
    files: list[tuple[zipfile.ZipInfo, str]] = []
    expanded = 0
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > limit:
            raise P4ResourceEnforcementError("archive entry count exceeds policy")
        for info in infos:
            if (
                len(info.filename.encode("utf-8")) > 1024
                or len(info.extra) > 4096
                or len(info.comment) > 4096
            ):
                raise P4ResourceEnforcementError("archive metadata budget exceeded")
            name, trailing_dir = _archive_name(info.filename, max_depth=max_depth)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise P4ResourceEnforcementError("archive symlink rejected")
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise P4ResourceEnforcementError("archive special entry rejected")
            if mode == stat.S_IFDIR and not trailing_dir:
                raise P4ResourceEnforcementError("ZIP directory type/name mismatch")
            if mode == stat.S_IFREG and trailing_dir:
                raise P4ResourceEnforcementError("ZIP regular type/name mismatch")
            is_dir = trailing_dir
            if is_dir and info.file_size:
                raise P4ResourceEnforcementError("ZIP directory has payload")
            _register_archive_path(name, is_dir=is_dir, seen=seen)
            if is_dir:
                continue
            if info.file_size > per_file:
                raise P4ResourceEnforcementError("archive member exceeds per-file policy")
            expanded += info.file_size
            files.append((info, name))
        _check_archive_totals(
            compressed_size=archive_path.stat().st_size,
            expanded_size=expanded,
            file_count=len(files),
            archive=archive,
            artifacts=artifacts,
        )
        destination = _prepare_destination(destination)
        for name, kind in seen.items():
            if kind == "dir":
                _safe_target(destination, name).mkdir(parents=True, exist_ok=True)
        for info, name in files:
            target = _safe_target(destination, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as source, target.open("xb") as output:
                _copy_limited(
                    source,
                    output,
                    expected=info.file_size,
                    deadline=time.monotonic() + 30.0,
                )
    return validate_artifact_tree(destination, policy)


@contextlib.contextmanager
def _bounded_tar_stream(path: Path, limit: int, entries: int) -> Iterator[Any]:
    # Bound decompression before tarfile processes extended headers.
    with tempfile.TemporaryFile(mode="w+b") as spool, path.open("rb") as source:
        magic = source.read(6)
        source.seek(0)
        copied = 0
        deadline = time.monotonic() + 30.0

        def drain(reader: Any) -> None:
            nonlocal copied
            while True:
                if time.monotonic() > deadline:
                    raise P4ResourceEnforcementError("archive decompression deadline exceeded")
                data = reader.read(65_536)
                if not data:
                    break
                copied += len(data)
                if copied > limit:
                    raise P4ResourceEnforcementError("archive decompression budget exceeded")
                spool.write(data)

        if magic.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=source) as reader:
                drain(reader)
        elif magic.startswith(b"BZh"):
            with bz2.BZ2File(source) as reader:
                drain(reader)
        elif magic == b"\xfd7zXZ\x00":
            with lzma.LZMAFile(source) as reader:
                drain(reader)
        else:
            drain(source)
        spool.seek(0)
        count = 0
        meta_bytes = 0
        offset = 0
        while offset + 512 <= copied:
            spool.seek(offset)
            header = spool.read(512)
            if header == bytes(512):
                break
            count += 1
            if count > entries:
                raise P4ResourceEnforcementError("archive entry count exceeds policy")
            kind = header[156:157]
            size_text = header[124:136].rstrip(b"\x00 ").lstrip(b" ")
            if not size_text or size_text[:1] == b"\x80":
                raise P4ResourceEnforcementError("unsupported TAR size encoding")
            try:
                size = int(size_text, 8)
            except ValueError as exc:
                raise P4ResourceEnforcementError("invalid TAR member size") from exc
            if kind in (b"x", b"g", b"L", b"K"):
                meta_bytes += size
                if size > 65_536 or meta_bytes > min(1_048_576, entries * 8192):
                    raise P4ResourceEnforcementError("archive metadata budget exceeded")
            elif kind not in (b"0", b"\x00", b"5", b"1", b"2", b"3", b"4", b"6"):
                raise P4ResourceEnforcementError("archive unsupported TAR entry type")
            offset += 512 + ((size + 511) // 512) * 512
            if offset > copied:
                raise P4ResourceEnforcementError("truncated TAR payload")
        spool.seek(0)
        yield spool


def _extract_tar(archive_path: Path, destination: Path, policy: dict[str, Any]) -> dict[str, int]:
    archive, artifacts = _archive_limits(policy)
    entry_limit = _archive_entry_limit(archive, artifacts)
    max_depth = min(
        _positive_int(archive.get("max_depth"), "archive.max_depth"),
        _positive_int(artifacts.get("max_depth"), "artifacts.max_depth"),
    )
    per_file = _positive_int(artifacts.get("per_file_bytes"), "artifacts.per_file_bytes")
    expanded_limit = _positive_int(archive.get("expanded_bytes"), "archive.expanded_bytes")
    artifact_limit = _positive_int(artifacts.get("total_bytes"), "artifacts.total_bytes")
    metadata_allowance = min(1_048_576, entry_limit * 8192)
    stream_limit = min(expanded_limit, artifact_limit) + metadata_allowance
    with _bounded_tar_stream(archive_path, stream_limit, entry_limit) as spool:
        seen: dict[str, str] = {}
        files: list[tuple[tarfile.TarInfo, str]] = []
        expanded = 0
        with tarfile.open(fileobj=spool, mode="r:") as tf:
            for member in tf.getmembers():
                if len(member.name.encode("utf-8")) > 1024:
                    raise P4ResourceEnforcementError("archive name exceeds metadata budget")
                name, trailing_dir = _archive_name(member.name, max_depth=max_depth)
                is_dir = member.isdir()
                if trailing_dir != is_dir and trailing_dir:
                    raise P4ResourceEnforcementError("TAR type/name mismatch")
                if member.issym():
                    raise P4ResourceEnforcementError("archive symlink rejected")
                if member.islnk():
                    raise P4ResourceEnforcementError("archive hardlink rejected")
                if member.isdev() or member.isfifo():
                    raise P4ResourceEnforcementError("archive device/fifo rejected")
                if not (member.isfile() or is_dir):
                    raise P4ResourceEnforcementError("archive special entry rejected")
                _register_archive_path(name, is_dir=is_dir, seen=seen)
                if is_dir:
                    continue
                if member.size > per_file:
                    raise P4ResourceEnforcementError("archive member exceeds per-file policy")
                expanded += member.size
                files.append((member, name))
            _check_archive_totals(
                compressed_size=archive_path.stat().st_size,
                expanded_size=expanded,
                file_count=len(files),
                archive=archive,
                artifacts=artifacts,
            )
            destination = _prepare_destination(destination)
            for name, kind in seen.items():
                if kind == "dir":
                    _safe_target(destination, name).mkdir(parents=True, exist_ok=True)
            for member, name in files:
                source = tf.extractfile(member)
                if source is None:
                    raise P4ResourceEnforcementError("archive regular file has no data stream")
                target = _safe_target(destination, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as output:
                    _copy_limited(
                        source,
                        output,
                        expected=member.size,
                        deadline=time.monotonic() + 30.0,
                    )
    return validate_artifact_tree(destination, policy)


def safe_extract_archive(
    archive_path: Path, destination: Path, policy: dict[str, Any]
) -> dict[str, int]:
    try:
        if archive_path.is_symlink() or not archive_path.is_file():
            raise P4ResourceEnforcementError("archive input must be a regular file")
        compressed_limit = _positive_int(
            _mapping(policy.get("archive_extraction"), "archive_extraction").get(
                "compressed_bytes"
            ),
            "archive.compressed_bytes",
        )
        if archive_path.stat().st_size > compressed_limit:
            raise P4ResourceEnforcementError("archive compressed bytes exceed policy")
        if destination.is_symlink() or (
            destination.exists() and (not destination.is_dir() or any(destination.iterdir()))
        ):
            raise P4ResourceEnforcementError("archive destination must be absent or empty")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".p4_archive_", dir=destination.parent) as owned:
            staging = Path(owned) / "tree"
            if zipfile.is_zipfile(archive_path):
                result = _extract_zip(archive_path, staging, policy)
            else:
                result = _extract_tar(archive_path, staging, policy)
            if destination.exists():
                destination.rmdir()
            staging.rename(destination)
            return result
    except P4ResourceEnforcementError:
        raise
    except (
        OSError,
        ValueError,
        EOFError,
        zipfile.BadZipFile,
        tarfile.TarError,
        gzip.BadGzipFile,
        lzma.LZMAError,
    ) as exc:
        raise P4ResourceEnforcementError("archive input or extraction invalid") from exc


def _docker_size(value: int) -> str:
    for unit, divisor in (("g", 1024**3), ("m", 1024**2), ("k", 1024)):
        if value % divisor == 0:
            return f"{value // divisor}{unit}"
    return str(value)


def docker_resource_args(policy: dict[str, Any]) -> list[str]:
    docker = _limits(policy, "docker_runtime")
    if docker.get("log_driver") != "local":
        raise P4ResourceEnforcementError("docker log driver must be local")
    return [
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(_positive_int(docker.get("pids_limit"), "docker.pids_limit")),
        "--memory",
        str(_positive_int(docker.get("memory_bytes"), "docker.memory_bytes")),
        "--cpus",
        f"{_positive_int(docker.get('nano_cpus'), 'docker.nano_cpus') / 1_000_000_000:.2f}",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={_docker_size(_positive_int(docker.get('tmpfs_bytes'), 'docker.tmpfs_bytes'))}",
        "--log-driver",
        "local",
        "--log-opt",
        f"max-size={_docker_size(_positive_int(docker.get('log_max_size_bytes'), 'docker.log_max_size_bytes'))}",
        "--log-opt",
        f"max-file={_positive_int(docker.get('log_max_files'), 'docker.log_max_files')}",
    ]


def build_command_limits(policy: dict[str, Any]) -> dict[str, int]:
    build = _limits(policy, "build")
    return {
        "timeout_seconds": _positive_int(build.get("timeout_seconds"), "build.timeout_seconds"),
        "output_budget_bytes": _positive_int(
            build.get("log_output_bytes"), "build.log_output_bytes"
        ),
        "context_bytes": _positive_int(build.get("context_bytes"), "build.context_bytes"),
    }


def subprocess_limits(policy: dict[str, Any]) -> dict[str, int]:
    subprocess_policy = _limits(policy, "subprocess")
    return {
        "timeout_seconds": _positive_int(
            subprocess_policy.get("command_timeout_seconds"), "subprocess.command_timeout_seconds"
        ),
        "output_budget_bytes": _positive_int(
            subprocess_policy.get("aggregate_output_bytes"), "subprocess.aggregate_output_bytes"
        ),
        "capture_limit_bytes": _positive_int(
            subprocess_policy.get("retained_bytes_per_stream"),
            "subprocess.retained_bytes_per_stream",
        ),
    }


@dataclass
class TrafficBudget:
    request_bytes: int
    response_bytes: int
    max_requests: int
    aggregate_bytes: int
    requests: int = 0
    total_bytes: int = 0

    @classmethod
    def from_policy(cls, policy: dict[str, Any]) -> TrafficBudget:
        value = _limits(policy, "fixture_traffic")
        return cls(
            request_bytes=_positive_int(value.get("request_bytes"), "fixture.request_bytes"),
            response_bytes=_positive_int(value.get("response_bytes"), "fixture.response_bytes"),
            max_requests=_positive_int(value.get("max_requests"), "fixture.max_requests"),
            aggregate_bytes=_positive_int(value.get("aggregate_bytes"), "fixture.aggregate_bytes"),
        )

    breached: bool = False

    def record(self, *, request_bytes: int, response_bytes: int) -> None:
        if self.breached:
            raise P4ResourceEnforcementError("fixture budget already breached")
        if type(request_bytes) is not int or type(response_bytes) is not int:
            raise P4ResourceEnforcementError("fixture byte counts must be integers")
        if request_bytes < 0 or response_bytes < 0:
            raise P4ResourceEnforcementError("fixture byte counts must be non-negative")
        requests = self.requests + 1
        total = self.total_bytes + request_bytes + response_bytes
        if request_bytes > self.request_bytes:
            self.breached = True
            raise P4ResourceEnforcementError("fixture request exceeds policy")
        if response_bytes > self.response_bytes:
            self.breached = True
            raise P4ResourceEnforcementError("fixture response exceeds policy")
        if requests > self.max_requests:
            self.breached = True
            raise P4ResourceEnforcementError("fixture request count exceeds policy")
        if total > self.aggregate_bytes:
            self.breached = True
            raise P4ResourceEnforcementError("fixture aggregate bytes exceed policy")
        self.requests = requests
        self.total_bytes = total


@dataclass
class OwnedResourceBudget:
    max_containers: int
    max_networks: int
    max_volumes: int
    containers: int = 0
    networks: int = 0
    volumes: int = 0

    @classmethod
    def from_policy(cls, policy: dict[str, Any]) -> OwnedResourceBudget:
        value = _limits(policy, "docker_runtime")
        return cls(
            max_containers=_positive_int(
                value.get("max_owned_containers_per_attempt"),
                "docker.max_owned_containers_per_attempt",
            ),
            max_networks=_positive_int(
                value.get("max_owned_networks_per_attempt"),
                "docker.max_owned_networks_per_attempt",
            ),
            max_volumes=_positive_int(
                value.get("max_owned_volumes_per_attempt"),
                "docker.max_owned_volumes_per_attempt",
            ),
        )

    def record_container(self) -> None:
        self.containers += 1
        if self.containers > self.max_containers:
            raise P4ResourceEnforcementError("owned container count exceeds policy")

    def record_network(self) -> None:
        self.networks += 1
        if self.networks > self.max_networks:
            raise P4ResourceEnforcementError("owned network count exceeds policy")

    def record_volume(self) -> None:
        self.volumes += 1
        if self.volumes > self.max_volumes:
            raise P4ResourceEnforcementError("owned volume count exceeds policy")


@dataclass(frozen=True)
class AttemptDeadline:
    deadline: float
    cleanup_timeout_seconds: int

    @classmethod
    def from_policy(cls, policy: dict[str, Any], *, now: float | None = None) -> AttemptDeadline:
        value = _limits(policy, "execution")
        attempt = _positive_int(
            value.get("attempt_timeout_seconds"), "execution.attempt_timeout_seconds"
        )
        cleanup = _positive_int(
            value.get("cleanup_timeout_seconds"), "execution.cleanup_timeout_seconds"
        )
        current = time.monotonic() if now is None else now
        return cls(deadline=current + attempt, cleanup_timeout_seconds=cleanup)

    def remaining(self, *, now: float | None = None) -> float:
        current = time.monotonic() if now is None else now
        remaining = self.deadline - current
        if remaining <= 0:
            raise P4ResourceEnforcementError("attempt timeout exceeded")
        return remaining


class AttemptLease:
    def __init__(self, path: Path, policy: dict[str, Any]) -> None:
        execution = _limits(policy, "execution")
        if (
            _positive_int(
                execution.get("max_concurrent_attempts"), "execution.max_concurrent_attempts"
            )
            != 1
        ):
            raise P4ResourceEnforcementError("only max_concurrent_attempts=1 is supported")
        self.path = path
        self._file: Any = None

    def __enter__(self) -> AttemptLease:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a+b")
        try:
            fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._file.close()
            self._file = None
            raise P4ResourceEnforcementError("concurrent attempt rejected") from exc
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        if self._file is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            self._file.close()
            self._file = None


def classify_cleanup_evidence(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    cleanup = _mapping(policy.get("cleanup_semantics"), "cleanup_semantics")
    unknown = {
        "outcome": cleanup.get("malformed_or_missing_evidence_outcome"),
        "recovery_required": cleanup.get("recovery_required"),
    }
    if unknown != {"outcome": "UNKNOWN", "recovery_required": True}:
        raise P4ResourceEnforcementError("cleanup policy must fail closed")
    if not isinstance(value, dict):
        return unknown
    if set(value) != {"cleanup_complete", "owned_resources_remaining"}:
        return unknown
    if not isinstance(value.get("cleanup_complete"), bool):
        return unknown
    remaining = value.get("owned_resources_remaining")
    if isinstance(remaining, bool) or not isinstance(remaining, int) or remaining < 0:
        return unknown
    if value["cleanup_complete"] is True and remaining == 0:
        return {"outcome": "CLEAN", "recovery_required": False}
    return unknown


def policy_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_trust_binding(repo: Path, trust_path: Path, policy_path: Path) -> dict[str, Any]:
    policy = load_policy(policy_path)
    trust = _load_object_bytes(trust_path.read_bytes(), max_bytes=131_072, label="trust boundary")
    binding = _mapping(trust.get("p4_resource_enforcement"), "trust.p4_resource_enforcement")
    expected = {
        "status": "IMPLEMENTED_NOT_RUNTIME_PROVEN",
        "stage": "PRE_HOSTILE_ENFORCEMENT_IMPLEMENTATION",
        "module_path": MODULE_REL,
        "module_sha256": hashlib.sha256((repo / MODULE_REL).read_bytes()).hexdigest(),
        "policy_path": POLICY_REL,
        "policy_sha256": policy_sha256(policy_path),
        "candidate_execution_enabled": False,
        "hostile_execution_authorized": False,
        "runtime_enforcement_proven": False,
        "implemented_primitives": IMPLEMENTED_PRIMITIVES,
    }
    if binding != expected:
        raise P4ResourceEnforcementError("trust-boundary enforcement binding mismatch")
    controller = _mapping(trust.get("controller"), "trust.controller")
    if (
        controller.get("controller_stage") != "INTAKE_ONLY"
        or controller.get("candidate_execution_enabled") is not False
    ):
        raise P4ResourceEnforcementError(
            "controller must remain intake-only with candidate execution disabled"
        )
    publisher = _mapping(trust.get("publisher"), "trust.publisher")
    if (
        publisher.get("bootstrap_status") != "UNBOOTSTRAPPED"
        or publisher.get("integration_id") is not None
    ):
        raise P4ResourceEnforcementError("publisher must remain unbootstrapped")
    consumed = trust.get("consumed_trusted_inputs")
    if not isinstance(consumed, list) or consumed.count(MODULE_REL) != 1:
        raise P4ResourceEnforcementError(
            "enforcement module must be listed exactly once as trusted input"
        )
    if (
        policy.get("runtime_enforcement_proven") is not False
        or policy.get("candidate_execution_enabled") is not False
    ):
        raise P4ResourceEnforcementError("frozen policy must remain unproven and non-executing")
    return binding


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--trust-boundary", type=Path, required=True)
    args = parser.parse_args()
    binding = validate_trust_binding(
        args.repo.resolve(), args.trust_boundary.resolve(), args.policy.resolve()
    )
    print(
        json.dumps(
            {
                "status": "P4_RESOURCE_ENFORCEMENT_IMPLEMENTED_NOT_RUNTIME_PROVEN",
                "candidate_execution_enabled": binding["candidate_execution_enabled"],
                "hostile_execution_authorized": binding["hostile_execution_authorized"],
                "runtime_enforcement_proven": binding["runtime_enforcement_proven"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
