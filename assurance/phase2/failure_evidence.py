from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

Run = Callable[..., Any]
Fence = Callable[[], None]

_SQLITE_BACKUP_SCRIPT = r"""\
import json
import sqlite3
from pathlib import Path

source = Path("/state/fixture.db")
destination = Path("/preserved/fixture.db")
if not source.is_file():
    raise SystemExit("fixture.db missing")
destination.parent.mkdir(parents=True, exist_ok=True)
src = sqlite3.connect("file:/state/fixture.db?mode=ro", uri=True)
dst = sqlite3.connect(str(destination))
try:
    src.backup(dst)
    row = dst.execute("PRAGMA integrity_check").fetchone()
    status = None if row is None else row[0]
    if status != "ok":
        raise SystemExit(f"integrity_check failed: {status!r}")
finally:
    dst.close()
    src.close()
Path("/preserved/sqlite-integrity.json").write_text(
    json.dumps({"integrity_check": "ok"}, sort_keys=True) + "\\n",
    encoding="utf-8",
)
"""

_COPY_OUTPUT_SCRIPT = r"""\
import shutil
from pathlib import Path

source = Path("/source")
destination = Path("/preserved")
destination.mkdir(parents=True, exist_ok=True)
for item in source.iterdir():
    target = destination / item.name
    if item.is_dir():
        shutil.copytree(item, target, dirs_exist_ok=True)
    else:
        shutil.copy2(item, target)
"""


@dataclass(frozen=True)
class CleanupResult:
    cleanup_complete: bool
    preservation_complete: bool
    failure_stage: str | None
    fence_attempted: bool
    fence_succeeded: bool | None
    quarantined_volumes: tuple[str, ...]
    uncertain_resources: tuple[str, ...]
    cleanup_errors: tuple[str, ...]
    preservation_errors: tuple[str, ...]
    finish_only_recovery_required: bool


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    manifest: dict[str, str] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        manifest[str(path.relative_to(root))] = _sha256(path)
    return manifest


Presence = Literal["PRESENT", "ABSENT", "UNKNOWN"]


def _presence(run: Run, kind: str, name: str) -> tuple[Presence, str | None]:
    result = run("docker", kind, "inspect", name, check=False)
    if result.returncode == 0:
        return "PRESENT", None

    stderr = str(getattr(result, "stderr", "") or "").strip()
    stdout = str(getattr(result, "stdout", "") or "").strip()
    detail = "\n".join(part for part in (stderr, stdout) if part)
    lowered = detail.lower()

    if kind == "container":
        absent = "no such container" in lowered or "no such object" in lowered
    elif kind == "network":
        absent = "no such network" in lowered or ("network " in lowered and " not found" in lowered)
    elif kind == "volume":
        absent = "no such volume" in lowered or "no such object" in lowered
    else:
        raise ValueError(f"unsupported Docker resource kind: {kind}")

    if absent:
        return "ABSENT", None

    return (
        "UNKNOWN",
        f"docker {kind} inspect could not establish presence for {name}: "
        f"{detail or 'no diagnostic output'}",
    )


def _preserve_state(
    *,
    run: Run,
    fixture_image: str,
    state_volume: str,
    destination: Path,
) -> tuple[bool, str | None]:
    destination.mkdir(parents=True, exist_ok=True)
    result = run(
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "0:0",
        "-v",
        f"{state_volume}:/state:ro",
        "-v",
        f"{destination.resolve()}:/preserved",
        "--entrypoint",
        "python",
        fixture_image,
        "-c",
        _SQLITE_BACKUP_SCRIPT,
        check=False,
    )
    if result.returncode != 0:
        return False, f"state preservation failed: {result.stderr.strip()}"
    db = destination / "fixture.db"
    integrity = destination / "sqlite-integrity.json"
    if not db.is_file() or not integrity.is_file():
        return False, "state preservation did not produce fixture.db + integrity evidence"
    return True, None


def _preserve_output(
    *,
    run: Run,
    evaluator_image: str,
    output_volume: str,
    destination: Path,
) -> tuple[bool, str | None]:
    destination.mkdir(parents=True, exist_ok=True)
    result = run(
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "0:0",
        "-v",
        f"{output_volume}:/source:ro",
        "-v",
        f"{destination.resolve()}:/preserved",
        "--entrypoint",
        "python",
        evaluator_image,
        "-c",
        _COPY_OUTPUT_SCRIPT,
        check=False,
    )
    if result.returncode != 0:
        return False, f"output preservation failed: {result.stderr.strip()}"
    return True, None


def cleanup_resources(
    *,
    run: Run,
    evidence_dir: Path,
    containers: list[str],
    networks: list[str],
    volumes: list[str],
    state_volume: str,
    output_volume: str,
    fixture_image: str,
    evaluator_image: str,
    preserve_on_failure: bool,
    failure_stage: str | None,
    fence: Fence | None = None,
) -> CleanupResult:
    cleanup_errors: list[str] = []
    preservation_errors: list[str] = []
    fence_attempted = False
    fence_succeeded: bool | None = None
    fence_error: str | None = None

    if preserve_on_failure and fence is not None:
        fence_attempted = True
        try:
            fence()
        except Exception as exc:  # best effort by design
            fence_succeeded = False
            fence_error = f"{type(exc).__name__}: {exc}"
        else:
            fence_succeeded = True

    # Terminate candidate activity and every fixture/evaluator writer before a
    # preservation copy. Container removal is non-destructive to named volumes.
    for name in reversed(containers):
        result = run("docker", "rm", "-f", name, check=False)
        if result.returncode != 0 and "No such container" not in result.stderr:
            cleanup_errors.append(f"container {name}: {result.stderr.strip()}")

    remaining_containers: list[str] = []
    uncertain_container_presence: list[str] = []
    for name in containers:
        presence, error = _presence(run, "container", name)
        if presence == "PRESENT":
            remaining_containers.append(name)
        elif presence == "UNKNOWN":
            uncertain_container_presence.append(name)
            if error:
                cleanup_errors.append(error)

    writers_stopped = not remaining_containers and not uncertain_container_presence
    if remaining_containers:
        cleanup_errors.append(
            "containers remained after forced termination: " + ", ".join(remaining_containers)
        )
    if uncertain_container_presence:
        cleanup_errors.append(
            "container termination could not be verified: "
            + ", ".join(uncertain_container_presence)
        )

    state_created = state_volume in volumes
    output_created = output_volume in volumes
    state_ok = not state_created
    output_ok = not output_created
    preserved_root = evidence_dir / "preserved-failure"
    preserved: dict[str, Any] = {
        "requested": preserve_on_failure,
        "fence": {
            "attempted": fence_attempted,
            "succeeded": fence_succeeded,
            "error": fence_error,
        },
        "writers_stopped": writers_stopped,
        "remaining_containers": list(remaining_containers),
        "uncertain_container_presence": list(uncertain_container_presence),
        "state": "not_requested",
        "output": "not_requested",
        "state_manifest": {},
        "output_manifest": {},
    }

    if preserve_on_failure:
        if not writers_stopped:
            if state_created:
                preserved["state"] = "quarantined_unstopped_writer"
                preservation_errors.append(
                    "state preservation skipped because writer termination was not verified"
                )
            else:
                preserved["state"] = "not_created"
            if output_created:
                preserved["output"] = "quarantined_unstopped_writer"
                preservation_errors.append(
                    "output preservation skipped because writer termination was not verified"
                )
            else:
                preserved["output"] = "not_created"
        else:
            if state_created:
                state_ok, error = _preserve_state(
                    run=run,
                    fixture_image=fixture_image,
                    state_volume=state_volume,
                    destination=preserved_root / "state",
                )
                preserved["state"] = "preserved" if state_ok else "failed"
                if error:
                    preservation_errors.append(error)
            else:
                preserved["state"] = "not_created"

            if output_created:
                output_ok, error = _preserve_output(
                    run=run,
                    evaluator_image=evaluator_image,
                    output_volume=output_volume,
                    destination=preserved_root / "output",
                )
                preserved["output"] = "preserved" if output_ok else "failed"
                if error:
                    preservation_errors.append(error)
            else:
                preserved["output"] = "not_created"

        preserved["state_manifest"] = _manifest(preserved_root / "state")
        preserved["output_manifest"] = _manifest(preserved_root / "output")

    for name in reversed(networks):
        result = run("docker", "network", "rm", name, check=False)
        if result.returncode != 0:
            presence, error = _presence(run, "network", name)
            if presence == "PRESENT":
                cleanup_errors.append(f"network {name}: {result.stderr.strip()}")
            elif presence == "UNKNOWN":
                cleanup_errors.append(
                    error or f"network {name}: removal state could not be verified"
                )

    # On a normal path, any cleanup failure discovered before volume deletion
    # changes the boundary into a failure. Keep the exact owned volumes rather
    # than deleting the only remaining fixture/output state.
    cleanup_failed_before_volumes = bool(cleanup_errors)

    # Delete a failure volume only when that exact volume has a preserved copy.
    # On a previously clean path, stop destructive volume cleanup after the
    # first failed removal. Always process the fixture state volume last,
    # independent of caller list ordering, so an earlier cleanup failure cannot
    # destroy the only remaining authoritative fixture state.
    stop_normal_volume_cleanup = cleanup_failed_before_volumes and not preserve_on_failure
    volume_cleanup_order = [name for name in reversed(volumes) if name != state_volume]
    if state_volume in volumes:
        volume_cleanup_order.append(state_volume)
    for name in volume_cleanup_order:
        if stop_normal_volume_cleanup:
            continue

        may_remove = True
        if preserve_on_failure:
            if not writers_stopped and name in {state_volume, output_volume}:
                may_remove = False
            elif name == state_volume:
                may_remove = state_ok
            elif name == output_volume:
                may_remove = output_ok
        if not may_remove:
            continue

        result = run("docker", "volume", "rm", name, check=False)
        if result.returncode != 0:
            presence, error = _presence(run, "volume", name)
            if presence == "PRESENT":
                cleanup_errors.append(f"volume {name}: {result.stderr.strip()}")
                if not preserve_on_failure:
                    stop_normal_volume_cleanup = True
            elif presence == "UNKNOWN":
                cleanup_errors.append(
                    error or f"volume {name}: removal state could not be verified"
                )
                if not preserve_on_failure:
                    stop_normal_volume_cleanup = True

    resource_ledger: list[dict[str, Any]] = []
    for kind, names in (("container", containers), ("network", networks), ("volume", volumes)):
        for name in names:
            presence, error = _presence(run, kind, name)
            if presence == "PRESENT":
                disposition = "QUARANTINED_FAILURE"
            elif presence == "ABSENT":
                disposition = "DELETED"
            else:
                disposition = "UNKNOWN_REQUIRES_RECOVERY"
            resource_ledger.append(
                {
                    "kind": kind,
                    "name": name,
                    "presence_after_cleanup": presence,
                    "presence_error": error,
                    "disposition": disposition,
                }
            )

    quarantined = tuple(
        item["name"]
        for item in resource_ledger
        if item["kind"] == "volume" and item["presence_after_cleanup"] == "PRESENT"
    )
    uncertain_resources = tuple(
        f"{item['kind']}:{item['name']}"
        for item in resource_ledger
        if item["presence_after_cleanup"] == "UNKNOWN"
    )
    remaining_resources = tuple(
        f"{item['kind']}:{item['name']}"
        for item in resource_ledger
        if item["presence_after_cleanup"] == "PRESENT"
    )
    cleanup_complete = not cleanup_errors and not remaining_resources and not uncertain_resources
    preservation_complete = (
        (state_ok and output_ok and writers_stopped) if preserve_on_failure else True
    )
    effective_failure_stage = failure_stage
    if effective_failure_stage is None and not cleanup_complete:
        effective_failure_stage = "cleanup_export"

    finish_only = bool(
        quarantined
        or cleanup_errors
        or preservation_errors
        or remaining_resources
        or uncertain_resources
        or (preserve_on_failure and not preservation_complete)
    )
    result = CleanupResult(
        cleanup_complete=cleanup_complete,
        preservation_complete=preservation_complete,
        failure_stage=effective_failure_stage,
        fence_attempted=fence_attempted,
        fence_succeeded=fence_succeeded,
        quarantined_volumes=quarantined,
        uncertain_resources=uncertain_resources,
        cleanup_errors=tuple(cleanup_errors),
        preservation_errors=tuple(preservation_errors),
        finish_only_recovery_required=finish_only,
    )

    _write_json(
        evidence_dir / "cleanup.json",
        {
            "cleanup_complete": result.cleanup_complete,
            "cleanup_errors": list(result.cleanup_errors),
            "quarantined_volumes": list(result.quarantined_volumes),
            "uncertain_resources": list(result.uncertain_resources),
            "failure_stage": result.failure_stage,
        },
    )
    _write_json(
        evidence_dir / "resource-ledger.json",
        {
            "schema_version": 1,
            "failure_stage": effective_failure_stage,
            "preservation": preserved,
            "resources": resource_ledger,
            "remaining_resources": list(remaining_resources),
            "uncertain_resources": list(uncertain_resources),
            "result": asdict(result),
        },
    )
    if preserve_on_failure or not cleanup_complete:
        _write_json(
            evidence_dir / "failure-recovery.json",
            {
                "schema_version": 1,
                "failure_stage": effective_failure_stage,
                "fence_attempted": result.fence_attempted,
                "fence_succeeded": result.fence_succeeded,
                "preservation_complete": result.preservation_complete,
                "quarantined_volumes": list(result.quarantined_volumes),
                "uncertain_resources": list(result.uncertain_resources),
                "finish_only_recovery_required": result.finish_only_recovery_required,
                "committed_pass_permitted": False,
            },
        )
    return result
