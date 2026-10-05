from __future__ import annotations

import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FAILURE_EVIDENCE_PATH = PROJECT_ROOT / "assurance/phase2/failure_evidence.py"
APPROVAL_RUNNER = PROJECT_ROOT / "assurance/phase2/run_approval_demo.py"
ADVERSARIAL_RUNNER = PROJECT_ROOT / "assurance/phase2/run_adversarial_closure.py"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "phase2_failure_evidence_test", FAILURE_EVIDENCE_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("could not load failure_evidence.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _result(code: int = 0, *, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


class FakeDocker:
    def __init__(
        self,
        *,
        fail_state_preservation: bool = False,
        fail_output_preservation: bool = False,
        fail_volume_remove: str | None = None,
        fail_container_remove: str | None = None,
        fail_network_remove: str | None = None,
        fail_inspect: tuple[str, str] | None = None,
    ) -> None:
        self.fail_state_preservation = fail_state_preservation
        self.fail_output_preservation = fail_output_preservation
        self.fail_volume_remove = fail_volume_remove
        self.fail_container_remove = fail_container_remove
        self.fail_network_remove = fail_network_remove
        self.fail_inspect = fail_inspect
        self.containers = {"candidate", "app", "control", "evaluator"}
        self.networks = {"net-ca", "net-ec", "net-ctrl"}
        self.volumes = {"state-vol", "output-vol"}
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str, check: bool = True) -> SimpleNamespace:
        self.calls.append(tuple(args))
        if args[:3] == ("docker", "rm", "-f"):
            name = args[3]
            if name == self.fail_container_remove:
                return _result(1, stderr="injected container removal failure")
            self.containers.discard(name)
            return _result()

        if args[:3] == ("docker", "network", "rm"):
            name = args[3]
            if name == self.fail_network_remove:
                return _result(1, stderr="injected network removal failure")
            self.networks.discard(name)
            return _result()

        if args[:3] == ("docker", "volume", "rm"):
            name = args[3]
            if name == self.fail_volume_remove:
                return _result(1, stderr="injected volume removal failure")
            self.volumes.discard(name)
            return _result()

        if len(args) >= 4 and args[0] == "docker" and args[2] == "inspect":
            kind = args[1]
            name = args[3]
            if self.fail_inspect == (kind, name):
                return _result(1, stderr="Cannot connect to the Docker daemon")
            present = {
                "container": name in self.containers,
                "network": name in self.networks,
                "volume": name in self.volumes,
            }[kind]
            if present:
                return _result()
            missing = {
                "container": f"Error: No such container: {name}",
                "network": f"Error response from daemon: network {name} not found",
                "volume": f"Error response from daemon: get {name}: no such volume",
            }[kind]
            return _result(1, stderr=missing)

        if args[:2] == ("docker", "run"):
            joined = "\n".join(args)
            mounts = [args[i + 1] for i, item in enumerate(args[:-1]) if item == "-v"]
            preserved_mount = next(
                (item for item in mounts if item.endswith(":/preserved")),
                None,
            )
            if preserved_mount is None:
                raise AssertionError(f"preservation command missing /preserved mount: {args!r}")
            host = Path(preserved_mount.rsplit(":", 1)[0])
            host.mkdir(parents=True, exist_ok=True)

            if "state-vol:/state:ro" in joined:
                if self.fail_state_preservation:
                    return _result(1, stderr="injected state preservation failure")
                db = host / "fixture.db"
                connection = sqlite3.connect(db)
                try:
                    connection.execute("CREATE TABLE evidence(value TEXT)")
                    connection.execute("INSERT INTO evidence(value) VALUES ('retained')")
                    connection.commit()
                finally:
                    connection.close()
                (host / "sqlite-integrity.json").write_text(
                    json.dumps({"integrity_check": "ok"}) + "\n",
                    encoding="utf-8",
                )
                return _result()

            if "output-vol:/source:ro" in joined:
                if self.fail_output_preservation:
                    return _result(1, stderr="injected output preservation failure")
                (host / "partial-report.json").write_text('{"retained": true}\n', encoding="utf-8")
                return _result()

        raise AssertionError(f"unexpected fake docker command: {args!r}")


def _failure_cleanup(
    tmp_path: Path,
    docker: FakeDocker,
    *,
    stage: str,
    fence_error: bool = False,
):
    module = _module()
    fence_calls: list[str] = []

    def fence() -> None:
        fence_calls.append("fence")
        if fence_error:
            raise RuntimeError("injected fence failure")

    result = module.cleanup_resources(
        run=docker,
        evidence_dir=tmp_path,
        containers=["app", "control", "evaluator", "candidate"],
        networks=["net-ca", "net-ec", "net-ctrl"],
        volumes=["state-vol", "output-vol"],
        state_volume="state-vol",
        output_volume="output-vol",
        fixture_image="fixture-image",
        evaluator_image="evaluator-image",
        preserve_on_failure=True,
        failure_stage=stage,
        fence=fence,
    )
    return module, result, fence_calls


@pytest.mark.parametrize(
    "stage",
    ["final_snapshot_export", "saved_run_copy", "finalization"],
)
def test_failure_stages_fence_stop_writers_preserve_then_remove_volumes(
    tmp_path: Path,
    stage: str,
) -> None:
    docker = FakeDocker()
    _module_value, result, fence_calls = _failure_cleanup(tmp_path, docker, stage=stage)

    assert fence_calls == ["fence"]
    assert result.fence_attempted is True
    assert result.fence_succeeded is True
    assert result.preservation_complete is True
    assert result.cleanup_complete is True
    assert result.quarantined_volumes == ()
    assert result.finish_only_recovery_required is False
    assert (tmp_path / "preserved-failure/state/fixture.db").is_file()
    assert (tmp_path / "preserved-failure/output/partial-report.json").is_file()

    first_container_remove = min(
        i for i, call in enumerate(docker.calls) if call[:3] == ("docker", "rm", "-f")
    )
    last_container_remove = max(
        i for i, call in enumerate(docker.calls) if call[:3] == ("docker", "rm", "-f")
    )
    first_preservation = min(
        i for i, call in enumerate(docker.calls) if call[:2] == ("docker", "run")
    )
    first_volume_remove = min(
        i for i, call in enumerate(docker.calls) if call[:3] == ("docker", "volume", "rm")
    )
    assert first_container_remove < last_container_remove < first_preservation < first_volume_remove

    recovery = json.loads((tmp_path / "failure-recovery.json").read_text(encoding="utf-8"))
    assert recovery["failure_stage"] == stage
    assert recovery["committed_pass_permitted"] is False


def test_best_effort_fence_failure_is_recorded_but_does_not_block_consistent_backup(
    tmp_path: Path,
) -> None:
    docker = FakeDocker()
    _module_value, result, _calls = _failure_cleanup(
        tmp_path, docker, stage="final_snapshot_export", fence_error=True
    )
    assert result.fence_attempted is True
    assert result.fence_succeeded is False
    assert result.preservation_complete is True
    ledger = json.loads((tmp_path / "resource-ledger.json").read_text(encoding="utf-8"))
    assert ledger["preservation"]["fence"]["succeeded"] is False
    assert "injected fence failure" in ledger["preservation"]["fence"]["error"]


def test_output_preservation_failure_quarantines_only_output_volume(tmp_path: Path) -> None:
    docker = FakeDocker(fail_output_preservation=True)
    _module_value, result, _calls = _failure_cleanup(tmp_path, docker, stage="saved_run_copy")
    assert result.preservation_complete is False
    assert result.cleanup_complete is False
    assert result.quarantined_volumes == ("output-vol",)
    assert "state-vol" not in docker.volumes
    assert "output-vol" in docker.volumes
    assert result.finish_only_recovery_required is True


def test_state_preservation_failure_quarantines_only_state_volume(tmp_path: Path) -> None:
    docker = FakeDocker(fail_state_preservation=True)
    _module_value, result, _calls = _failure_cleanup(
        tmp_path, docker, stage="final_snapshot_export"
    )
    assert result.preservation_complete is False
    assert result.quarantined_volumes == ("state-vol",)
    assert "state-vol" in docker.volumes
    assert "output-vol" not in docker.volumes


def test_unstopped_writer_skips_consistency_claim_and_quarantines_both_volumes(
    tmp_path: Path,
) -> None:
    docker = FakeDocker(fail_container_remove="app")
    _module_value, result, _calls = _failure_cleanup(tmp_path, docker, stage="finalization")
    assert result.preservation_complete is False
    assert set(result.quarantined_volumes) == {"state-vol", "output-vol"}
    assert not any(call[:2] == ("docker", "run") for call in docker.calls)
    assert result.finish_only_recovery_required is True

    ledger = json.loads((tmp_path / "resource-ledger.json").read_text(encoding="utf-8"))
    assert ledger["preservation"]["writers_stopped"] is False
    assert ledger["preservation"]["state"] == "quarantined_unstopped_writer"
    assert ledger["preservation"]["output"] == "quarantined_unstopped_writer"


def test_normal_volume_cleanup_failure_stops_before_state_deletion_and_no_pass(
    tmp_path: Path,
) -> None:
    module = _module()
    docker = FakeDocker(fail_volume_remove="output-vol")
    result = module.cleanup_resources(
        run=docker,
        evidence_dir=tmp_path,
        containers=["app", "control", "evaluator", "candidate"],
        networks=["net-ca", "net-ec", "net-ctrl"],
        volumes=["output-vol", "state-vol"],
        state_volume="state-vol",
        output_volume="output-vol",
        fixture_image="fixture-image",
        evaluator_image="evaluator-image",
        preserve_on_failure=False,
        failure_stage=None,
    )
    assert result.cleanup_complete is False
    assert result.failure_stage == "cleanup_export"
    assert set(result.quarantined_volumes) == {"state-vol", "output-vol"}
    assert "state-vol" in docker.volumes
    assert "output-vol" in docker.volumes
    assert not any(call[:4] == ("docker", "volume", "rm", "state-vol") for call in docker.calls)
    assert result.finish_only_recovery_required is True
    recovery = json.loads((tmp_path / "failure-recovery.json").read_text(encoding="utf-8"))
    assert recovery["committed_pass_permitted"] is False


def test_normal_network_cleanup_failure_quarantines_volumes_before_deletion(
    tmp_path: Path,
) -> None:
    module = _module()
    docker = FakeDocker(fail_network_remove="net-ctrl")
    result = module.cleanup_resources(
        run=docker,
        evidence_dir=tmp_path,
        containers=["app", "control", "evaluator", "candidate"],
        networks=["net-ca", "net-ec", "net-ctrl"],
        volumes=["state-vol", "output-vol"],
        state_volume="state-vol",
        output_volume="output-vol",
        fixture_image="fixture-image",
        evaluator_image="evaluator-image",
        preserve_on_failure=False,
        failure_stage=None,
    )
    assert result.cleanup_complete is False
    assert result.failure_stage == "cleanup_export"
    assert set(result.quarantined_volumes) == {"state-vol", "output-vol"}
    assert not any(call[:3] == ("docker", "volume", "rm") for call in docker.calls)
    assert result.finish_only_recovery_required is True


def test_runners_declare_fence_stages_and_shared_preservation_helper() -> None:
    approval = APPROVAL_RUNNER.read_text(encoding="utf-8")
    adversarial = ADVERSARIAL_RUNNER.read_text(encoding="utf-8")

    for source in (approval, adversarial):
        assert "cleanup_resources" in source
        assert "preserve_on_failure" in source
        assert "failure_stage" in source
        assert "best_effort_fence" in source
        assert "fence=" in source

    assert "cleanup_attempt_id" in adversarial
    assert "runtime.cleanup_attempt_id = new_attempt" in adversarial
    assert "context_assembly" in approval
    assert "except BaseException as exc" in approval
    assert '_write(attempt_dir / "execution-context.json", context)' in approval
    assert "failure_fence" in approval
    assert "process_cleanup_error" in adversarial
    assert "active_error = sys.exc_info()[1]" in adversarial
    assert "owned_resources" in approval
    assert "owned_resources" in adversarial
    assert "for resource in reversed(created_volumes)" not in approval
    assert "for name in reversed(runtime.volumes)" not in adversarial

    combined = approval + adversarial + FAILURE_EVIDENCE_PATH.read_text(encoding="utf-8")
    assert "docker system prune" not in combined
    assert "docker volume prune" not in combined
    for stage in (
        "final_snapshot_export",
        "saved_run_copy",
        "finalization",
        "cleanup_export",
    ):
        assert stage in combined


def test_sqlite_preservation_uses_backup_api_integrity_check_and_read_only_source() -> None:
    source = FAILURE_EVIDENCE_PATH.read_text(encoding="utf-8")
    assert ".backup(" in source
    assert "PRAGMA integrity_check" in source
    assert ":/state:ro" in source
    assert "committed_pass_permitted" in source
    assert "QUARANTINED_FAILURE" in source
    assert "UNKNOWN_REQUIRES_RECOVERY" in source
    assert "uncertain_resources" in source


def test_unknown_resource_presence_is_never_reported_as_deleted(tmp_path: Path) -> None:
    module = _module()
    docker = FakeDocker(fail_inspect=("volume", "output-vol"))
    docker.volumes.discard("output-vol")
    result = module.cleanup_resources(
        run=docker,
        evidence_dir=tmp_path,
        containers=["app", "control", "evaluator", "candidate"],
        networks=["net-ca", "net-ec", "net-ctrl"],
        volumes=["state-vol", "output-vol"],
        state_volume="state-vol",
        output_volume="output-vol",
        fixture_image="fixture-image",
        evaluator_image="evaluator-image",
        preserve_on_failure=False,
        failure_stage=None,
    )
    assert result.cleanup_complete is False
    assert "volume:output-vol" in result.uncertain_resources
    assert result.finish_only_recovery_required is True

    ledger = json.loads((tmp_path / "resource-ledger.json").read_text(encoding="utf-8"))
    item = next(
        value
        for value in ledger["resources"]
        if value["kind"] == "volume" and value["name"] == "output-vol"
    )
    assert item["presence_after_cleanup"] == "UNKNOWN"
    assert item["disposition"] == "UNKNOWN_REQUIRES_RECOVERY"
    assert (
        not (tmp_path / "failure-recovery.json")
        .read_text(encoding="utf-8")
        .count('"committed_pass_permitted": true')
    )


def test_unknown_container_termination_skips_consistency_claim(tmp_path: Path) -> None:
    docker = FakeDocker(
        fail_container_remove="app",
        fail_inspect=("container", "app"),
    )
    _module_value, result, _calls = _failure_cleanup(
        tmp_path, docker, stage="final_snapshot_export"
    )
    assert result.preservation_complete is False
    assert "container:app" in result.uncertain_resources
    assert not any(call[:2] == ("docker", "run") for call in docker.calls)
    assert result.finish_only_recovery_required is True

    ledger = json.loads((tmp_path / "resource-ledger.json").read_text(encoding="utf-8"))
    assert ledger["preservation"]["writers_stopped"] is False
    assert "app" in ledger["preservation"]["uncertain_container_presence"]


def test_cleanup_json_compatibility_is_retained(tmp_path: Path) -> None:
    module = _module()
    docker = FakeDocker()
    result = module.cleanup_resources(
        run=docker,
        evidence_dir=tmp_path,
        containers=["app", "control", "evaluator", "candidate"],
        networks=["net-ca", "net-ec", "net-ctrl"],
        volumes=["state-vol", "output-vol"],
        state_volume="state-vol",
        output_volume="output-vol",
        fixture_image="fixture-image",
        evaluator_image="evaluator-image",
        preserve_on_failure=False,
        failure_stage=None,
    )
    assert result.cleanup_complete is True
    cleanup = json.loads((tmp_path / "cleanup.json").read_text(encoding="utf-8"))
    assert cleanup["cleanup_complete"] is True
    assert cleanup["cleanup_errors"] == []
    assert cleanup["uncertain_resources"] == []
    assert not (tmp_path / "failure-recovery.json").exists()


def test_actual_embedded_sqlite_backup_producer_writes_valid_sidecar_and_copy(
    tmp_path: Path,
) -> None:
    module = _module()
    state = tmp_path / "state"
    preserved = tmp_path / "preserved"
    state.mkdir()
    preserved.mkdir()
    db = state / "fixture.db"
    connection = sqlite3.connect(db)
    try:
        connection.execute("CREATE TABLE evidence(value TEXT)")
        connection.execute("INSERT INTO evidence(value) VALUES ('actual-producer')")
        connection.commit()
    finally:
        connection.close()

    env = dict(__import__("os").environ)
    env["MCP_GUARD_PHASE2_STATE_DIR"] = str(state)
    env["MCP_GUARD_PHASE2_PRESERVED_DIR"] = str(preserved)
    result = subprocess.run(
        [sys.executable, "-c", module._SQLITE_BACKUP_SCRIPT],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    sidecar = json.loads((preserved / "sqlite-integrity.json").read_text(encoding="utf-8"))
    assert sidecar == {"integrity_check": "ok"}
    copied = sqlite3.connect(preserved / "fixture.db")
    try:
        assert copied.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert copied.execute("SELECT value FROM evidence").fetchone() == ("actual-producer",)
    finally:
        copied.close()


def test_planned_but_absent_failure_volumes_are_not_materialized_for_preservation(
    tmp_path: Path,
) -> None:
    module = _module()
    docker = FakeDocker()
    docker.volumes.clear()
    result = module.cleanup_resources(
        run=docker,
        evidence_dir=tmp_path,
        containers=["app", "control", "evaluator", "candidate"],
        networks=["net-ca", "net-ec", "net-ctrl"],
        volumes=["state-vol", "output-vol"],
        state_volume="state-vol",
        output_volume="output-vol",
        fixture_image="fixture-image",
        evaluator_image="evaluator-image",
        preserve_on_failure=True,
        failure_stage="runtime_setup",
    )
    assert not any(call[:2] == ("docker", "run") for call in docker.calls)
    ledger = json.loads((tmp_path / "resource-ledger.json").read_text(encoding="utf-8"))
    assert ledger["preservation"]["state"] == "not_created"
    assert ledger["preservation"]["output"] == "not_created"
    assert result.preservation_complete is True


def test_unknown_planned_failure_volume_requires_recovery_without_preservation(
    tmp_path: Path,
) -> None:
    module = _module()
    docker = FakeDocker(fail_inspect=("volume", "state-vol"))
    docker.volumes.discard("state-vol")
    result = module.cleanup_resources(
        run=docker,
        evidence_dir=tmp_path,
        containers=["app", "control", "evaluator", "candidate"],
        networks=["net-ca", "net-ec", "net-ctrl"],
        volumes=["state-vol", "output-vol"],
        state_volume="state-vol",
        output_volume="output-vol",
        fixture_image="fixture-image",
        evaluator_image="evaluator-image",
        preserve_on_failure=True,
        failure_stage="runtime_setup",
    )
    assert result.finish_only_recovery_required is True
    assert "volume:state-vol" in result.uncertain_resources
    ledger = json.loads((tmp_path / "resource-ledger.json").read_text(encoding="utf-8"))
    assert ledger["preservation"]["state"] == "unknown_requires_recovery"
