from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PHASE2 = PROJECT_ROOT / "assurance/phase2"
APPROVAL = PHASE2 / "run_approval_demo.py"
ADVERSARIAL = PHASE2 / "run_adversarial_closure.py"


def _load(path: Path, name: str) -> ModuleType:
    sys.path.insert(0, str(PHASE2))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise AssertionError(f"could not load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def _result(code: int = 0, *, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def test_gate_volume_preservation_is_independent_and_delete_requires_verified_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load(APPROVAL, "phase2_approval_p1a_gate_test")
    volumes = {"authority-vol", "results-vol"}
    calls: list[tuple[str, ...]] = []

    def fake_run(*args: str, check: bool = True, **_kwargs: Any) -> SimpleNamespace:
        calls.append(tuple(args))
        if args[:3] == ("docker", "volume", "inspect"):
            name = args[3]
            if name in volumes:
                return _result()
            return _result(1, stderr=f"Error response from daemon: get {name}: no such volume")
        if args[:3] == ("docker", "volume", "rm"):
            volumes.discard(args[3])
            return _result()
        raise AssertionError(f"unexpected command: {args!r}")

    def fake_preserve(*, volume: str, **_kwargs: Any) -> dict[str, str]:
        if volume == "authority-vol":
            raise RuntimeError("injected authority export failure")
        return {"decision.json": "a" * 64}

    monkeypatch.setattr(module, "_run", fake_run)
    monkeypatch.setattr(module, "_copy_gate_volume_verified", fake_preserve)
    plans = module._gate_volume_plans(
        authority_volume="authority-vol", results_volume="results-vol", output=tmp_path
    )
    result = module._cleanup_gate_volumes(gate_image="gate-image", plans=plans, output=tmp_path)
    assert result["cleanup_complete"] is False
    assert result["finish_only_recovery_required"] is True
    ledger = json.loads((tmp_path / "gate-resource-ledger.json").read_text(encoding="utf-8"))
    assert ledger == result
    assert (tmp_path / "gate-recovery.json").is_file()
    assert "authority-vol" in volumes
    assert "results-vol" not in volumes
    assert not any(call[:4] == ("docker", "volume", "rm", "authority-vol") for call in calls)
    authority = next(item for item in result["resources"] if item["role"] == "authority")
    results = next(item for item in result["resources"] if item["role"] == "results")
    assert authority["preservation"] == "preservation_failed"
    assert authority["disposition"] == "QUARANTINED_FAILURE"
    assert results["preservation"] == "preserved_verified"
    assert results["disposition"] == "DELETED"


def test_gate_volume_unknown_presence_is_retained_without_export_or_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load(APPROVAL, "phase2_approval_p1a_unknown_test")
    calls: list[tuple[str, ...]] = []

    def fake_run(*args: str, check: bool = True, **_kwargs: Any) -> SimpleNamespace:
        calls.append(tuple(args))
        if args[:3] == ("docker", "volume", "inspect"):
            return _result(1, stderr="Cannot connect to the Docker daemon")
        raise AssertionError(f"unexpected command: {args!r}")

    monkeypatch.setattr(module, "_run", fake_run)
    monkeypatch.setattr(
        module,
        "_copy_gate_volume_verified",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not export UNKNOWN")),
    )
    plans = module._gate_volume_plans(
        authority_volume="authority-vol", results_volume="results-vol", output=tmp_path
    )
    result = module._cleanup_gate_volumes(gate_image="gate-image", plans=plans, output=tmp_path)
    assert result["finish_only_recovery_required"] is True
    assert all(item["disposition"] == "UNKNOWN_REQUIRES_RECOVERY" for item in result["resources"])
    assert not any(call[:3] == ("docker", "volume", "rm") for call in calls)


@pytest.mark.parametrize("fail_on", [1, 4, 6])
def test_partial_runtime_setup_cleanup_owns_all_planned_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_on: int
) -> None:
    module = _load(ADVERSARIAL, f"phase2_adversarial_p1a_setup_{fail_on}")
    count = 0
    captured: dict[str, Any] = {}

    def fake_run(*_args: str, **_kwargs: Any) -> SimpleNamespace:
        nonlocal count
        count += 1
        if count == fail_on:
            raise module.IsolationError(f"injected setup failure {fail_on}")
        return _result()

    def fake_cleanup(runtime: Any, output: Path, **kwargs: Any) -> None:
        captured["containers"] = list(runtime.containers)
        captured["networks"] = list(runtime.networks)
        captured["volumes"] = list(runtime.volumes)
        captured["output"] = output
        captured["preserve_on_failure"] = kwargs["preserve_on_failure"]
        captured["failure_stage"] = kwargs["failure_stage"]

    monkeypatch.setattr(module, "_run", fake_run)
    monkeypatch.setattr(module, "_cleanup", fake_cleanup)
    with pytest.raises(module.IsolationError, match="injected setup failure"):
        module._start_runtime(
            label="setup",
            mode="good",
            evaluator_image="eval",
            fixture_image="fixture",
            candidate_image="candidate",
            contract=tmp_path / "contract.yaml",
            output=tmp_path,
        )
    assert len(captured["networks"]) == 3
    assert len(captured["volumes"]) == 2
    assert len(captured["containers"]) == 4
    assert captured["preserve_on_failure"] is True
    assert captured["failure_stage"] == "runtime_setup"


def test_partial_runtime_attempt_setup_failure_is_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load(ADVERSARIAL, "phase2_adversarial_p1a_attempt")
    captured: dict[str, Any] = {}

    monkeypatch.setattr(module, "_run", lambda *_args, **_kwargs: _result())
    monkeypatch.setattr(module, "_wait_exec", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module,
        "_control",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            module.IsolationError("attempt create failed")
        ),
    )

    def fake_cleanup(runtime: Any, output: Path, **kwargs: Any) -> None:
        captured["containers"] = list(runtime.containers)
        captured["networks"] = list(runtime.networks)
        captured["volumes"] = list(runtime.volumes)
        captured["failure_stage"] = kwargs["failure_stage"]

    monkeypatch.setattr(module, "_cleanup", fake_cleanup)
    with pytest.raises(module.IsolationError, match="attempt create failed"):
        module._start_runtime(
            label="attempt",
            mode="good",
            evaluator_image="eval",
            fixture_image="fixture",
            candidate_image="candidate",
            contract=tmp_path / "contract.yaml",
            output=tmp_path,
        )
    assert len(captured["networks"]) == 3
    assert len(captured["volumes"]) == 2
    assert len(captured["containers"]) == 4
    assert captured["failure_stage"] == "runtime_setup"


def test_setup_keyboard_interrupt_still_enters_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load(ADVERSARIAL, "phase2_adversarial_p1a_keyboard")
    cleaned: list[bool] = []
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(module, "_cleanup", lambda *_args, **_kwargs: cleaned.append(True))
    with pytest.raises(KeyboardInterrupt):
        module._start_runtime(
            label="interrupt",
            mode="good",
            evaluator_image="eval",
            fixture_image="fixture",
            candidate_image="candidate",
            contract=tmp_path / "contract.yaml",
            output=tmp_path,
        )
    assert cleaned == [True]


def test_capture_failure_cannot_bypass_primary_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load(ADVERSARIAL, "phase2_adversarial_p1a_capture")
    runtime = module.Runtime(
        label="capture",
        net_ca="ca",
        net_ec="ec",
        net_ctrl="ctrl",
        state_volume="state",
        output_volume="output",
        app="app",
        control="control",
        evaluator="evaluator",
        candidate="candidate",
        attempt_id="attempt",
        cleanup_attempt_id="",
        token="secret-not-written",
        containers=["app", "control", "evaluator", "candidate"],
        networks=["ca", "ec", "ctrl"],
        volumes=["state", "output"],
    )
    cleanup_calls: list[bool] = []

    def fake_cleanup_resources(**_kwargs: Any) -> SimpleNamespace:
        cleanup_calls.append(True)
        return SimpleNamespace(cleanup_complete=True)

    monkeypatch.setattr(module, "cleanup_resources", fake_cleanup_resources)

    def fail_capture(_runtime: Any, _output: Path) -> None:
        raise RuntimeError("capture hook failed")

    with pytest.raises(RuntimeError, match="capture hook failed"):
        module._cleanup(
            runtime,
            tmp_path,
            fixture_image="fixture",
            evaluator_image="eval",
            preserve_on_failure=False,
            failure_stage=None,
            before_cleanup_capture=fail_capture,
        )
    assert cleanup_calls == [True]
    capture_error = (tmp_path / "capture-error.json").read_text(encoding="utf-8")
    assert "secret-not-written" not in capture_error
