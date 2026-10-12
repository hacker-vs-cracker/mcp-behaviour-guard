from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "assurance/phase2/ci"
MODULE = CI / "p4_trusted_runtime_adapter.py"
POLICY = CI / "p4-resource-policy.json"
AUTHORITY = CI / "p3-promoted-authority.json"
TRUST = CI / "trust-boundary.json"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("p4_trusted_runtime_adapter_test", MODULE)
    assert spec and spec.loader
    instance = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = instance
    inserted = str(CI) not in sys.path
    if inserted:
        sys.path.insert(0, str(CI))
    try:
        spec.loader.exec_module(instance)
    finally:
        if inserted:
            sys.path.remove(str(CI))
    return instance


def _inputs(module: ModuleType) -> tuple[dict, bytes]:
    return module.bounds.load_policy(POLICY), AUTHORITY.read_bytes()


class FakeDocker:
    def __init__(self, *, fail_create: bool = False, foreign_owner: bool = False) -> None:
        self.commands: list[list[str]] = []
        self.names: set[str] = set()
        self.owners: dict[str, str] = {}
        self.fail_create = fail_create
        self.foreign_owner = foreign_owner

    def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
        from p4_trusted_runtime_adapter import CommandResult

        args = list(argv)
        self.commands.append(args)
        assert args[0] == "docker"
        assert 0 < timeout <= 300
        assert output_budget <= 1_048_576
        if args[:2] == ["docker", "create"]:
            name = args[args.index("--name") + 1]
            self.names.add(name)
            self.owners[name] = args[args.index("--label") + 1].split("=", 1)[1]
            if self.fail_create:
                raise OSError("ambiguous daemon response")
            return CommandResult(0, ("a" * 64).encode(), b"", 64)
        if args[1:3] in (["network", "create"], ["volume", "create"]):
            name = args[-1]
            self.names.add(name)
            self.owners[name] = args[args.index("--label") + 1].split("=", 1)[1]
            return CommandResult(0, name.encode(), b"", len(name))
        if args[1:3] == ["buildx", "create"]:
            name = args[args.index("--name") + 1]
            self.names.add(name)
            return CommandResult(0, name.encode(), b"", len(name))
        if "inspect" in args:
            name = args[-1]
            if name in self.names:
                if self.foreign_owner:
                    return CommandResult(0, b"another-owner\n", b"", 14)
                if args[1:3] == ["buildx", "inspect"]:
                    return CommandResult(
                        0,
                        f"Name: {name}\nDriver: docker-container\n".encode(),
                        b"",
                        55,
                    )
                owner = self.owners[name]
                return CommandResult(0, owner.encode(), b"", len(owner))
            return CommandResult(1, b"", b"Error: No such object", 21)
        if args[1] in {"rm", "buildx", "network", "volume"}:
            name = args[-1]
            self.names.discard(name)
            return CommandResult(0, b"", b"", 0)
        raise AssertionError(f"unexpected Docker command: {args}")


def test_source_only_binding_and_exact_promoted_fixed_images() -> None:
    module = _module()
    trust = json.loads(TRUST.read_text(encoding="utf-8"))
    bound = module.adapter_binding(MODULE, trust)
    assert bound["status"] == "SOURCE_WIRED_NOT_RUNTIME_PROVEN"
    assert bound["candidate_execution_enabled"] is False
    assert bound["runtime_enforcement_proven"] is False
    _, authority = _inputs(module)
    doc = json.loads(authority)
    image = doc["runtime"]["images"]["fixture"]
    assert module.approved_fixture_image(authority, role="fixture", image=image) == image
    for forged in (image + "-evil", "fixture:latest", "sha256:" + "0" * 64):
        with pytest.raises(module.P4AdapterError):
            module.approved_fixture_image(authority, role="fixture", image=forged)
    with pytest.raises(module.P4AdapterError):
        module.approved_fixture_image(
            authority,
            role="vertical_candidate",
            image=doc["runtime"]["images"]["vertical_candidate"],
        )
    altered = json.loads(authority)
    altered["platform"] = "linux/arm64"
    with pytest.raises(module.P4AdapterError):
        module.approved_fixture_image(json.dumps(altered).encode(), role="fixture", image=image)


def test_process_output_limit_and_timeout_are_bounded() -> None:
    module = _module()
    runner = module.BoundedProcess()
    with pytest.raises(module.P4AdapterError, match="output budget"):
        runner(
            [sys.executable, "-c", "import os; os.write(1, b'x'*8000)"],
            timeout=3,
            output_budget=1024,
            retained_per_stream=128,
        )
    with pytest.raises(module.P4AdapterError, match="deadline"):
        runner(
            [sys.executable, "-c", "import time; time.sleep(3)"],
            timeout=0.2,
            output_budget=1024,
            retained_per_stream=128,
        )


def test_streaming_traffic_rejects_undeclared_overbudget_before_forwarding() -> None:
    module = _module()
    policy, _ = _inputs(module)
    meter = module.StreamMeter(module.bounds.TrafficBudget.from_policy(policy))
    meter.begin()
    meter.account(b"a" * 60_000, response=False)
    with pytest.raises(module.P4AdapterError, match="budget"):
        meter.account(b"b" * 6_000, response=False)
    assert meter.aborted is True
    with pytest.raises(module.P4AdapterError):
        meter.finish()
    with pytest.raises(module.P4AdapterError):
        meter.begin()
    assert meter.budget.requests == 0


def test_exact_fixed_container_options_and_absence(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    fake = FakeDocker()
    # Module import is registered by helper for FakeDocker's result class.
    sys.modules["p4_trusted_runtime_adapter"] = module
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    with module.OwnedDockerAttempt(
        policy, "f12", tmp_path / "global.lock", tmp_path / "owned-f12.jsonl", run=fake
    ) as attempt:
        container = attempt.create_fixed_container(image, authority, role="fixture")
        assert container.object_id == "a" * 64
        assert container.state == "CREATED"
        assert attempt._reserve("network").state == "INTENT"
        cmd = fake.commands[0]
        assert cmd[:2] == ["docker", "create"]
        for flag in ("--read-only", "--pids-limit", "--log-driver", "--log-opt", "--tmpfs"):
            assert flag in cmd
        assert "local" in cmd and "max-size=1m" in cmd and "max-file=2" in cmd
        assert "--network" in cmd and "none" in cmd
        assert cmd[2:4] == ["--platform", "linux/amd64"]
        assert any(item == "/trusted-output:rw,noexec,nosuid,size=16777216" for item in cmd)
    assert attempt.recovery_required is False
    assert attempt.cleanup_result() == {"outcome": "CLEAN", "recovery_required": False}
    assert fake.names == set()


def test_partial_create_and_foreign_object_require_recovery(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    fake = FakeDocker(fail_create=True)
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy, "f13", tmp_path / "global.lock", tmp_path / "owned-f13.jsonl", run=fake
        ) as attempt,
        pytest.raises(module.P4AdapterError),
    ):
        attempt.create_fixed_container(image, authority, role="fixture")
    assert attempt.recovery_required is True
    assert attempt.cleanup_result()["outcome"] == "UNKNOWN"
    foreign = FakeDocker(foreign_owner=True)
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy, "f14", tmp_path / "global2.lock", tmp_path / "owned-f14.jsonl", run=foreign
        ) as other,
    ):
        other.create_network()
    assert other.recovery_required is True
    assert other.cleanup_result()["outcome"] == "UNKNOWN"
    assert not any(c[1:3] == ["network", "rm"] for c in foreign.commands)


def test_slots_reserved_before_side_effects(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy, "f15", tmp_path / "shared.lock", tmp_path / "owned-f15.jsonl", run=fake
    ) as attempt:
        cap = module.bounds.OwnedResourceBudget.from_policy(policy).max_networks
        for _ in range(cap):
            attempt._reserve("network")
        before = len(fake.commands)
        with pytest.raises(module.P4AdapterError, match="slot budget"):
            attempt.create_network()
        assert len(fake.commands) == before


def test_invalid_attempt_rejected_before_docker(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    fake = FakeDocker()
    with (
        pytest.raises(module.P4AdapterError),
        module.OwnedDockerAttempt(
            policy,
            "../../unsafe",
            tmp_path / "global.lock",
            tmp_path / "owned-invalid.jsonl",
            run=fake,
        ),
    ):
        pass
    assert fake.commands == []


def test_hyphenated_owner_label_and_write_ahead_ledger(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    ledger = tmp_path / "owned-hyphen.jsonl"
    with module.OwnedDockerAttempt(
        policy, "fixed-test", tmp_path / "global.lock", ledger, run=fake
    ) as attempt:
        network = attempt.create_network()
        assert network.name in fake.names
        assert fake.owners[network.name] == "fixed-test"
    assert attempt.cleanup_result() == {"outcome": "CLEAN", "recovery_required": False}
    events = [json.loads(line)["event"] for line in ledger.read_text().splitlines()]
    assert "CREATE_REQUESTED" in events
    assert "CREATE_CONFIRMED" in events
    assert "ABSENCE_VERIFIED" in events
    assert events[-1] == "FINISH_CLEAN"
    assert not fake.names
