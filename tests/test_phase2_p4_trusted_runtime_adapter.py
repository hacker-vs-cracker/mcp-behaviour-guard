from __future__ import annotations

import hashlib
import importlib.util
import json
import os
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


def _ledger_identity(lock: Path) -> dict[str, str]:
    lock.touch(exist_ok=True, mode=0o600)
    info = lock.stat()
    inode = f"{info.st_dev}:{info.st_ino}"
    daemon = "source-only-unbound"
    scope = hashlib.sha256(
        json.dumps([str(lock.resolve()), inode, daemon, daemon], separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "lease_scope_sha256": scope,
        "lock_identity": inode,
        "daemon_context": daemon,
        "daemon_identity": daemon,
    }


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
        self.ids: dict[str, str] = {}
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
            self.ids[name] = "a" * 64
            if self.fail_create:
                raise OSError("ambiguous daemon response")
            return CommandResult(0, ("a" * 64).encode(), b"", 64)
        if args[1:3] in (["network", "create"], ["volume", "create"]):
            name = args[-1]
            self.names.add(name)
            self.owners[name] = args[args.index("--label") + 1].split("=", 1)[1]
            identity = ("b" * 64) if args[1] == "network" else name
            self.ids[name] = identity
            return CommandResult(0, identity.encode(), b"", len(identity))
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
                result = f"{self.ids[name]}|{owner}".encode()
                return CommandResult(0, result, b"", len(result))
            return CommandResult(1, b"", b"Error: No such object", 21)
        if args[1] in {"rm", "buildx", "network", "volume"}:
            identity = args[-1]
            matches = [name for name in self.names if identity in {name, self.ids.get(name)}]
            for name in matches:
                self.names.discard(name)
                self.ids.pop(name, None)
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
    image = json.loads(authority)["runtime"]["images"]["evaluator"]
    with module.OwnedDockerAttempt(
        policy, "f12", tmp_path / "global.lock", tmp_path / "owned-f12.jsonl", run=fake
    ) as attempt:
        container = attempt.create_fixed_container(image, authority, role="evaluator")
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
    image = json.loads(authority)["runtime"]["images"]["evaluator"]
    fake = FakeDocker(fail_create=True)
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy, "f13", tmp_path / "global.lock", tmp_path / "owned-f13.jsonl", run=fake
        ) as attempt,
        pytest.raises(module.P4AdapterError),
    ):
        attempt.create_fixed_container(image, authority, role="evaluator")
    assert attempt.recovery_required is True
    assert attempt.cleanup_result()["outcome"] == "UNKNOWN"
    foreign = FakeDocker(foreign_owner=True)
    next_state = tmp_path / "other-state"
    next_state.mkdir(mode=0o700)
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy, "f14", next_state / "global2.lock", next_state / "owned-f14.jsonl", run=foreign
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


def test_prior_clean_ledger_can_reuse_only_same_local_scope(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    lock = tmp_path / "shared.lock"
    with module.OwnedDockerAttempt(
        policy, "first", lock, tmp_path / "owned-first.jsonl", run=fake
    ) as attempt:
        attempt.create_network()
    assert attempt.cleanup_result()["outcome"] == "CLEAN"
    with module.OwnedDockerAttempt(
        policy, "second", lock, tmp_path / "owned-second.jsonl", run=fake
    ):
        pass
    assert (tmp_path / "owned-second.jsonl").exists()


def test_prior_unknown_blocks_before_any_new_owned_operation(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker(fail_create=True)
    authority = AUTHORITY.read_bytes()
    image = json.loads(authority)["runtime"]["images"]["evaluator"]
    lock = tmp_path / "same-global.lock"
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy, "first", lock, tmp_path / "owned-first.jsonl", run=fake
        ) as attempt,
        pytest.raises(module.P4AdapterError),
    ):
        attempt.create_fixed_container(image, authority, role="evaluator")
    before = len(fake.commands)
    with (
        pytest.raises(module.P4RecoveryRequired, match="prior attempt unresolved"),
        module.OwnedDockerAttempt(
            policy, "second", lock, tmp_path / "owned-second.jsonl", run=fake
        ),
    ):
        pass
    assert len(fake.commands) == before
    assert not (tmp_path / "owned-second.jsonl").exists()


def test_forged_clean_ending_does_not_hide_unresolved_resources(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    fake = FakeDocker()
    lock = tmp_path / "global.lock"
    scope_info = _ledger_identity(lock)

    def row(event, **fields):
        return (
            json.dumps(
                dict(
                    event=event,
                    attempt="first",
                    nonce="deadbeef",
                    utc_epoch=1,
                    **scope_info,
                    **fields,
                ),
                sort_keys=True,
            )
            + "\n"
        )

    (tmp_path / "owned-first.jsonl").write_text(
        row("ATTEMPT_OPEN")
        + row(
            "RESERVED",
            kind="container",
            name="mcpbg-p4-first-test-container-1",
            state="INTENT",
            object_id=None,
        )
        + row(
            "CREATE_REQUESTED",
            kind="container",
            name="mcpbg-p4-first-test-container-1",
            state="REQUESTED",
            object_id=None,
        )
        + row("FINISH_CLEAN"),
        encoding="utf-8",
    )
    (tmp_path / "owned-first.jsonl").chmod(0o600)
    with (
        pytest.raises(module.P4RecoveryRequired, match="not verified absent"),
        module.OwnedDockerAttempt(
            policy, "second", lock, tmp_path / "owned-second.jsonl", run=fake
        ),
    ):
        pass
    assert fake.commands == []


@pytest.mark.parametrize(
    "mode", ["symlink", "truncated", "oversized", "duplicate_key", "unhashable_scope"]
)
def test_prior_corrupt_ledger_fails_closed(tmp_path: Path, mode: str) -> None:
    module = _module()
    policy, _ = _inputs(module)
    lock = tmp_path / "global.lock"
    prior = tmp_path / "owned-first.jsonl"
    if mode == "symlink":
        other = tmp_path / "outside.txt"
        other.write_text("outside")
        prior.symlink_to(other)
    elif mode == "truncated":
        prior.write_bytes(b'{"event":"ATTEMPT_OPEN"}')
    elif mode == "oversized":
        prior.write_bytes(b"x" * 131_073)
    else:
        prior.write_bytes(b'{"event":"ATTEMPT_OPEN","event":"FINISH_CLEAN"}\n')
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(policy, "second", lock, tmp_path / "owned-second.jsonl"),
    ):
        pass
    assert not (tmp_path / "owned-second.jsonl").exists()


def test_ledger_scope_must_share_lock_directory_and_known_name(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    separated = tmp_path / "other"
    separated.mkdir()
    for path in (separated / "owned-moved.jsonl", tmp_path / "wrong.jsonl"):
        with (
            pytest.raises(module.P4AdapterError),
            module.OwnedDockerAttempt(policy, "safe", tmp_path / "global.lock", path),
        ):
            pass
        assert not path.exists()


def test_prior_ledger_kind_cannot_change_between_events(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    fake = FakeDocker()
    lock = tmp_path / "global.lock"
    scope_info = _ledger_identity(lock)
    name = "mcpbg-p4-first-deadbeef-container-1"

    def row(event: str, kind: str | None = None) -> str:
        value = dict(event=event, attempt="first", nonce="deadbeef", utc_epoch=1, **scope_info)
        if kind is not None:
            states = {
                "RESERVED": "INTENT",
                "CREATE_REQUESTED": "REQUESTED",
                "ABSENCE_VERIFIED": "ABSENT",
            }
            value.update(kind=kind, name=name, state=states[event], object_id=None)
        return json.dumps(value, sort_keys=True) + "\n"

    (tmp_path / "owned-first.jsonl").write_text(
        row("ATTEMPT_OPEN")
        + row("RESERVED", "container")
        + row("CREATE_REQUESTED", "container")
        + row("ABSENCE_VERIFIED", "network")
        + row("FINISH_CLEAN"),
        encoding="utf-8",
    )
    (tmp_path / "owned-first.jsonl").chmod(0o600)
    with (
        pytest.raises(module.P4RecoveryRequired, match="inconsistent prior"),
        module.OwnedDockerAttempt(
            policy, "second", lock, tmp_path / "owned-second.jsonl", run=fake
        ),
    ):
        pass
    assert fake.commands == []
    assert not (tmp_path / "owned-second.jsonl").exists()


def test_cleanup_rejects_swapped_container_with_same_owner(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    image = json.loads(authority)["runtime"]["images"]["evaluator"]
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy, "swapped", tmp_path / "shared.lock", tmp_path / "owned-swapped.jsonl", run=fake
        ) as attempt,
    ):
        item = attempt.create_fixed_container(image, authority, role="evaluator")
        fake.ids[item.name] = "c" * 64  # same resource name and owner, different object
    assert attempt.cleanup_result() == {"outcome": "UNKNOWN", "recovery_required": True}
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in fake.commands)
    assert fake.names


def test_cleanup_uses_original_id_not_mutable_name(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    image = json.loads(authority)["runtime"]["images"]["evaluator"]
    with module.OwnedDockerAttempt(
        policy, "stable", tmp_path / "shared.lock", tmp_path / "owned-stable.jsonl", run=fake
    ) as attempt:
        item = attempt.create_fixed_container(image, authority, role="evaluator")
        identity = item.object_id
    assert ["docker", "rm", "-f", identity] in fake.commands
    assert not fake.names


def test_cleanup_network_id_identity_verification(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy, "network", tmp_path / "shared.lock", tmp_path / "owned-network.jsonl", run=fake
    ) as attempt:
        item = attempt.create_network()
        assert item.object_id == "b" * 64
    assert ["docker", "network", "rm", "b" * 64] in fake.commands
    assert not fake.names


def test_subprocess_aggregate_output_cannot_reset_per_command(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    policy["limits"]["subprocess"]["aggregate_output_bytes"] = 200
    policy["limits"]["subprocess"]["retained_bytes_per_stream"] = 16
    seen = []

    def bounded(argv, *, timeout, output_budget, retained_per_stream):
        assert timeout > 0
        assert retained_per_stream == min(16, output_budget)
        seen.append(output_budget)
        n = min(120, output_budget)
        return module.CommandResult(0, b"x" * min(n, 16), b"", n)

    with (
        pytest.raises(module.P4RecoveryRequired, match="UNKNOWN"),
        module.OwnedDockerAttempt(
            policy,
            "aggregate",
            tmp_path / "shared.lock",
            tmp_path / "owned-aggregate.jsonl",
            run=bounded,
        ) as attempt,
    ):
        attempt._checked_call(["docker", "version"])
        attempt._checked_call(["docker", "version"])
        assert attempt.command_output_bytes == 200
        with pytest.raises(module.P4AdapterError, match="aggregate"):
            attempt._checked_call(["docker", "version"])
    assert seen == [200, 80]
    assert attempt.cleanup_result() == {"outcome": "UNKNOWN", "recovery_required": True}


def test_cleanup_output_reserve_is_separate_from_command_budget(tmp_path: Path) -> None:
    import time

    module = _module()
    policy, _ = _inputs(module)
    policy["limits"]["subprocess"]["aggregate_output_bytes"] = 100
    used = []

    def bounded(argv, *, timeout, output_budget, retained_per_stream):
        assert timeout > 0
        used.append(output_budget)
        return module.CommandResult(0, b"", b"", output_budget)

    with module.OwnedDockerAttempt(
        policy, "reserved", tmp_path / "shared.lock", tmp_path / "owned-reserved.jsonl", run=bounded
    ) as attempt:
        attempt._checked_call(["docker", "version"])
        attempt._cleanup_deadline = time.monotonic() + 5
        attempt._checked_call(["docker", "version"], cleanup=True)
        assert attempt.command_output_bytes == 100
        assert attempt.cleanup_output_bytes == 100
    assert used == [100, 100]


def test_unaccounted_subprocess_result_fails_closed(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    calls = []

    def invalid(argv, *, timeout, output_budget, retained_per_stream):
        calls.append(argv)
        return module.CommandResult(0, b"a", b"", output_budget + 1)

    with (
        pytest.raises(module.P4RecoveryRequired, match="UNKNOWN"),
        module.OwnedDockerAttempt(
            policy,
            "accounting",
            tmp_path / "shared.lock",
            tmp_path / "owned-accounting.jsonl",
            run=invalid,
        ) as attempt,
    ):
        with pytest.raises(module.P4AdapterError, match="uncertain"):
            attempt._checked_call(["docker", "version"])
        assert attempt.command_output_unknown is True
        with pytest.raises(module.P4AdapterError, match="aggregate"):
            attempt._checked_call(["docker", "version"])
    assert len(calls) == 1
    assert attempt.cleanup_result() == {"outcome": "UNKNOWN", "recovery_required": True}


def test_forwarding_accounts_before_side_effect_and_aborts_on_writer_error() -> None:
    module = _module()
    policy, _ = _inputs(module)
    budget = module.bounds.TrafficBudget.from_policy(policy)
    relay = module.StreamMeter(budget)
    sent = []
    relay.begin()

    def sink(chunk: bytes) -> int:
        sent.append(chunk)
        return len(chunk)

    relay.forward(b"ok", response=False, sink=sink)
    policy_limit = budget.request_bytes
    with pytest.raises(module.P4AdapterError, match="budget"):
        relay.forward(b"x" * policy_limit, response=False, sink=sink)
    assert sent == [b"ok"]  # Over-budget chunk never reached the side effect.
    assert relay.aborted and budget.breached
    with pytest.raises(module.P4AdapterError):
        relay.finish()


def test_forwarding_partial_writer_and_exception_fail_closed() -> None:
    module = _module()
    policy, _ = _inputs(module)
    for writer in (lambda raw: len(raw) - 1, lambda raw: True):
        relay = module.StreamMeter(module.bounds.TrafficBudget.from_policy(policy))
        relay.begin()
        with pytest.raises(module.P4AdapterError, match="incomplete"):
            relay.forward(b"data", response=True, sink=writer)
        assert relay.aborted and relay.budget.breached
    relay = module.StreamMeter(module.bounds.TrafficBudget.from_policy(policy))
    relay.begin()

    def failing(_raw: bytes) -> int:
        raise OSError("downstream disconnected")

    with pytest.raises(OSError, match="disconnected"):
        relay.forward(b"data", response=False, sink=failing)
    assert relay.aborted and relay.budget.breached


def test_streamed_archive_atomic_publish_and_digest(tmp_path: Path) -> None:
    import hashlib
    import io
    import tarfile

    module = _module()
    policy, _ = _inputs(module)
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    payload = b"synthetic artifact"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("report.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    raw = buffer.getvalue()
    policy["archive_extraction"]["compressed_bytes"] = len(raw) + 128

    def pieces():
        for start in range(0, len(raw), 257):
            yield raw[start : start + 257]

    destination = parent / "results"
    result = module.receive_bounded_artifact_archive(
        pieces(), destination, policy, deadline=module.time.monotonic() + 20
    )
    assert result == {
        "files": 1,
        "bytes": len(payload),
        "archive_bytes": len(raw),
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
    }
    assert (destination / "report.txt").read_bytes() == payload
    with pytest.raises(module.P4AdapterError, match="exists"):
        module.receive_bounded_artifact_archive(
            pieces(), destination, policy, deadline=module.time.monotonic() + 20
        )


def test_streamed_archive_rejects_overflow_corruption_and_partial_exposure(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    destination = parent / "results"
    policy["archive_extraction"]["compressed_bytes"] = 1024
    for chunks in ([b"z" * 1025], [b"z" * 200], [b"ok", "wrong type"]):
        with pytest.raises(module.P4AdapterError):
            module.receive_bounded_artifact_archive(
                chunks, destination, policy, deadline=module.time.monotonic() + 20
            )
        assert not destination.exists()
        assert list(parent.iterdir()) == []


def test_streamed_archive_rejects_exhausted_deadline_and_unsafe_parent(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    with pytest.raises(module.P4AdapterError, match="deadline"):
        module.receive_bounded_artifact_archive(
            [b"blob"], parent / "results", policy, deadline=module.time.monotonic() - 1
        )
    for invalid in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(module.P4AdapterError, match="deadline invalid"):
            module.receive_bounded_artifact_archive(
                [b"blob"], parent / "results", policy, deadline=invalid
            )
    parent.chmod(0o755)
    with pytest.raises(module.P4AdapterError, match="private"):
        module.receive_bounded_artifact_archive(
            [b"blob"], parent / "results", policy, deadline=module.time.monotonic() + 20
        )
    assert list(parent.iterdir()) == []


class EffectiveConfigFake(FakeDocker):
    """Fake daemon returns inspect output; no Docker or candidate code executes."""

    def __init__(self, image: str, policy: dict, **overrides) -> None:
        super().__init__()
        self.image = image
        self.policy = policy
        self.overrides = overrides
        self.attested_calls = 0

    def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
        from p4_trusted_runtime_adapter import CommandResult

        args = list(argv)
        if args[1:5] == ["container", "inspect", "--format", "{{json .}}"]:
            self.commands.append(args)
            self.attested_calls += 1
            name = next(iter(self.names))
            limit = self.policy["limits"]["docker_runtime"]
            doc = {
                "Id": "a" * 64,
                "Name": "/" + name,
                "Config": {"Image": self.image, "Labels": {"mcpbg.p4.owner": "fixed"}},
                "State": {"Running": False, "Pid": 0},
                "Mounts": [],
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "Privileged": False,
                    "PublishAllPorts": False,
                    "Memory": limit["memory_bytes"],
                    "MemorySwap": limit["memory_bytes"],
                    "PidsLimit": limit["pids_limit"],
                    "NanoCpus": limit["nano_cpus"],
                    "CapDrop": ["ALL"],
                    "CapAdd": None,
                    "SecurityOpt": ["no-new-privileges:true"],
                    "Binds": None,
                    "Devices": None,
                    "PortBindings": None,
                    "Tmpfs": {
                        "/tmp": "rw,noexec,nosuid,size=16m",
                        "/trusted-output": "rw,noexec,nosuid,size=16777216",
                    },
                    "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "2"}},
                },
            }
            for key, value in self.overrides.items():
                section, field = key.split("__", 1)
                doc[section][field] = value
            raw = (json.dumps(doc, sort_keys=True) + "\n").encode()
            return CommandResult(0, raw, b"", len(raw))
        return super().__call__(
            argv,
            timeout=timeout,
            output_budget=output_budget,
            retained_per_stream=retained_per_stream,
        )


@pytest.mark.parametrize(
    "override",
    [
        {},
        {"HostConfig__Privileged": True},
        {"HostConfig__ReadonlyRootfs": False},
        {"HostConfig__NetworkMode": "bridge"},
        {"HostConfig__Memory": 1},
        {"HostConfig__MemorySwap": -1},
        {"HostConfig__NanoCpus": 0},
        {"HostConfig__PidsLimit": 0},
        {"HostConfig__CapDrop": []},
        {"HostConfig__SecurityOpt": []},
        {"HostConfig__PortBindings": {"8000/tcp": [{"HostPort": "8000"}]}},
        {"HostConfig__Binds": ["/var/run/docker.sock:/var/run/docker.sock"]},
        {"HostConfig__LogConfig": {"Type": "json-file", "Config": {}}},
        {"HostConfig__Tmpfs": {}},
        {"State__Running": True},
        {"Config__Image": "unapproved:latest"},
    ],
)
def test_prestart_daemon_configuration_is_fail_closed(tmp_path: Path, override: dict) -> None:
    module = _module()
    policy, authority = _inputs(module)
    image = json.loads(authority)["runtime"]["images"]["evaluator"]
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = EffectiveConfigFake(image, policy, **override)
    ledger = tmp_path / "owned-fixed.jsonl"
    with (
        pytest.raises(module.P4RecoveryRequired)
        if override
        else __import__("contextlib").nullcontext(),
        module.OwnedDockerAttempt(
            policy, "fixed", tmp_path / "scope.lock", ledger, run=fake
        ) as attempt,
    ):
        item = attempt.create_fixed_container(image, authority, role="evaluator")
        if override:
            with pytest.raises(module.P4RecoveryRequired, match="attestation UNKNOWN"):
                attempt.attest_fixed_container(item, authority, role="evaluator")
            assert attempt.recovery_required is True
        else:
            value = attempt.attest_fixed_container(item, authority, role="evaluator")
            assert value["status"] == "PRESTART_CONFIG_ATTESTED_SOURCE_ONLY"
            assert fake.attested_calls == 1
            assert "--memory-swap" in fake.commands[0]
            assert all("start" not in args for args in fake.commands)
    assert not fake.names


def test_prestart_rejects_foreign_owned_item_without_daemon_read(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = EffectiveConfigFake(image, policy)
    with module.OwnedDockerAttempt(
        policy, "fixed", tmp_path / "scope.lock", tmp_path / "owned-fixed.jsonl", run=fake
    ) as attempt:
        from p4_trusted_runtime_adapter import OwnedItem

        foreign = OwnedItem(kind="container", name="external", state="CREATED", object_id="a" * 64)
        before = len(fake.commands)
        with pytest.raises(module.P4AdapterError, match="owned created container required"):
            attempt.attest_fixed_container(foreign, authority, role="fixture")
        assert len(fake.commands) == before


def test_v9_archive_subprocess_consumes_real_pipes_and_checks_exit() -> None:
    module = _module()
    import time

    def collect(code: str, *, limit: int = 1024, duration: float = 2.0) -> bytes:
        return b"".join(
            module._bounded_archive_process(
                [sys.executable, "-c", code],
                deadline=float(time.monotonic() + duration),
                byte_limit=limit,
            )
        )

    assert collect("import os;os.write(1,b'archive')") == b"archive"
    with pytest.raises(module.P4AdapterError, match="bytes exceeded"):
        collect("import os;os.write(1,b'x'*4096)", limit=100)
    with pytest.raises(module.P4AdapterError, match="CLI failed"):
        collect("import os,sys;os.write(1,b'archive');sys.exit(4)")
    with pytest.raises(module.P4AdapterError, match="deadline"):
        collect("import time;time.sleep(3)", duration=0.2)
    with pytest.raises(module.P4AdapterError, match="stderr budget"):
        b"".join(
            module._bounded_archive_process(
                [sys.executable, "-c", "import os;os.write(2,b'e'*2048)"],
                deadline=float(time.monotonic() + 2),
                byte_limit=1024,
                stderr_limit=100,
            )
        )


def test_v9_export_cannot_run_without_owned_fenced_fixture(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    with (
        module.OwnedDockerAttempt(
            policy, "export", tmp_path / "global.lock", tmp_path / "owned-export.jsonl", run=fake
        ) as attempt,
        pytest.raises(module.P4AdapterError, match="prestart-attested"),
    ):
        from p4_trusted_runtime_adapter import OwnedItem

        other = OwnedItem(kind="container", name="foreign", state="CREATED", object_id="a" * 64)
        attempt.export_paused_fixed_artifacts(
            other, AUTHORITY.read_bytes(), role="fixture", destination=tmp_path / "published"
        )
    assert fake.commands == []


def test_v9_paused_export_malformed_daemon_state_fail_closed(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    output = tmp_path / "private"
    output.mkdir(mode=0o700)
    with (
        pytest.raises(module.P4RecoveryRequired, match="owned cleanup is UNKNOWN"),
        module.OwnedDockerAttempt(
            policy, "paused", tmp_path / "global.lock", tmp_path / "owned-paused.jsonl", run=fake
        ) as attempt,
    ):
        volume = attempt._reserve("volume")
        volume.state, volume.object_id = "CREATED", volume.name
        volume.artifact_tmpfs_attested, volume.artifact_owner_uid = True, 10003
        item = attempt._reserve("container")
        item.state, item.object_id = "CREATED", "a" * 64
        item.prestart_attested = item.mounted_attested = True
        item.planned_mounts = {"/trusted-output": volume.name}
        with pytest.raises(
            module.P4RecoveryRequired, match="archive export or publication UNKNOWN"
        ):
            attempt.export_paused_fixed_artifacts(
                item, authority, role="evaluator", destination=output / "published"
            )
    assert attempt.cleanup_result()["outcome"] == "UNKNOWN"
    assert not (output / "published").exists()
    assert not any(command[:3] == ["docker", "container", "cp"] for command in fake.commands)


def test_v9_unfinished_artifact_export_blocks_next_attempt(tmp_path: Path) -> None:
    module = _module()

    policy, _ = _inputs(module)
    lock = tmp_path / "global.lock"
    scope_info = _ledger_identity(lock)
    name = "mcpbg-p4-first-deadbeef-container-1"

    def row(event: str, resource: bool = False) -> str:
        value = {
            "event": event,
            "attempt": "first",
            "nonce": "deadbeef",
            "utc_epoch": 1,
            **scope_info,
        }
        if resource:
            known_id = (
                "a" * 64
                if event in {"CREATE_CONFIRMED", "ARTIFACT_EXPORT_BEGIN", "ABSENCE_VERIFIED"}
                else None
            )
            states = {
                "RESERVED": "INTENT",
                "CREATE_REQUESTED": "REQUESTED",
                "CREATE_CONFIRMED": "CREATED",
                "ARTIFACT_EXPORT_BEGIN": "CREATED",
                "ABSENCE_VERIFIED": "ABSENT",
            }
            value.update(kind="container", name=name, state=states[event], object_id=known_id)
        if event == "ARTIFACT_EXPORT_BEGIN":
            value["details"] = {
                "role": "evaluator",
                "volume": "mcpbg-p4-first-deadbeef-volume-1",
                "source": "/trusted-output",
                "destination": "/tmp/out",
            }
        return json.dumps(value, sort_keys=True) + "\n"

    (tmp_path / "owned-first.jsonl").write_text(
        row("ATTEMPT_OPEN")
        + row("RESERVED", True)
        + row("CREATE_REQUESTED", True)
        + row("CREATE_CONFIRMED", True)
        + row("ARTIFACT_EXPORT_BEGIN", True)
        + row("ABSENCE_VERIFIED", True)
        + row("FINISH_CLEAN"),
        encoding="utf-8",
    )
    (tmp_path / "owned-first.jsonl").chmod(0o600)
    with (
        pytest.raises(module.P4RecoveryRequired, match="prior export"),
        module.OwnedDockerAttempt(policy, "second", lock, tmp_path / "owned-second.jsonl"),
    ):
        pass
    assert not (tmp_path / "owned-second.jsonl").exists()


def test_v10_unsupported_tmpfs_docker_cp_is_fail_closed(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    image = json.loads(authority)["runtime"]["images"]["evaluator"]
    with module.OwnedDockerAttempt(
        policy, "legacy", tmp_path / "global.lock", tmp_path / "owned-legacy.jsonl", run=fake
    ) as attempt:
        item = attempt.create_fixed_container(image, authority, role="evaluator")
        item.prestart_attested = True
        with pytest.raises(module.P4AdapterError, match="verified mounted"):
            attempt.export_paused_fixed_artifacts(
                item, authority, role="evaluator", destination=tmp_path / "published"
            )
    assert not any(command[:3] == ["docker", "container", "cp"] for command in fake.commands)
    assert not (tmp_path / "published").exists()


@pytest.mark.parametrize("bad", ["driver", "options", "name", "owner", "malformed"])
def test_v10_artifact_volume_inspection_rejects_drift(tmp_path: Path, bad: str) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    from p4_trusted_runtime_adapter import CommandResult

    class VolumeFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "volume", "inspect"] and "{{json .}}" in args:
                self.commands.append(args)
                name = args[-1]
                options = (
                    f"size={policy['limits']['artifacts']['total_bytes']},uid=10001,"
                    "gid=10001,mode=0770,noexec,nosuid,nodev"
                )
                doc = {
                    "Name": name,
                    "Driver": "local",
                    "Options": {"type": "tmpfs", "device": "tmpfs", "o": options},
                    "Labels": {"mcpbg.p4.owner": "volume"},
                }
                if bad == "driver":
                    doc["Driver"] = "remote"
                if bad == "options":
                    doc["Options"]["o"] = "size=999999999"
                if bad == "name":
                    doc["Name"] = "other"
                if bad == "owner":
                    doc["Labels"]["mcpbg.p4.owner"] = "other"
                if bad == "malformed":
                    return CommandResult(0, b"not-json", b"", 8)
                raw = json.dumps(doc).encode()
                return module.CommandResult(0, raw, b"", len(raw))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = VolumeFake()
    with (
        pytest.raises(module.P4RecoveryRequired, match="owned cleanup is UNKNOWN"),
        module.OwnedDockerAttempt(
            policy, "volume", tmp_path / "global.lock", tmp_path / "owned-volume.jsonl", run=fake
        ) as attempt,
        pytest.raises(module.P4RecoveryRequired, match="volume verification UNKNOWN"),
    ):
        attempt.create_bounded_artifact_volume()
    assert attempt.recovery_required
    assert attempt.cleanup_result()["outcome"] == "UNKNOWN"


def test_v10_owned_volume_options_and_no_unbounded_storage(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    from p4_trusted_runtime_adapter import CommandResult

    class GoodVolumeFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "volume", "inspect"] and "{{json .}}" in args:
                self.commands.append(args)
                name = args[-1]
                options = (
                    f"size={policy['limits']['artifacts']['total_bytes']},uid=10001,"
                    "gid=10001,mode=0770,noexec,nosuid,nodev"
                )
                data = json.dumps(
                    {
                        "Name": name,
                        "Driver": "local",
                        "Options": {"type": "tmpfs", "device": "tmpfs", "o": options},
                        "Labels": {"mcpbg.p4.owner": "volume"},
                    }
                ).encode()
                return CommandResult(0, data, b"", len(data))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = GoodVolumeFake()
    with module.OwnedDockerAttempt(
        policy, "volume", tmp_path / "global.lock", tmp_path / "owned-volume.jsonl", run=fake
    ) as attempt:
        resource = attempt.create_bounded_artifact_volume()
        assert resource.artifact_tmpfs_attested is True
        created = next(c for c in fake.commands if c[:3] == ["docker", "volume", "create"])
        assert "--driver" in created and "local" in created
        assert "--opt" in created and "type=tmpfs" in created and "device=tmpfs" in created
        assert any(x.startswith("o=size=16777216,") for x in created)
    assert attempt.cleanup_result()["outcome"] == "CLEAN"
    assert not fake.names


@pytest.mark.parametrize("role,paths", [("fixture", {"/state"}), ("evaluator", set())])
def test_v11_declared_image_volumes_require_exact_owned_mounts(
    tmp_path: Path, role: str, paths: set[str]
) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    images = json.loads(authority)["runtime"]["images"]
    if role not in images:
        pytest.skip("synthetic authority lacks this fixed role")
    image = images[role]
    from p4_trusted_runtime_adapter import CommandResult

    class ImageFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "image", "inspect"]:
                self.commands.append(args)
                data = json.dumps(
                    {
                        "RepoDigests": [image],
                        "Config": {"Volumes": {key: {} for key in paths}},
                    }
                ).encode()
                return CommandResult(0, data, b"", len(data))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = ImageFake()
    with module.OwnedDockerAttempt(
        policy, "mountplan", tmp_path / "one.lock", tmp_path / "owned-mountplan.jsonl", run=fake
    ) as attempt:
        bindings = {}
        for destination in sorted(paths | ({"/trusted-output"} if role == "evaluator" else set())):
            item = attempt._reserve("volume")
            item.state = "CREATED"
            item.object_id = item.name
            item.artifact_tmpfs_attested = True
            item.artifact_owner_uid = 10001 if role == "fixture" else 10003
            bindings[destination] = item
        flags = attempt.plan_owned_image_mounts(image, authority, role=role, bindings=bindings)
        assert len(flags) == len(bindings) * 2
        assert "--mount" in flags
        assert all("volume-nocopy" in flag for flag in flags if flag != "--mount")
        assert not any(cmd[:2] == ["docker", "create"] for cmd in fake.commands)
        # This is a mock-only planner check. Reservation is not real Docker proof.
        for item in attempt.items:
            item.state = "INTENT"
    assert attempt.recovery_required is False


def test_v11_missing_fixture_state_binding_fails_before_docker_create(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    role = "fixture"
    image = json.loads(authority)["runtime"]["images"][role]

    class ImageFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "image", "inspect"]:
                self.commands.append(args)
                raw = json.dumps(
                    {"RepoDigests": [image], "Config": {"Volumes": {"/state": {}}}}
                ).encode()
                return module.CommandResult(0, raw, b"", len(raw))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = ImageFake()
    with module.OwnedDockerAttempt(
        policy, "mountdeny", tmp_path / "one.lock", tmp_path / "owned-mountdeny.jsonl", run=fake
    ) as attempt:
        with pytest.raises(module.P4AdapterError, match="explicitly owned"):
            attempt.plan_owned_image_mounts(image, authority, role=role, bindings={})
        assert not any(command[:2] == ["docker", "create"] for command in fake.commands)


@pytest.mark.parametrize("case", ["missing_digest", "extra_volume", "invalid_shape"])
def test_v11_image_declared_volume_inventory_fails_closed(tmp_path: Path, case: str) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    image = json.loads(authority)["runtime"]["images"]["fixture"]

    class ImageFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "image", "inspect"]:
                self.commands.append(args)
                doc = {"RepoDigests": [image], "Config": {"Volumes": {"/state": {}}}}
                if case == "missing_digest":
                    doc["RepoDigests"] = []
                if case == "extra_volume":
                    doc["Config"]["Volumes"]["/unowned"] = {}
                if case == "invalid_shape":
                    doc["Config"]["Volumes"] = ["/state"]
                raw = b"not-json" if case == "bad_bytes" else json.dumps(doc).encode()
                return module.CommandResult(0, raw, b"", len(raw))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = ImageFake()
    with module.OwnedDockerAttempt(
        policy, "mountbad", tmp_path / "one.lock", tmp_path / "owned-mountbad.jsonl", run=fake
    ) as attempt:
        with pytest.raises((module.P4AdapterError, module.P4RecoveryRequired)):
            attempt.plan_owned_image_mounts(image, authority, role="fixture", bindings={})
        assert not any(command[:2] == ["docker", "create"] for command in fake.commands)


def test_v12_mount_path_applies_attested_flags_before_create(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy, "v12mount", tmp_path / "global.lock", tmp_path / "owned-v12mount.jsonl", run=fake
    ) as attempt:
        mounts = {}
        for dest in ("/state",):
            volume = attempt._reserve("volume")
            volume.state = "CREATED"
            volume.object_id = volume.name
            volume.artifact_tmpfs_attested = True
            mounts[dest] = volume

        def verified_plan(img, auth, *, role, bindings):
            assert img == image and auth == authority and role == "fixture"
            assert bindings is mounts
            return [
                part
                for dest in sorted(bindings)
                for part in (
                    "--mount",
                    f"type=volume,src={bindings[dest].name},dst={dest},volume-nocopy",
                )
            ]

        attempt.plan_owned_image_mounts = verified_plan
        owned = attempt.create_mounted_fixed_container(
            image, authority, role="fixture", bindings=mounts
        )
        assert owned.state == "CREATED"
        assert owned.planned_mounts == {path: mounts[path].name for path in sorted(mounts)}
        command = next(cmd for cmd in fake.commands if cmd[:2] == ["docker", "create"])
        assert command.count("--mount") == 1
        assert "/trusted-output:" not in " ".join(command)
        assert all("volume-nocopy" in arg for arg in command if arg.startswith("type=volume"))
        assert "--read-only" in command and "--network" in command
        # FakeDocker cannot prove physical mounts. The source-only path is not runnable.
        assert owned.mounted_attested is False
        # Prevent fake volume cleanup from claiming a daemon result it never created.
        for volume in mounts.values():
            volume.state = "INTENT"
    assert attempt.recovery_required is False


def test_v12_mount_path_rejects_stale_volume_before_create(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy, "v12stale", tmp_path / "global.lock", tmp_path / "owned-v12stale.jsonl", run=fake
    ) as attempt:
        a = attempt._reserve("volume")
        a.state = "CREATED"
        a.object_id = a.name
        a.artifact_tmpfs_attested = True
        bindings = {"/state": a}

        def stale_plan(img, auth, *, role, bindings):
            a.artifact_tmpfs_attested = False
            return [
                "--mount",
                f"type=volume,src={a.name},dst=/state,volume-nocopy",
            ]

        attempt.plan_owned_image_mounts = stale_plan
        try:
            attempt.create_mounted_fixed_container(
                image, authority, role="fixture", bindings=bindings
            )
        except module.P4AdapterError as exc:
            assert "identity changed" in str(exc)
        else:
            pytest.fail("stale owned volume unexpectedly passed pre-create verification")
        assert not any(cmd[:2] == ["docker", "create"] for cmd in fake.commands)
        a.state = "INTENT"
    assert attempt.recovery_required is False


@pytest.mark.parametrize("swapped", [False, True])
def test_v12_mounted_effective_inspection_requires_exact_owned_volumes(
    tmp_path: Path, swapped: bool
) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    image = json.loads(authority)["runtime"]["images"]["fixture"]

    class MountedFake(EffectiveConfigFake):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            result = super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )
            if list(argv)[1:5] == ["container", "inspect", "--format", "{{json .}}"]:
                doc = json.loads(result.stdout)
                doc["HostConfig"]["Tmpfs"] = {"/tmp": "rw,noexec,nosuid,size=16m"}
                doc["Mounts"] = [
                    {
                        "Destination": dest,
                        "Name": name if not swapped or dest != "/state" else "unowned-volume",
                        "Type": "volume",
                        "RW": True,
                    }
                    for dest, name in sorted(self.planned.items())
                ]
                raw = json.dumps(doc).encode()
                return module.CommandResult(0, raw, b"", len(raw))
            return result

    fake = MountedFake(image, policy)
    fake.planned = {}
    with (
        pytest.raises(module.P4RecoveryRequired)
        if swapped
        else __import__("contextlib").nullcontext(),
        module.OwnedDockerAttempt(
            policy, "fixed", tmp_path / "global.lock", tmp_path / "owned-fixed.jsonl", run=fake
        ) as attempt,
    ):
        bindings = {}
        for dest in ("/state",):
            volume = attempt._reserve("volume")
            volume.state = "CREATED"
            volume.object_id = volume.name
            volume.artifact_tmpfs_attested = True
            bindings[dest] = volume
        fake.planned = {dest: volume.name for dest, volume in bindings.items()}
        attempt.plan_owned_image_mounts = lambda *_a, **_kw: [
            part
            for dest in sorted(bindings)
            for part in (
                "--mount",
                f"type=volume,src={bindings[dest].name},dst={dest},volume-nocopy",
            )
        ]
        item = attempt.create_mounted_fixed_container(
            image, authority, role="fixture", bindings=bindings
        )
        if swapped:
            with pytest.raises(module.P4RecoveryRequired, match="attestation UNKNOWN"):
                attempt.attest_fixed_container(item, authority, role="fixture")
            assert not item.mounted_attested
        else:
            assert (
                attempt.attest_fixed_container(item, authority, role="fixture")["container_id"]
                == item.object_id
            )
            assert item.mounted_attested
            for volume in bindings.values():
                volume.state = "INTENT"


def test_v12_legacy_create_does_not_confer_mounted_attestation() -> None:
    module = _module()
    item = module.OwnedItem(kind="container", name="not-runnable")
    assert item.planned_mounts is None
    assert item.mounted_attested is False


def test_v13_unknown_volume_role_fails_before_any_reservation(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy, "v13bad", tmp_path / "one.lock", tmp_path / "owned-v13bad.jsonl", run=fake
    ) as attempt:
        with pytest.raises(module.P4AdapterError, match="unapproved owned volume role"):
            attempt.create_bounded_artifact_volume(role="unknown")
        assert not attempt.items
        assert not fake.commands


@pytest.mark.parametrize("role,owner", [("fixture", 10001), ("evaluator", 10003)])
def test_v13_volume_creation_seals_uid_and_gid_for_pinned_role(
    tmp_path: Path, role: str, owner: int
) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module

    class VolumeFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "volume", "inspect"] and "{{json .}}" in args:
                self.commands.append(args)
                name = args[-1]
                options = (
                    f"size={policy['limits']['artifacts']['total_bytes']},uid={owner},"
                    f"gid={owner},mode=0770,noexec,nosuid,nodev"
                )
                raw = json.dumps(
                    {
                        "Name": name,
                        "Driver": "local",
                        "Options": {"type": "tmpfs", "device": "tmpfs", "o": options},
                        "Labels": {"mcpbg.p4.owner": "v13role"},
                    }
                ).encode()
                return module.CommandResult(0, raw, b"", len(raw))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = VolumeFake()
    with module.OwnedDockerAttempt(
        policy, "v13role", tmp_path / "one.lock", tmp_path / "owned-v13role.jsonl", run=fake
    ) as attempt:
        owned = attempt.create_bounded_artifact_volume(role=role)
        assert owned.artifact_owner_uid == owner
        assert owned.artifact_tmpfs_attested
        command = next(c for c in fake.commands if c[:3] == ["docker", "volume", "create"])
        assert f"uid={owner},gid={owner},mode=0770" in " ".join(command)
    assert attempt.cleanup_result()["outcome"] == "CLEAN"


def test_v13_fixture_volume_uid_mismatch_denies_mount_before_create(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy, "v13mount", tmp_path / "one.lock", tmp_path / "owned-v13mount.jsonl", run=fake
    ) as attempt:
        bindings = {}
        for dest in ("/state",):
            item = attempt._reserve("volume")
            item.state = "CREATED"
            item.object_id = item.name
            item.artifact_tmpfs_attested = True
            bindings[dest] = item
        bindings["/state"].artifact_owner_uid = 10003
        attempt.plan_owned_image_mounts = lambda *_a, **_kw: [
            part
            for dest in sorted(bindings)
            for part in (
                "--mount",
                f"type=volume,src={bindings[dest].name},dst={dest},volume-nocopy",
            )
        ]
        with pytest.raises(module.P4AdapterError, match="volume ownership mismatch"):
            attempt.create_mounted_fixed_container(
                image, authority, role="fixture", bindings=bindings
            )
        assert not any(cmd[:2] == ["docker", "create"] for cmd in fake.commands)
        for item in bindings.values():
            item.state = "INTENT"


def test_v13_role_volume_contract_does_not_enable_execution() -> None:
    module = _module()
    assert len(module.PROMOTED_AUTHORITY_SHA256) == 64
    item = module.OwnedItem(kind="volume", name="unsubmitted")
    assert item.artifact_tmpfs_attested is False
    assert item.artifact_owner_uid == 10001


def test_v14_owned_volume_create_requires_verified_absence(tmp_path: Path) -> None:
    module = _module()
    sys.modules["p4_trusted_runtime_adapter"] = module
    policy, _ = _inputs(module)
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy, "v14normal", tmp_path / "lock", tmp_path / "owned-v14normal.jsonl", run=fake
    ) as attempt:
        volume = attempt.create_volume()
        assert volume.object_id == volume.name
        commands = fake.commands
        preflight = next(
            i
            for i, command in enumerate(commands)
            if command[:3] == ["docker", "volume", "inspect"]
        )
        created = next(
            i for i, command in enumerate(commands) if command[:3] == ["docker", "volume", "create"]
        )
        assert preflight < created
        assert commands[preflight][-1] == volume.name
    assert attempt.cleanup_result()["outcome"] == "CLEAN"


@pytest.mark.parametrize("kind", ["generic", "artifact"])
def test_v14_preexisting_volume_never_adopted(tmp_path: Path, kind: str) -> None:
    module = _module()
    sys.modules["p4_trusted_runtime_adapter"] = module
    policy, _ = _inputs(module)
    from p4_trusted_runtime_adapter import CommandResult

    class Preexisting(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "volume", "inspect"] and "{{.Name}}" in args:
                self.commands.append(args)
                value = args[-1].encode()
                return CommandResult(0, value, b"", len(value))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = Preexisting()
    attempt = module.OwnedDockerAttempt(
        policy,
        "v14existing",
        tmp_path / "lock",
        tmp_path / "owned-v14existing.jsonl",
        run=fake,
    )
    with pytest.raises(module.P4RecoveryRequired), attempt:
        if kind == "generic":
            attempt.create_volume()
        else:
            attempt.create_bounded_artifact_volume(role="fixture")
    assert attempt.recovery_required
    assert not any(c[:3] == ["docker", "volume", "create"] for c in fake.commands)
    assert attempt.cleanup_result()["outcome"] == "UNKNOWN"


@pytest.mark.parametrize(
    "exit_code,stderr",
    [(1, b"unexpected daemon error"), (0, b"No such volume"), (2, b"No such volume")],
)
def test_v14_ambiguous_volume_absence_fails_closed(
    tmp_path: Path, exit_code: int, stderr: bytes
) -> None:
    module = _module()
    sys.modules["p4_trusted_runtime_adapter"] = module
    policy, _ = _inputs(module)
    from p4_trusted_runtime_adapter import CommandResult

    class Ambiguous(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "volume", "inspect"] and "{{.Name}}" in args:
                self.commands.append(args)
                return CommandResult(exit_code, b"", stderr, len(stderr))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = Ambiguous()
    attempt = module.OwnedDockerAttempt(
        policy,
        "v14ambiguous",
        tmp_path / "lock",
        tmp_path / "owned-v14ambiguous.jsonl",
        run=fake,
    )
    with pytest.raises(module.P4RecoveryRequired), attempt:
        attempt.create_bounded_artifact_volume(role="fixture")
    assert not any(c[:3] == ["docker", "volume", "create"] for c in fake.commands)
    assert attempt.cleanup_result()["outcome"] == "UNKNOWN"


def test_v14_generic_volume_create_must_echo_exact_reserved_name(tmp_path: Path) -> None:
    module = _module()
    sys.modules["p4_trusted_runtime_adapter"] = module
    policy, _ = _inputs(module)
    from p4_trusted_runtime_adapter import CommandResult

    class BadReply(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "volume", "create"]:
                super().__call__(
                    argv,
                    timeout=timeout,
                    output_budget=output_budget,
                    retained_per_stream=retained_per_stream,
                )
                return CommandResult(0, b"different-volume", b"", len(b"different-volume"))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = BadReply()
    attempt = module.OwnedDockerAttempt(
        policy, "v14reply", tmp_path / "lock", tmp_path / "owned-v14reply.jsonl", run=fake
    )
    with pytest.raises(module.P4RecoveryRequired), attempt:
        attempt.create_volume()
    assert attempt.recovery_required
    assert attempt.cleanup_result()["outcome"] == "UNKNOWN"


def test_v15_legacy_fixture_create_rejects_implicit_anonymous_state_volume(
    tmp_path: Path,
) -> None:
    module = _module()
    sys.modules["p4_trusted_runtime_adapter"] = module
    policy, authority = _inputs(module)
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy,
        "v15legacy",
        tmp_path / "global.lock",
        tmp_path / "owned-v15legacy.jsonl",
        run=fake,
    ) as attempt:
        before = len(fake.commands)
        with pytest.raises(module.P4AdapterError, match="owned mount plan required"):
            attempt.create_fixed_container(image, authority, role="fixture")
        assert len(fake.commands) == before
        assert attempt.items == []
    assert attempt.cleanup_result()["outcome"] == "NO_DOCKER_OPERATION"


@pytest.mark.parametrize(
    "role,expected_paths",
    [
        ("fixture", {"/state"}),
        ("evaluator", {"/trusted-output"}),
    ],
)
def test_v17_required_mounts_are_role_specific_and_within_two_volume_limit(
    tmp_path: Path, role: str, expected_paths: set[str]
) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    images = json.loads(authority)["runtime"]["images"]
    if role not in images:
        pytest.skip("synthetic authority lacks this fixed role")
    image = images[role]

    class ImageFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "image", "inspect"]:
                self.commands.append(args)
                declared = {"/state": {}} if role == "fixture" else {}
                raw = json.dumps({"RepoDigests": [image], "Config": {"Volumes": declared}}).encode()
                return module.CommandResult(0, raw, b"", len(raw))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = ImageFake()
    with module.OwnedDockerAttempt(
        policy,
        "v17roles",
        tmp_path / "shared.lock",
        tmp_path / "owned-v17roles.jsonl",
        run=fake,
    ) as attempt:
        item = attempt._reserve("volume")
        item.state = "CREATED"
        item.object_id = item.name
        item.artifact_tmpfs_attested = True
        item.artifact_owner_uid = 10001 if role == "fixture" else 10003
        bindings = {next(iter(expected_paths)): item}
        flags = attempt.plan_owned_image_mounts(image, authority, role=role, bindings=bindings)
        assert flags == [
            "--mount",
            f"type=volume,src={item.name},dst={next(iter(expected_paths))},volume-nocopy",
        ]
        assert not any(cmd[:2] == ["docker", "create"] for cmd in fake.commands)
        item.state = "INTENT"
    assert attempt.cleanup_result()["outcome"] == "CLEAN"


def test_v17_extra_fixture_output_mount_is_rejected_before_container_creation(
    tmp_path: Path,
) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    image = json.loads(authority)["runtime"]["images"]["fixture"]

    class ImageFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            args = list(argv)
            if args[:3] == ["docker", "image", "inspect"]:
                self.commands.append(args)
                raw = json.dumps(
                    {"RepoDigests": [image], "Config": {"Volumes": {"/state": {}}}}
                ).encode()
                return module.CommandResult(0, raw, b"", len(raw))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = ImageFake()
    with module.OwnedDockerAttempt(
        policy,
        "v17extra",
        tmp_path / "shared.lock",
        tmp_path / "owned-v17extra.jsonl",
        run=fake,
    ) as attempt:
        state = attempt._reserve("volume")
        output = attempt._reserve("volume")
        for item in (state, output):
            item.state = "CREATED"
            item.object_id = item.name
            item.artifact_tmpfs_attested = True
            item.artifact_owner_uid = 10001
        with pytest.raises(module.P4AdapterError, match="every image volume"):
            attempt.plan_owned_image_mounts(
                image,
                authority,
                role="fixture",
                bindings={"/state": state, "/trusted-output": output},
            )
        assert not any(cmd[:2] == ["docker", "create"] for cmd in fake.commands)
        state.state = "INTENT"
        output.state = "INTENT"
    assert attempt.cleanup_result()["outcome"] == "CLEAN"


def test_v17_fixture_plus_evaluator_budget_is_exactly_two(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    fake = FakeDocker()
    with module.OwnedDockerAttempt(
        policy,
        "v17budget",
        tmp_path / "shared.lock",
        tmp_path / "owned-v17budget.jsonl",
        run=fake,
    ) as attempt:
        state = attempt._reserve("volume")
        output = attempt._reserve("volume")
        assert state.name != output.name
        with pytest.raises(module.P4AdapterError, match="resource slot budget"):
            attempt._reserve("volume")
        assert len(attempt.items) == 2
        assert not fake.commands
    assert attempt.cleanup_result()["outcome"] == "CLEAN"


@pytest.mark.parametrize(
    "alias", ["symlink-parent", "relative-parent", "symlink-lock", "hardlink-lock"]
)
def test_r27_alias_paths_cannot_partition_recovery(tmp_path: Path, alias: str) -> None:
    module = _module()
    policy, _ = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    lock = tmp_path / "shared.lock"
    with module.OwnedDockerAttempt(
        policy, "before", lock, tmp_path / "owned-before.jsonl", run=FakeDocker()
    ):
        pass
    # Preserve an unresolved prior ledger for the same physical state directory.
    events = (tmp_path / "owned-before.jsonl").read_text().splitlines()
    events[-1] = events[-1].replace("FINISH_CLEAN", "FINISH_UNKNOWN")
    (tmp_path / "owned-before.jsonl").write_text("\n".join(events) + "\n")
    if alias == "symlink-parent":
        indirect = tmp_path.parent / (tmp_path.name + "-alias")
        indirect.symlink_to(tmp_path, target_is_directory=True)
        new_lock, new_ledger = indirect / "shared.lock", indirect / "owned-after.jsonl"
    elif alias == "relative-parent":
        new_lock, new_ledger = (
            tmp_path / "sub" / ".." / "shared.lock",
            tmp_path / "sub" / ".." / "owned-after.jsonl",
        )
        (tmp_path / "sub").mkdir()
    elif alias == "symlink-lock":
        new_lock = tmp_path / "other.lock"
        new_lock.symlink_to(lock)
        new_ledger = tmp_path / "owned-after.jsonl"
    else:
        new_lock = tmp_path / "other.lock"
        os.link(lock, new_lock)
        new_ledger = tmp_path / "owned-after.jsonl"
    with (
        pytest.raises((module.P4AdapterError, module.P4RecoveryRequired, OSError)),
        module.OwnedDockerAttempt(policy, "after", new_lock, new_ledger, run=FakeDocker()),
    ):
        pass
    assert not (tmp_path / "owned-after.jsonl").exists()


def test_r27_replaced_lock_inode_and_changed_daemon_reject(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    fake = FakeDocker()
    lock = tmp_path / "shared.lock"
    with module.OwnedDockerAttempt(
        policy,
        "first",
        lock,
        tmp_path / "owned-first.jsonl",
        run=fake,
        daemon_context="desktop-linux",
        daemon_identity="engine-a",
    ):
        pass
    with (
        pytest.raises(module.P4RecoveryRequired, match="scope/daemon mismatch"),
        module.OwnedDockerAttempt(
            policy,
            "second",
            lock,
            tmp_path / "owned-second.jsonl",
            run=fake,
            daemon_context="desktop-linux",
            daemon_identity="engine-b",
        ),
    ):
        pass
    assert not (tmp_path / "owned-second.jsonl").exists()
    lock.rename(tmp_path / "retired.lock")
    lock.touch(mode=0o600)
    with (
        pytest.raises(module.P4RecoveryRequired, match="scope/daemon mismatch"),
        module.OwnedDockerAttempt(
            policy,
            "third",
            lock,
            tmp_path / "owned-third.jsonl",
            run=fake,
            daemon_context="desktop-linux",
            daemon_identity="engine-a",
        ),
    ):
        pass


@pytest.mark.parametrize("kind", ["container", "network", "volume"])
def test_r27_clean_ledger_must_prove_same_resource_id(tmp_path: Path, kind: str) -> None:
    module = _module()
    policy, _ = _inputs(module)
    fake = FakeDocker()
    sys.modules["p4_trusted_runtime_adapter"] = module
    lock, ledger = tmp_path / "shared.lock", tmp_path / "owned-first.jsonl"
    with module.OwnedDockerAttempt(policy, "first", lock, ledger, run=fake) as attempt:
        if kind == "container":
            authority = AUTHORITY.read_bytes()
            image = json.loads(authority)["runtime"]["images"]["evaluator"]
            attempt.create_fixed_container(image, authority, role="evaluator")
        elif kind == "network":
            attempt.create_network()
        else:
            attempt.create_volume()
    events = [json.loads(line) for line in ledger.read_text().splitlines()]
    index = next(i for i, row in enumerate(events) if row["event"] == "ABSENCE_VERIFIED")
    events[index]["object_id"] = "f" * 64 if kind != "volume" else "different-owned-volume"
    ledger.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in events))
    with (
        pytest.raises(module.P4RecoveryRequired, match="transition or ID"),
        module.OwnedDockerAttempt(
            policy, "second", lock, tmp_path / "owned-second.jsonl", run=fake
        ),
    ):
        pass
    assert not (tmp_path / "owned-second.jsonl").exists()


def test_r27_cleanup_lifecycle_distinguishes_open_and_noop(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    attempt = module.OwnedDockerAttempt(
        policy, "noop", tmp_path / "shared.lock", tmp_path / "owned-noop.jsonl", run=FakeDocker()
    )
    assert attempt.cleanup_result() == {"outcome": "NOT_STARTED", "recovery_required": False}
    with attempt:
        assert attempt.cleanup_result() == {"outcome": "OPEN", "recovery_required": False}
    assert attempt.cleanup_result() == {
        "outcome": "NO_DOCKER_OPERATION",
        "recovery_required": False,
    }
    assert [
        json.loads(line)["event"]
        for line in (tmp_path / "owned-noop.jsonl").read_text().splitlines()
    ] == ["ATTEMPT_OPEN", "FINISH_CLEAN"]


def test_r27_failed_final_ledger_fsync_does_not_claim_clean(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    attempt = module.OwnedDockerAttempt(
        policy,
        "failedfinish",
        tmp_path / "shared.lock",
        tmp_path / "owned-failed.jsonl",
        run=FakeDocker(),
    )
    original = attempt._record

    def reject_final(event, item=None):
        if event == "FINISH_CLEAN":
            attempt.recovery_required = True
            raise module.P4RecoveryRequired("synthetic final fsync failure")
        return original(event, item)

    attempt._record = reject_final
    with pytest.raises(module.P4RecoveryRequired, match="synthetic final fsync"), attempt:
        pass
    assert attempt.cleanup_result() == {"outcome": "UNKNOWN", "recovery_required": True}
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy,
            "next",
            tmp_path / "shared.lock",
            tmp_path / "owned-next.jsonl",
            run=FakeDocker(),
        ),
    ):
        pass


@pytest.mark.parametrize(
    "role,path,uid", [("fixture", "/state", 10001), ("evaluator", "/trusted-output", 10003)]
)
def test_r27_engine_archive_source_binding_and_real_pipe(
    tmp_path: Path, monkeypatch, role: str, path: str, uid: int
) -> None:
    import io
    import tarfile

    module = _module()
    policy, authority = _inputs(module)
    image = json.loads(authority)["runtime"]["images"][role]
    output_root = tmp_path / "result"
    output_root.mkdir(mode=0o700)
    commands = []

    class InspectFake(FakeDocker):
        def __call__(self, argv, *, timeout, output_budget, retained_per_stream):
            cmd = list(argv)
            if cmd[:3] == ["docker", "container", "inspect"] and "{{json .}}" in cmd:
                commands.append(cmd)
                data = {
                    "Id": "a" * 64,
                    "Name": "/" + item.name,
                    "Config": {"Image": image, "Labels": {"mcpbg.p4.owner": "engine"}},
                    "State": {"Running": True, "Paused": True},
                    "Mounts": [
                        {"Type": "volume", "Destination": path, "Name": volume.name, "RW": True}
                    ],
                }
                raw = json.dumps(data).encode()
                return module.CommandResult(0, raw, b"", len(raw))
            return super().__call__(
                argv,
                timeout=timeout,
                output_budget=output_budget,
                retained_per_stream=retained_per_stream,
            )

    fake = InspectFake()
    sys.modules["p4_trusted_runtime_adapter"] = module
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode="w") as f:
        entry = tarfile.TarInfo("receipt.txt")
        entry.size = 8
        f.addfile(entry, io.BytesIO(b"accepted"))
    data = tar_data.getvalue()
    run_data = tmp_path / "bounded.tar"
    run_data.write_bytes(data)

    def actual_archive(argv, *, deadline, byte_limit, stderr_limit=131072):
        assert argv == ["docker", "container", "cp", "a" * 64 + ":" + path, "-"]
        yield from module._original_archive_process(
            [
                sys.executable,
                "-c",
                "import sys;sys.stdout.buffer.write(open(sys.argv[1], 'rb').read())",
                str(run_data),
            ],
            deadline=deadline,
            byte_limit=byte_limit,
            stderr_limit=stderr_limit,
        )

    module._original_archive_process = module._bounded_archive_process
    monkeypatch.setattr(module, "_bounded_archive_process", actual_archive)
    with module.OwnedDockerAttempt(
        policy, "engine", tmp_path / "shared.lock", tmp_path / "owned-engine.jsonl", run=fake
    ) as attempt:
        volume = attempt._reserve("volume")
        volume.state = "REQUESTED"
        attempt._record("CREATE_REQUESTED", volume)
        volume.object_id, volume.state = volume.name, "CREATED"
        volume.artifact_tmpfs_attested, volume.artifact_owner_uid = True, uid
        attempt._record("CREATE_CONFIRMED", volume)
        item = attempt._reserve("container")
        item.state = "REQUESTED"
        attempt._record("CREATE_REQUESTED", item)
        item.object_id, item.state = "a" * 64, "CREATED"
        item.prestart_attested = item.mounted_attested = True
        item.planned_mounts = {path: volume.name}
        attempt._record("CREATE_CONFIRMED", item)
        evidence = attempt.export_paused_fixed_artifacts(
            item, authority, role=role, destination=output_root / "published"
        )
        assert evidence["archive_bytes"] == len(data)
    assert (output_root / "published" / "receipt.txt").read_bytes() == b"accepted"
    assert attempt.cleanup_result() == {"outcome": "CLEAN", "recovery_required": False}
    events = [
        json.loads(line) for line in (tmp_path / "owned-engine.jsonl").read_text().splitlines()
    ]
    assert any(row["event"] == "ARTIFACT_EXPORT_BEGIN" for row in events)
    assert any(row["event"] == "ARTIFACT_EXPORT_COMPLETE" for row in events)
    with module.OwnedDockerAttempt(
        policy, "next", tmp_path / "shared.lock", tmp_path / "owned-next.jsonl", run=FakeDocker()
    ) as closed:
        assert closed.cleanup_result()["outcome"] == "OPEN"


def test_r27_archive_outer_deadline_is_forwarded_to_extractor(tmp_path: Path, monkeypatch) -> None:
    module = _module()
    policy, _ = _inputs(module)
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    received = []

    def nested(_source, _destination, _policy, *, deadline):
        received.append(deadline)
        raise module.bounds.P4ResourceEnforcementError("synthetic nested expiry")

    monkeypatch.setattr(module.bounds, "safe_extract_archive", nested)
    target_deadline = module.time.monotonic() + 1.0
    with pytest.raises(module.P4AdapterError, match="artifact archive intake invalid"):
        module.receive_bounded_artifact_archive(
            [b"archive"], parent / "published", policy, deadline=target_deadline
        )
    assert received == [target_deadline]
    assert not (parent / "published").exists()


def _synthetic_two_export_ledger(module, policy, tmp_path: Path) -> tuple[Path, Path, list[dict]]:
    """Durable replay fixture only. No Docker operation or approval evidence."""
    lock = tmp_path / "shared.lock"
    ledger = tmp_path / "owned-first.jsonl"
    with module.OwnedDockerAttempt(
        policy,
        "first",
        lock,
        ledger,
        run=FakeDocker(),
    ):
        pass
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    base = rows[0]

    def event(kind: str, name: str, action: str, state: str, identity, details=None):
        row = {
            **base,
            "event": action,
            "kind": kind,
            "name": name,
            "state": state,
            "object_id": identity,
        }
        if details is not None:
            row["details"] = details
        return row

    volumes = [f"mcpbg-p4-first-abcdef0123-volume-{n}" for n in (1, 2)]
    containers = [f"mcpbg-p4-first-abcdef0123-container-{n}" for n in (1, 2)]
    identities = ["a" * 64, "b" * 64]
    actions = []
    for kind, names, ids in (("volume", volumes, volumes), ("container", containers, identities)):
        for name, identity in zip(names, ids, strict=True):
            actions += [
                event(kind, name, "RESERVED", "INTENT", None),
                event(kind, name, "CREATE_REQUESTED", "REQUESTED", None),
                event(kind, name, "CREATE_CONFIRMED", "CREATED", identity),
            ]
    for role, volume, container, identity, source in zip(
        ("fixture", "evaluator"),
        volumes,
        containers,
        identities,
        ("/state", "/trusted-output"),
        strict=True,
    ):
        destination = f"/private/evidence/{role}"
        actions.append(
            event(
                "container",
                container,
                "ARTIFACT_EXPORT_BEGIN",
                "CREATED",
                identity,
                {"role": role, "volume": volume, "source": source, "destination": destination},
            )
        )
        actions.append(
            event(
                "container",
                container,
                "ARTIFACT_EXPORT_COMPLETE",
                "CREATED",
                identity,
                {"destination": destination, "archive_sha256": "d" * 64, "archive_bytes": 1024},
            )
        )
    for kind, names, ids in (("container", containers, identities), ("volume", volumes, volumes)):
        for name, identity in zip(names, ids, strict=True):
            actions.append(event(kind, name, "ABSENCE_VERIFIED", "ABSENT", identity))
    return lock, ledger, [rows[0], *actions, rows[-1]]


def test_two_distinct_role_exports_can_replay_as_clean(tmp_path: Path) -> None:
    module = _module()
    policy, _ = _inputs(module)
    lock, ledger, rows = _synthetic_two_export_ledger(module, policy, tmp_path)
    ledger.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    with module.OwnedDockerAttempt(
        policy,
        "second",
        lock,
        tmp_path / "owned-second.jsonl",
        run=FakeDocker(),
    ):
        pass


@pytest.mark.parametrize(
    "tamper", ["destination", "source", "volume", "duplicate", "id", "unfinished"]
)
def test_prior_exports_require_exact_role_volume_and_destination(
    tmp_path: Path, tamper: str
) -> None:
    module = _module()
    policy, _ = _inputs(module)
    lock, ledger, rows = _synthetic_two_export_ledger(module, policy, tmp_path)
    first = next(i for i, row in enumerate(rows) if row["event"] == "ARTIFACT_EXPORT_BEGIN")
    complete = first + 1
    if tamper == "destination":
        rows[complete]["details"]["destination"] = "/private/evidence/other"
    elif tamper == "source":
        rows[first]["details"]["source"] = "/trusted-output"
    elif tamper == "volume":
        rows[first]["details"]["volume"] = "mcpbg-p4-first-abcdef0123-volume-other"
    elif tamper == "duplicate":
        rows.insert(complete + 1, dict(rows[first]))
    elif tamper == "id":
        rows[complete]["object_id"] = "f" * 64
    else:
        rows.pop(complete)
    ledger.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy,
            "second",
            lock,
            tmp_path / "owned-second.jsonl",
            run=FakeDocker(),
        ),
    ):
        pass
    assert not (tmp_path / "owned-second.jsonl").exists()
