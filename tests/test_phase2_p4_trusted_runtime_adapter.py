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
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    lock = tmp_path / "same-global.lock"
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy, "first", lock, tmp_path / "owned-first.jsonl", run=fake
        ) as attempt,
        pytest.raises(module.P4AdapterError),
    ):
        attempt.create_fixed_container(image, authority, role="fixture")
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
    scope = __import__("hashlib").sha256(str(lock.absolute()).encode()).hexdigest()

    def row(event, **fields):
        return (
            json.dumps(
                dict(
                    event=event,
                    attempt="first",
                    nonce="deadbeef",
                    lease_scope_sha256=scope,
                    utc_epoch=1,
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
    scope = __import__("hashlib").sha256(str(lock.absolute()).encode()).hexdigest()
    name = "mcpbg-p4-first-deadbeef-container-1"

    def row(event: str, kind: str | None = None) -> str:
        value = dict(
            event=event, attempt="first", nonce="deadbeef", lease_scope_sha256=scope, utc_epoch=1
        )
        if kind is not None:
            value.update(kind=kind, name=name, state="CREATED", object_id=None)
        return json.dumps(value, sort_keys=True) + "\n"

    (tmp_path / "owned-first.jsonl").write_text(
        row("ATTEMPT_OPEN")
        + row("RESERVED", "container")
        + row("CREATE_REQUESTED", "container")
        + row("ABSENCE_VERIFIED", "network")
        + row("FINISH_CLEAN"),
        encoding="utf-8",
    )
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
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    with (
        pytest.raises(module.P4RecoveryRequired),
        module.OwnedDockerAttempt(
            policy, "swapped", tmp_path / "shared.lock", tmp_path / "owned-swapped.jsonl", run=fake
        ) as attempt,
    ):
        item = attempt.create_fixed_container(image, authority, role="fixture")
        fake.ids[item.name] = "c" * 64  # same resource name and owner, different object
    assert attempt.cleanup_result() == {"outcome": "UNKNOWN", "recovery_required": True}
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in fake.commands)
    assert fake.names


def test_cleanup_uses_original_id_not_mutable_name(tmp_path: Path) -> None:
    module = _module()
    policy, authority = _inputs(module)
    sys.modules["p4_trusted_runtime_adapter"] = module
    fake = FakeDocker()
    image = json.loads(authority)["runtime"]["images"]["fixture"]
    with module.OwnedDockerAttempt(
        policy, "stable", tmp_path / "shared.lock", tmp_path / "owned-stable.jsonl", run=fake
    ) as attempt:
        item = attempt.create_fixed_container(image, authority, role="fixture")
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
