from __future__ import annotations

import ast
from pathlib import Path

import yaml

from mcp_behaviour_guard.config import load_contract
from mcp_behaviour_guard.models import SideEffectKind

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VERTICAL = PROJECT_ROOT / "assurance/phase2/vertical"
CONTRACT = VERTICAL / "contract.yaml"
SERVER = VERTICAL / "candidate_server.py"
DOCKERFILE = VERTICAL / "Dockerfile"
RUNNER = PROJECT_ROOT / "assurance/phase2/run_vertical_demo.py"


def test_contract_freezes_one_narrow_database_write_claim(monkeypatch) -> None:
    monkeypatch.setenv("PHASE2_CANDIDATE_HOST", "candidate")
    monkeypatch.setenv("PHASE2_CONTROL_HOST", "control")
    contract = load_contract(CONTRACT)

    assert set(contract.tools) == {"lookup_record"}
    assert set(contract.identities) == {"reviewer", "anonymous"}
    tool = contract.tools["lookup_record"]
    assert tool.permitted_identities == ["reviewer"]
    assert tool.probe_arguments == {"record_id": "synthetic-record-001"}
    assert tool.denial_error_markers == ["GUARD_DEMO_DENIED"]
    assert tool.side_effect_identity == "reviewer"
    assert tool.read_only is False
    assert tool.forbidden_side_effects == [SideEffectKind.DATABASE_WRITE]

    assert set(contract.observers) == {"trusted_database_audit"}
    observer = contract.observers["trusted_database_audit"]
    assert observer.type == "http_audit"
    assert observer.correlation == "none"
    assert observer.observes == [SideEffectKind.DATABASE_WRITE]

    assert contract.safety.destructive_tests is True
    assert contract.safety.require_lab_mode is True
    assert contract.session_tests == []
    assert contract.temporal_integrity.enabled is False


def test_contract_has_no_hidden_extra_policy_surface() -> None:
    raw = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    assert set(raw["tools"]) == {"lookup_record"}
    assert "replay_probe" not in raw["tools"]["lookup_record"]
    assert "tenant_probes" not in raw["tools"]["lookup_record"]
    assert "policy_probes" not in raw["tools"]["lookup_record"]
    assert "session_tests" not in raw
    assert "temporal_integrity" not in raw


def test_candidate_build_is_local_and_has_no_dependency_acquisition() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "ARG BASE_IMAGE" in dockerfile
    assert "ARG BASE_IMAGE=" not in dockerfile
    assert "COPY candidate_server.py" in dockerfile
    assert "pip install" not in dockerfile
    assert "apt-get" not in dockerfile
    assert "curl " not in dockerfile
    assert "git clone" not in dockerfile
    assert "USER candidate" in dockerfile


def test_candidate_modes_preserve_base_modes_and_denial_is_explicit() -> None:
    source = SERVER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for mode in ("good", "write"):
        assert f'"{mode}"' in source
    assert "GUARD_DEMO_DENIED" in source
    assert "PHASE2_ATTEMPT_TOKEN" in source
    assert "/records/write" in source
    assert "synthetic-forbidden-write" in source
    assert "subprocess" not in source
    assert "/var/run/docker.sock" not in source
    assert any(
        isinstance(node, ast.AsyncFunctionDef) and node.name == "lookup_record"
        for node in ast.walk(tree)
    )


def test_vertical_runner_keeps_gate_reference_and_ci_out_of_scope() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert 'CASES = ("good", "write", "missing_evidence")' in source
    for required in (
        "/close",
        "/final-snapshot",
        "/finalize",
        '"network", "disconnect"',
        '"network", "connect"',
        '"mcp-guard"',
        '"run"',
        '"--lab-mode"',
        '"docker", "cp"',
        '"container", "inspect"',
        '"network", "inspect"',
        '"volume", "inspect"',
    ):
        assert required in source
    for forbidden in (
        "compare_saved_runs",
        "baseline compare-saved",
        "approval_bundle",
        "policy_profile_digest",
        "pull_request_target",
        "gh api",
        "git push",
    ):
        assert forbidden not in source
    functions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"_run_case", "_validate_case", "_control", "_find_run_dir"} <= functions
