from __future__ import annotations

import ast
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE = PROJECT_ROOT / "assurance/phase2/gate"
RUNNER = PROJECT_ROOT / "assurance/phase2/run_approval_demo.py"


def test_expected_check_matrix_is_exact_and_external_to_reports() -> None:
    payload = json.loads((GATE / "expected-checks.json").read_text(encoding="utf-8"))
    assert set(payload["required_findings"]) == {
        "INVENTORY-001",
        "AUTH-LOOKUP-RECORD-REVIEWER",
        "AUTH-LOOKUP-RECORD-ANONYMOUS",
        "BEHAVIOUR-LOOKUP-RECORD",
    }
    assert payload["conditional_suffixes"] == ["-EFFECTS"]
    assert payload["unknown_finding_policy"] == "review"


def test_gate_rules_freeze_precedence_and_comparator_boundary() -> None:
    payload = json.loads((GATE / "gate-rules.json").read_text(encoding="utf-8"))
    assert payload["outcomes"] == ["PASS", "BLOCK", "REVIEW", "INVALID"]
    assert payload["precedence"][0] == "invalid_authority_or_subject_binding"
    assert payload["precedence"][1] == "authentic_confirmed_violation"
    assert payload["rejected_attempt_without_committed_violation"] == "REVIEW"
    assert payload["comparator_exit_code_is_not_gate_verdict"] is True


def test_gate_image_has_no_dependency_or_network_acquisition() -> None:
    dockerfile = (GATE / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG BASE_IMAGE" in dockerfile
    assert "ARG BASE_IMAGE=" not in dockerfile
    assert "pip install" not in dockerfile
    assert "apt-get" not in dockerfile
    assert "curl " not in dockerfile
    assert "git clone" not in dockerfile
    assert "USER evaluator" in dockerfile


def test_gate_uses_structured_comparator_and_atomic_publication() -> None:
    source = (GATE / "gate.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert "compare_saved_runs" in source
    assert "manifest_self_hash" in source
    assert "selected_approval_digest" in source
    assert "candidate attempt reuses the approved reference attempt" in source
    assert "comparator_exit" not in source
    functions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert {"_promote", "_evaluate", "_publish", "_matrix", "_validate_snapshot"} <= functions
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.func.attr == "rename"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "staging"
        and isinstance(node.args[1], ast.Name)
        and node.args[1].id == "final_dir"
        for node in ast.walk(tree)
    )


def test_approval_runner_uses_stable_logical_aliases() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "_run":
            continue
        for index, arg in enumerate(node.args[:-1]):
            if isinstance(arg, ast.Constant) and arg.value == "--network-alias":
                next_arg = node.args[index + 1]
                if isinstance(next_arg, ast.Constant) and isinstance(next_arg.value, str):
                    aliases.add(next_arg.value)
    assert {"candidate", "fixture-app", "fixture-control"} <= aliases
    assert "PHASE2_CANDIDATE_HOST=candidate" in source
    assert "PHASE2_CONTROL_HOST=fixture-control" in source
    assert "PHASE2_FIXTURE_APP=http://fixture-app:8001" in source


def test_approval_runner_separates_reference_candidate_and_tamper_cases() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert 'label="reference"' in source
    assert '"candidate-good": "PASS"' in source
    assert '"candidate-write": "BLOCK"' in source
    assert '"candidate-review": "REVIEW"' in source
    assert '"candidate-missing": "INVALID"' in source
    for name in ("tampered-context", "swapped-run", "stale-attempt", "tampered-approval"):
        assert name in source
    assert "git push" not in source
    assert "gh api" not in source
    assert "pull_request_target" not in source
