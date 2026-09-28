from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_behaviour_guard.baseline import SavedRunComparisonError, compare_saved_runs
from mcp_behaviour_guard.cli import app
from mcp_behaviour_guard.models import (
    Contract,
    Finding,
    FindingStatus,
    RunSummary,
    Severity,
)
from mcp_behaviour_guard.receipts import write_run_receipt
from mcp_behaviour_guard.reporting import write_reports


def _contract(
    *,
    location: str = "tool_probe",
    semantic_key: str = "limit",
    semantic_value: Any = 10,
    known_secret: str = "known-secret",
) -> Contract:
    argument = {semantic_key: semantic_value}
    tool: dict[str, Any] = {
        "permitted_identities": ["reviewer"],
        "read_only": True,
    }
    payload: dict[str, Any] = {
        "version": 1,
        "server": {
            "name": "synthetic",
            "url": "http://127.0.0.1:8000/mcp",
        },
        "identities": {
            "reviewer": {
                "headers": {"Authorization": f"Bearer {known_secret}"},
                "role": "reviewer",
            }
        },
        "tools": {"lookup": tool},
    }

    if location == "tool_probe":
        tool["probe_arguments"] = argument
    elif location == "tenant_probe":
        tool["tenant_probes"] = {
            "reviewer": {
                "arguments": argument,
                "require_denial": True,
            }
        }
    elif location == "policy_probe":
        tool["policy_probes"] = [
            {
                "id": "policy-1",
                "identity": "reviewer",
                "arguments": argument,
                "checks": [{"type": "denied"}],
            }
        ]
    elif location == "replay_probe":
        tool["replay_probe"] = {"arguments": argument}
    elif location in {"session_write", "session_read"}:
        write_args = argument if location == "session_write" else {}
        read_args = argument if location == "session_read" else {}
        payload["session_tests"] = [
            {
                "id": "session-1",
                "writer_identity": "reviewer",
                "reader_identity": "reviewer",
                "write": {"tool": "lookup", "arguments": write_args},
                "read": {"tool": "lookup", "arguments": read_args},
                "marker_argument": "marker",
            }
        ]
    elif location == "temporal_driver":
        payload["temporal_integrity"] = {
            "enabled": True,
            "identity": "reviewer",
            "driver_tool": "lookup",
            "driver_arguments": argument,
        }
    elif location == "temporal_prompt":
        payload["temporal_integrity"] = {
            "enabled": True,
            "identity": "reviewer",
            "driver_tool": "lookup",
            "prompt_probes": {"credential_prompt": argument},
        }
    else:
        raise AssertionError(f"unsupported test location: {location}")

    return Contract.model_validate(payload)


def _summary(run_id: str, target: str, contract_path: Path) -> RunSummary:
    return RunSummary(
        run_id=run_id,
        target=target,
        contract_path=str(contract_path),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        findings=[
            Finding(
                test_id="AUTH-SYNTHETIC",
                category="authorization",
                title="synthetic authorization",
                status=FindingStatus.PASSED,
                severity=Severity.INFO,
                expected={"allowed": True},
                observed={"allowed": True},
            )
        ],
        invocations=[],
        transport="streamable-http",
        sdk_version="1.28.1",
        state_strategy="legacy_session",
    )


def _write_actual_run(root: Path, contract: Contract) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    contract_path = root / "contract.json"
    contract_path.write_text(
        json.dumps(contract.model_dump(mode="json"), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    summary = _summary(root.name, contract.server.target_label, contract_path)
    write_reports(summary, root, ["json"])
    (root / "tool-inventory.json").write_text(
        json.dumps([{"name": "lookup", "inputSchema": {"type": "object"}}], indent=2),
        encoding="utf-8",
    )
    write_run_receipt(
        summary=summary,
        run_dir=root,
        contract=contract,
        contract_path=contract_path,
        lab_mode=False,
    )
    return root


def _receipt(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "receipt.json").read_text(encoding="utf-8"))


def _force_normalization(run_dir: Path, version: int) -> None:
    path = run_dir / "receipt.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["normalization_version"] = version
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _assert_semantic_hashes_change(before: Path, after: Path) -> None:
    left = _receipt(before)
    right = _receipt(after)
    assert left["context"]["effective_policy_sha256"] != right["context"]["effective_policy_sha256"]
    assert left["checks"]["definition_sha256"] != right["checks"]["definition_sha256"]


def test_phase1b2_writer_emits_normalization_v2_and_preserves_report_v2(
    tmp_path: Path,
) -> None:
    run_dir = _write_actual_run(tmp_path / "run", _contract())
    receipt = _receipt(run_dir)
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))

    assert receipt["schema_version"] == 1
    assert receipt["normalization_version"] == 2
    assert receipt["report_schema_version"] == 2
    assert report["schema_version"] == 2


@pytest.mark.parametrize(
    ("semantic_key", "before_value", "after_value"),
    [
        pytest.param("max_tokens", 10, 10000, id="max-tokens-number"),
        pytest.param("token_budget", 10, 10000, id="token-budget-number"),
        pytest.param("credential_count", 1, 2, id="credential-count-number"),
        pytest.param("secret_enabled", False, True, id="secret-enabled-boolean"),
    ],
)
def test_phase1b2_sensitive_looking_typed_semantic_values_affect_identity(
    tmp_path: Path,
    semantic_key: str,
    before_value: Any,
    after_value: Any,
) -> None:
    before = _write_actual_run(
        tmp_path / "before",
        _contract(semantic_key=semantic_key, semantic_value=before_value),
    )
    after = _write_actual_run(
        tmp_path / "after",
        _contract(semantic_key=semantic_key, semantic_value=after_value),
    )

    _assert_semantic_hashes_change(before, after)


def test_phase1b2_nested_sensitive_looking_semantic_value_affects_identity(
    tmp_path: Path,
) -> None:
    before = _write_actual_run(
        tmp_path / "before",
        _contract(semantic_key="options", semantic_value={"max_tokens": 10}),
    )
    after = _write_actual_run(
        tmp_path / "after",
        _contract(semantic_key="options", semantic_value={"max_tokens": 10000}),
    )

    _assert_semantic_hashes_change(before, after)


@pytest.mark.parametrize(
    "location",
    [
        pytest.param("tenant_probe", id="tenant-probe"),
        pytest.param("policy_probe", id="policy-probe"),
        pytest.param("replay_probe", id="replay-probe"),
        pytest.param("session_write", id="session-write"),
        pytest.param("session_read", id="session-read"),
        pytest.param("temporal_driver", id="temporal-driver"),
    ],
)
def test_phase1b2_argument_bearing_model_paths_preserve_typed_semantics(
    tmp_path: Path,
    location: str,
) -> None:
    before = _write_actual_run(
        tmp_path / "before",
        _contract(
            location=location,
            semantic_key="token_budget",
            semantic_value=10,
        ),
    )
    after = _write_actual_run(
        tmp_path / "after",
        _contract(
            location=location,
            semantic_key="token_budget",
            semantic_value=10000,
        ),
    )

    _assert_semantic_hashes_change(before, after)


def test_phase1b2_known_secret_rotation_stays_stable_and_is_not_exported(
    tmp_path: Path,
) -> None:
    before_secret = "known-secret-alpha"
    after_secret = "known-secret-beta"
    before = _write_actual_run(
        tmp_path / "before",
        _contract(known_secret=before_secret),
    )
    after = _write_actual_run(
        tmp_path / "after",
        _contract(known_secret=after_secret),
    )

    left = _receipt(before)
    right = _receipt(after)

    assert left["context"]["identity_profile_sha256"] == right["context"]["identity_profile_sha256"]
    assert left["context"]["effective_policy_sha256"] == right["context"]["effective_policy_sha256"]
    assert left["checks"]["definition_sha256"] == right["checks"]["definition_sha256"]

    before_text = (before / "receipt.json").read_text(encoding="utf-8")
    after_text = (after / "receipt.json").read_text(encoding="utf-8")
    assert before_secret not in before_text
    assert after_secret not in after_text


def test_phase1b2_unclassified_sensitive_prompt_string_cannot_approve_or_export(
    tmp_path: Path,
) -> None:
    before_value = "opaque-alpha"
    after_value = "opaque-beta"
    before = _write_actual_run(
        tmp_path / "before",
        _contract(
            location="temporal_prompt",
            semantic_key="access_token",
            semantic_value=before_value,
        ),
    )
    after = _write_actual_run(
        tmp_path / "after",
        _contract(
            location="temporal_prompt",
            semantic_key="access_token",
            semantic_value=after_value,
        ),
    )

    assert before_value not in (before / "receipt.json").read_text(encoding="utf-8")
    assert after_value not in (after / "receipt.json").read_text(encoding="utf-8")

    output = tmp_path / "ambiguous-string.json"
    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(before),
            str(after),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2, result.output


def test_phase1b2_actual_writer_to_comparator_sees_semantic_argument_change(
    tmp_path: Path,
) -> None:
    before = _write_actual_run(
        tmp_path / "before",
        _contract(semantic_key="max_tokens", semantic_value=10),
    )
    after = _write_actual_run(
        tmp_path / "after",
        _contract(semantic_key="max_tokens", semantic_value=10000),
    )

    result = compare_saved_runs(before, after)

    assert result["normalization_version"] == 2
    assert result["comparability"]["state"] == "changed_context"
    assert "checks.definition_sha256" in result["comparability"]["reasons"]


def test_phase1b2_legacy_normalization_v1_is_rejected_for_assurance(
    tmp_path: Path,
) -> None:
    reference = _write_actual_run(tmp_path / "reference", _contract())
    candidate = _write_actual_run(tmp_path / "candidate", _contract())
    _force_normalization(reference, 1)
    _force_normalization(candidate, 1)

    with pytest.raises(
        SavedRunComparisonError,
        match=r"normalization.*(?:legacy|unsupported|version).*1|version.*1.*(?:legacy|unsupported)",
    ):
        compare_saved_runs(reference, candidate)


def test_phase1b2_normalization_v2_pair_is_comparable(
    tmp_path: Path,
) -> None:
    reference = _write_actual_run(tmp_path / "reference", _contract())
    candidate = _write_actual_run(tmp_path / "candidate", _contract())
    _force_normalization(reference, 2)
    _force_normalization(candidate, 2)

    result = compare_saved_runs(reference, candidate)

    assert result["normalization_version"] == 2
    assert result["comparability"]["state"] == "comparable"


def test_phase1b2_mixed_v1_v2_normalization_is_rejected(
    tmp_path: Path,
) -> None:
    reference = _write_actual_run(tmp_path / "reference", _contract())
    candidate = _write_actual_run(tmp_path / "candidate", _contract())
    _force_normalization(reference, 1)
    _force_normalization(candidate, 2)

    with pytest.raises(SavedRunComparisonError, match="normalization"):
        compare_saved_runs(reference, candidate)


def test_phase1b2_unknown_normalization_version_is_rejected(
    tmp_path: Path,
) -> None:
    reference = _write_actual_run(tmp_path / "reference", _contract())
    candidate = _write_actual_run(tmp_path / "candidate", _contract())
    _force_normalization(candidate, 3)

    with pytest.raises(SavedRunComparisonError, match="normalization"):
        compare_saved_runs(reference, candidate)


def test_phase1b2_cli_legacy_normalization_returns_two(
    tmp_path: Path,
) -> None:
    reference = _write_actual_run(tmp_path / "reference", _contract())
    candidate = _write_actual_run(tmp_path / "candidate", _contract())
    _force_normalization(reference, 1)
    _force_normalization(candidate, 1)
    output = tmp_path / "legacy-v1.json"

    result = CliRunner().invoke(
        app,
        [
            "baseline",
            "compare-saved",
            str(reference),
            str(candidate),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2, result.output
    assert not output.exists()
