from __future__ import annotations

import json
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .client import McpClient
from .correlation import (
    attribute_correlated_events,
    build_correlation_meta,
    correlation_enabled,
    strip_internal_correlation,
)
from .evidence import contract_secrets, redact
from .models import Contract
from .observers import ObserverCollectionError, build_observer
from .observers.base import ObservationScope
from .observers.ownership import observer_ownership, server_ownership_key
from .util import file_sha256, response_shape, stable_hash, utc_now


async def capture_baseline(contract: Contract, lab_mode: bool = False) -> dict[str, Any]:
    identity_name, identity = _discovery_identity(contract)
    client = McpClient(contract.server, identity_name, identity)
    observers = [build_observer(name, spec) for name, spec in contract.observers.items()]
    target_key = server_ownership_key(contract.server)
    baseline_run_id = uuid.uuid4().hex[:12]

    async with observer_ownership(observers, extra_keys=(target_key,)):
        tools = await client.list_tools()
        probes: dict[str, Any] = {}
        for tool_name, tool_contract in contract.tools.items():
            if not tool_contract.read_only and not (lab_mode and contract.safety.destructive_tests):
                probes[tool_name] = {
                    "skipped": True,
                    "reason": "state-changing baseline probe requires lab mode",
                }
                continue
            probe_identity_name = (
                tool_contract.side_effect_identity or tool_contract.permitted_identities[0]
            )
            probe_identity = contract.identities[probe_identity_name]
            test_id = f"BASELINE-{tool_name}"
            scope = ObservationScope(
                run_id=baseline_run_id,
                check_id=test_id,
                window_id=uuid.uuid4().hex,
                operation_ids=(uuid.uuid4().hex,),
            )
            async with observer_ownership(observers):
                for observer in observers:
                    await observer.begin()

                probe_client = McpClient(
                    contract.server,
                    probe_identity_name,
                    probe_identity,
                )
                if correlation_enabled(observers):
                    invocation = await probe_client.invoke(
                        test_id,
                        tool_name,
                        tool_contract.probe_arguments,
                        meta=build_correlation_meta(
                            scope.run_id,
                            scope.operation_ids[0],
                        ),
                    )
                else:
                    invocation = await probe_client.invoke(
                        test_id,
                        tool_name,
                        tool_contract.probe_arguments,
                    )

                event_batches = [await observer.collect() for observer in observers]

            collected_events = [event for batch in event_batches for event in batch]
            attributed_events, correlation_errors = attribute_correlated_events(
                collected_events,
                observers,
                scope,
            )
            if correlation_errors:
                raise ObserverCollectionError(
                    "correlation: required MCP metadata is missing or malformed",
                    attributed_events,
                )

            events = [asdict(event) for event in attributed_events]
            probes[tool_name] = {
                "identity": probe_identity_name,
                "allowed": invocation.allowed,
                "response_shape": response_shape(strip_internal_correlation(invocation.response)),
                "side_effects": _normalise_events(events),
            }

        tool_map = {tool["name"]: tool for tool in tools}
        payload = {
            "format_version": 1,
            "captured_at": utc_now(),
            "target": contract.server.target_label,
            "tools": tool_map,
            "probes": probes,
        }
        payload = redact(payload, contract_secrets(contract))
        payload["fingerprint"] = stable_hash(payload)
        return payload


def write_baseline(baseline: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")


def load_baseline(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def compare_baselines(expected: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    expected_tools = set(expected.get("tools", {}))
    current_tools = set(current.get("tools", {}))
    schema_changes: dict[str, Any] = {}

    for name in sorted(expected_tools & current_tools):
        before = expected["tools"][name]
        after = current["tools"][name]
        if stable_hash(before) != stable_hash(after):
            schema_changes[name] = {"before": before, "after": after}

    probe_changes: dict[str, Any] = {}
    expected_probes = expected.get("probes", {})
    current_probes = current.get("probes", {})
    for name in sorted(set(expected_probes) | set(current_probes)):
        before = expected_probes.get(name)
        after = current_probes.get(name)
        if stable_hash(before) != stable_hash(after):
            probe_changes[name] = {"before": before, "after": after}

    result: dict[str, Any] = {
        "added_tools": sorted(current_tools - expected_tools),
        "removed_tools": sorted(expected_tools - current_tools),
        "changed_tool_schemas": schema_changes,
        "changed_behaviour_probes": probe_changes,
    }
    result["drift_detected"] = any(
        [
            result["added_tools"],
            result["removed_tools"],
            schema_changes,
            probe_changes,
        ]
    )
    return result


def _discovery_identity(contract: Contract):
    for name, identity in contract.identities.items():
        if identity.headers:
            return name, identity
    return next(iter(contract.identities.items()))


def _normalise_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalised = []
    for event in events:
        details = dict(event.get("details", {}))
        for volatile in ("id", "timestamp", "created_at", "request_id"):
            details.pop(volatile, None)
        normalised.append(
            {
                "observer": event.get("observer"),
                "kind": str(event.get("kind")),
                "details": details,
            }
        )
    return sorted(normalised, key=lambda item: json.dumps(item, sort_keys=True, default=str))


class SavedRunComparisonError(ValueError):
    """Saved run artifacts are missing, inconsistent, or unsupported."""


def compare_saved_runs(reference_dir: Path, candidate_dir: Path) -> dict[str, Any]:
    reference = _load_saved_run(Path(reference_dir), "reference")
    candidate = _load_saved_run(Path(candidate_dir), "candidate")

    comparability = _saved_run_comparability(reference["receipt"], candidate["receipt"])
    reference_findings = reference["findings"]
    candidate_findings = candidate["findings"]

    reference_ids = set(reference_findings)
    candidate_ids = set(candidate_findings)
    common_ids = sorted(reference_ids & candidate_ids)

    comparison_is_comparable = comparability["state"] == "comparable"
    new_failures = sorted(
        test_id
        for test_id in common_ids
        if comparison_is_comparable
        and reference_findings[test_id]["status"] == "passed"
        and candidate_findings[test_id]["status"] == "failed"
    )
    fixed_failures = sorted(
        test_id
        for test_id in common_ids
        if comparison_is_comparable
        and reference_findings[test_id]["status"] == "failed"
        and candidate_findings[test_id]["status"] == "passed"
    )
    persistent_failures = sorted(
        test_id
        for test_id in common_ids
        if comparison_is_comparable
        and reference_findings[test_id]["status"] == "failed"
        and candidate_findings[test_id]["status"] == "failed"
    )
    new_errors = sorted(
        test_id
        for test_id in common_ids
        if comparison_is_comparable
        and reference_findings[test_id]["status"] == "passed"
        and candidate_findings[test_id]["status"] == "error"
    )
    resolved_errors = sorted(
        test_id
        for test_id in common_ids
        if comparison_is_comparable
        and reference_findings[test_id]["status"] == "error"
        and candidate_findings[test_id]["status"] == "passed"
    )

    status_changes = [
        {
            "test_id": test_id,
            "before": reference_findings[test_id]["status"],
            "after": candidate_findings[test_id]["status"],
        }
        for test_id in common_ids
        if reference_findings[test_id]["status"] != candidate_findings[test_id]["status"]
    ]
    severity_changes = [
        {
            "test_id": test_id,
            "before": reference_findings[test_id]["severity"],
            "after": candidate_findings[test_id]["severity"],
        }
        for test_id in common_ids
        if reference_findings[test_id]["severity"] != candidate_findings[test_id]["severity"]
    ]
    severity_escalations = [
        change
        for change in severity_changes
        if _severity_rank(change["after"]) < _severity_rank(change["before"])
    ]

    observation_changes = [
        {
            "test_id": test_id,
            "before": reference_findings[test_id]["observation"],
            "after": candidate_findings[test_id]["observation"],
        }
        for test_id in common_ids
        if reference_findings[test_id]["observation"] != candidate_findings[test_id]["observation"]
    ]
    observation_regressions = [
        change for change in observation_changes if _observation_regressed(change)
    ]

    missing_checks = sorted(reference_ids - candidate_ids)
    new_checks = sorted(candidate_ids - reference_ids)
    skipped_checks = sorted(
        test_id for test_id, finding in candidate_findings.items() if finding["status"] == "skipped"
    )
    newly_skipped = sorted(
        test_id
        for test_id in common_ids
        if candidate_findings[test_id]["status"] == "skipped"
        and reference_findings[test_id]["status"] != "skipped"
    )
    capabilities = _compare_saved_tool_inventory(
        reference["tools"],
        candidate["tools"],
        reference_available=reference["tool_inventory_available"],
        candidate_available=candidate["tool_inventory_available"],
    )
    capability_inventory_regression = (
        reference["tool_inventory_available"] and not candidate["tool_inventory_available"]
    )
    coverage_regression = bool(
        missing_checks
        or newly_skipped
        or new_errors
        or observation_regressions
        or capability_inventory_regression
    )

    has_new_regression = comparison_is_comparable and bool(new_failures)

    return {
        "schema_version": 1,
        "normalization_version": 1,
        "inputs": {
            "reference": {
                "receipt_sha256": reference["receipt_sha256"],
                "run_id": reference["report"].get("run_id"),
                "logical_target": reference["receipt"]["context"].get("logical_target"),
            },
            "candidate": {
                "receipt_sha256": candidate["receipt_sha256"],
                "run_id": candidate["report"].get("run_id"),
                "logical_target": candidate["receipt"]["context"].get("logical_target"),
            },
        },
        "comparability": comparability,
        "conformance": {
            "reference": _conformance(reference_findings),
            "candidate": _conformance(candidate_findings),
        },
        "regression": {
            "new_failures": new_failures,
            "fixed_failures": fixed_failures,
            "persistent_failures": persistent_failures,
            "new_errors": new_errors,
            "resolved_errors": resolved_errors,
            "status_changes": status_changes,
            "severity_changes": severity_changes,
            "severity_escalations": severity_escalations,
            "has_new_regression": has_new_regression,
        },
        "coverage": {
            "missing_checks": missing_checks,
            "new_checks": new_checks,
            "skipped_checks": skipped_checks,
            "observation_changes": observation_changes,
            "observation_regressions": observation_regressions,
            "capability_inventory_regression": capability_inventory_regression,
            "regression": coverage_regression,
        },
        "capabilities": capabilities,
        "freshness": {"reference": "unknown", "candidate": "unknown"},
    }


def _load_saved_run(root: Path, label: str) -> dict[str, Any]:
    receipt_path = root / "receipt.json"
    report_path = root / "report.json"

    receipt = _load_json_object(receipt_path, f"{label} receipt")
    if receipt.get("schema_version") != 1:
        raise SavedRunComparisonError(
            f"{label} receipt schema is unsupported: {receipt.get('schema_version')!r}"
        )
    if receipt.get("normalization_version") != 1:
        raise SavedRunComparisonError(
            f"{label} normalization version is unsupported: "
            f"{receipt.get('normalization_version')!r}"
        )
    if receipt.get("report_schema_version") != 2:
        raise SavedRunComparisonError(
            f"{label} report schema is unsupported: {receipt.get('report_schema_version')!r}"
        )

    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict):
        raise SavedRunComparisonError(f"{label} receipt has no artifacts mapping")

    expected_report_digest = artifacts.get("report_json_sha256")
    if not isinstance(expected_report_digest, str) or not expected_report_digest:
        raise SavedRunComparisonError(f"{label} receipt has no report digest")
    if not report_path.is_file():
        raise SavedRunComparisonError(f"{label} report.json is missing")
    if file_sha256(report_path) != expected_report_digest:
        raise SavedRunComparisonError(f"{label} report digest mismatch")

    report = _load_json_object(report_path, f"{label} report")
    if report.get("schema_version") != 2:
        raise SavedRunComparisonError(
            f"{label} report schema is unsupported: {report.get('schema_version')!r}"
        )

    findings = _index_saved_findings(report, label)
    finding_ids = sorted(findings)
    receipt_checks = receipt.get("checks")
    if not isinstance(receipt_checks, dict):
        raise SavedRunComparisonError(f"{label} receipt has no checks mapping")
    receipt_ids = receipt_checks.get("finding_ids")
    if not isinstance(receipt_ids, list) or not all(isinstance(item, str) for item in receipt_ids):
        raise SavedRunComparisonError(f"{label} receipt finding membership is invalid")
    if sorted(receipt_ids) != finding_ids:
        raise SavedRunComparisonError(f"{label} receipt finding membership does not match report")

    run = receipt.get("run")
    context = receipt.get("context")
    runner = receipt.get("runner")
    if not isinstance(run, dict) or not isinstance(context, dict) or not isinstance(runner, dict):
        raise SavedRunComparisonError(f"{label} receipt is missing run/context/runner mappings")

    _validate_receipt_v1(receipt, label)

    if run.get("completion") != "completed":
        raise SavedRunComparisonError(f"{label} receipt is not a completed run")
    if run.get("run_id") != report.get("run_id"):
        raise SavedRunComparisonError(f"{label} receipt run identity does not match report")
    if context.get("logical_target") != report.get("target"):
        raise SavedRunComparisonError(f"{label} receipt target identity does not match report")

    for receipt_key, report_key in (
        ("mcp_sdk_version", "sdk_version"),
        ("transport", "transport"),
        ("state_strategy", "state_strategy"),
    ):
        receipt_value = runner.get(receipt_key)
        report_value = report.get(report_key)
        if receipt_value != report_value:
            raise SavedRunComparisonError(f"{label} receipt {receipt_key} does not match report")

    computed_assessment = _conformance(findings)
    if report.get("assessment") != computed_assessment:
        raise SavedRunComparisonError(f"{label} report assessment does not match finding statuses")

    expected_inventory_digest = artifacts.get("tool_inventory_sha256")
    tools: dict[str, dict[str, Any]] = {}
    inventory_available = False
    if expected_inventory_digest is not None:
        if not isinstance(expected_inventory_digest, str) or not expected_inventory_digest:
            raise SavedRunComparisonError(f"{label} tool inventory digest is invalid")
        inventory_path = root / "tool-inventory.json"
        if not inventory_path.is_file():
            raise SavedRunComparisonError(f"{label} tool-inventory.json is missing")
        if file_sha256(inventory_path) != expected_inventory_digest:
            raise SavedRunComparisonError(f"{label} tool inventory digest mismatch")
        try:
            inventory_payload = json.loads(inventory_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SavedRunComparisonError(f"{label} tool inventory is invalid: {exc}") from exc
        tools = _index_saved_tools(inventory_payload, label)
        inventory_available = True

    return {
        "receipt": receipt,
        "receipt_sha256": file_sha256(receipt_path),
        "report": report,
        "findings": findings,
        "tools": tools,
        "tool_inventory_available": inventory_available,
    }


def _validate_receipt_v1(receipt: dict[str, Any], label: str) -> None:
    required_top = ("run", "context", "runner", "checks", "artifacts")
    for key in required_top:
        if key not in receipt:
            raise SavedRunComparisonError(f"{label} receipt missing required field: {key}")

    run = receipt["run"]
    context = receipt["context"]
    runner = receipt["runner"]
    checks = receipt["checks"]
    artifacts = receipt["artifacts"]
    if not all(isinstance(item, dict) for item in (run, context, runner, checks, artifacts)):
        raise SavedRunComparisonError(f"{label} receipt required sections must be mappings")

    required_run = (
        "run_id",
        "attempt_id",
        "started_at",
        "finished_at",
        "completion",
    )
    required_context = (
        "logical_target",
        "deployment_identity",
        "credential_principal",
        "contract_source_sha256",
        "target_input_sha256",
        "effective_policy_sha256",
        "identity_profile_sha256",
        "observer_scope_sha256",
        "fixture_profile",
    )
    required_runner = (
        "version",
        "mcp_sdk_version",
        "transport",
        "state_strategy",
        "protocol_versions",
    )
    required_checks = ("finding_ids", "definition_sha256")
    required_artifacts = ("report_json_sha256", "tool_inventory_sha256")

    for section_name, section, keys in (
        ("run", run, required_run),
        ("context", context, required_context),
        ("runner", runner, required_runner),
        ("checks", checks, required_checks),
        ("artifacts", artifacts, required_artifacts),
    ):
        for key in keys:
            if key not in section:
                raise SavedRunComparisonError(
                    f"{label} receipt missing required field: {section_name}.{key}"
                )

    for field in (
        "contract_source_sha256",
        "target_input_sha256",
        "effective_policy_sha256",
        "identity_profile_sha256",
        "observer_scope_sha256",
    ):
        value = context[field]
        if not isinstance(value, str) or not value:
            raise SavedRunComparisonError(
                f"{label} receipt field context.{field} must be a non-empty string"
            )

    if not isinstance(context["logical_target"], str) or not context["logical_target"]:
        raise SavedRunComparisonError(
            f"{label} receipt field context.logical_target must be a non-empty string"
        )
    for field in ("deployment_identity", "credential_principal"):
        value = context[field]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise SavedRunComparisonError(
                f"{label} receipt field context.{field} must be a non-empty string or null"
            )
    if not isinstance(context["fixture_profile"], dict):
        raise SavedRunComparisonError(
            f"{label} receipt field context.fixture_profile must be a mapping"
        )

    if not isinstance(runner["version"], str) or not runner["version"]:
        raise SavedRunComparisonError(
            f"{label} receipt field runner.version must be a non-empty string"
        )
    for field in ("mcp_sdk_version", "transport", "state_strategy"):
        value = runner[field]
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise SavedRunComparisonError(
                f"{label} receipt field runner.{field} must be a non-empty string or null"
            )
    protocol_versions = runner["protocol_versions"]
    if protocol_versions is not None:
        if (
            not isinstance(protocol_versions, list)
            or not protocol_versions
            or not all(isinstance(item, str) and bool(item.strip()) for item in protocol_versions)
        ):
            raise SavedRunComparisonError(
                f"{label} receipt field runner.protocol_versions must be "
                "a non-empty string list or null"
            )
        if protocol_versions != sorted(set(protocol_versions)):
            raise SavedRunComparisonError(
                f"{label} receipt field runner.protocol_versions must be sorted and duplicate-free"
            )

    if not isinstance(checks["definition_sha256"], str) or not checks["definition_sha256"]:
        raise SavedRunComparisonError(
            f"{label} receipt field checks.definition_sha256 must be a non-empty string"
        )


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SavedRunComparisonError(f"{label} is missing: {path.name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SavedRunComparisonError(f"{label} is invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise SavedRunComparisonError(f"{label} must be a JSON object")
    return payload


def _index_saved_findings(report: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    raw_findings = report.get("findings")
    if not isinstance(raw_findings, list):
        raise SavedRunComparisonError(f"{label} report findings must be a list")

    findings: dict[str, dict[str, Any]] = {}
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise SavedRunComparisonError(f"{label} report contains a malformed finding")
        test_id = raw.get("test_id")
        if not isinstance(test_id, str) or not test_id:
            raise SavedRunComparisonError(f"{label} report contains a finding without test_id")
        if test_id in findings:
            raise SavedRunComparisonError(
                f"{label} report contains duplicate finding id: {test_id}"
            )

        status = raw.get("status")
        severity = raw.get("severity")
        observation = raw.get("observation")
        if status not in {"passed", "failed", "error", "skipped"}:
            raise SavedRunComparisonError(
                f"{label} finding {test_id} has unsupported status: {status!r}"
            )
        if severity not in {"critical", "high", "medium", "low", "info"}:
            raise SavedRunComparisonError(
                f"{label} finding {test_id} has unsupported severity: {severity!r}"
            )
        if observation not in {"complete", "partial", "unavailable", "not_required"}:
            raise SavedRunComparisonError(
                f"{label} finding {test_id} has unsupported observation: {observation!r}"
            )
        findings[test_id] = raw
    return findings


def _index_saved_tools(payload: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, list):
        raise SavedRunComparisonError(f"{label} tool inventory must be a JSON list")
    tools: dict[str, dict[str, Any]] = {}
    for raw in payload:
        if not isinstance(raw, dict):
            raise SavedRunComparisonError(f"{label} tool inventory contains a malformed entry")
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            raise SavedRunComparisonError(f"{label} tool inventory contains an entry without name")
        if name in tools:
            raise SavedRunComparisonError(f"{label} tool inventory contains duplicate tool: {name}")
        tools[name] = raw
    return tools


def _conformance(findings: dict[str, dict[str, Any]]) -> str:
    statuses = [finding["status"] for finding in findings.values()]
    if "failed" in statuses:
        return "fail"
    if "error" in statuses:
        return "inconclusive"
    if "skipped" in statuses:
        return "not_tested"
    if "passed" not in statuses:
        return "not_tested"
    return "pass"


def _saved_run_comparability(
    reference: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    unsupported_fields = (
        "context.logical_target",
        "context.deployment_identity",
        "context.credential_principal",
    )
    changed_context_fields = (
        "context.effective_policy_sha256",
        "context.identity_profile_sha256",
        "context.observer_scope_sha256",
        "context.fixture_profile",
        "runner.version",
        "runner.mcp_sdk_version",
        "runner.transport",
        "runner.state_strategy",
        "runner.protocol_versions",
        "checks.definition_sha256",
    )
    informational_fields = (
        "context.contract_source_sha256",
        "context.target_input_sha256",
    )
    unknown_capable_fields = (
        "context.deployment_identity",
        "context.credential_principal",
        "runner.mcp_sdk_version",
        "runner.transport",
        "runner.state_strategy",
        "runner.protocol_versions",
    )

    reasons: list[str] = []
    input_changes: list[str] = []
    unknown_fields: list[str] = []
    asymmetric_unknown_fields: list[str] = []

    for field in unsupported_fields:
        before = _dotted(reference, field)
        after = _dotted(candidate, field)
        if before is None or after is None:
            if field in unknown_capable_fields:
                unknown_fields.append(field)
                if (before is None) != (after is None):
                    reasons.append(field)
                    input_changes.append(field)
                    asymmetric_unknown_fields.append(field)
            continue
        if before != after:
            reasons.append(field)
            input_changes.append(field)

    for field in changed_context_fields:
        before = _dotted(reference, field)
        after = _dotted(candidate, field)
        if before is None or after is None:
            if field in unknown_capable_fields and field not in unknown_fields:
                unknown_fields.append(field)
            if field in unknown_capable_fields and (before is None) != (after is None):
                reasons.append(field)
                input_changes.append(field)
                asymmetric_unknown_fields.append(field)
            continue
        if before != after:
            reasons.append(field)
            input_changes.append(field)

    for field in informational_fields:
        before = _dotted(reference, field)
        after = _dotted(candidate, field)
        if before is not None and after is not None and before != after:
            input_changes.append(field)

    if asymmetric_unknown_fields or any(field in unsupported_fields for field in reasons):
        state = "unsupported"
    elif reasons:
        state = "changed_context"
    else:
        state = "comparable"

    return {
        "state": state,
        "reasons": sorted(set(reasons)),
        "input_changes": sorted(set(input_changes)),
        "unknown_fields": sorted(set(unknown_fields)),
    }


def _dotted(value: dict[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _compare_saved_tool_inventory(
    reference: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
    *,
    reference_available: bool,
    candidate_available: bool,
) -> dict[str, Any]:
    if not reference_available or not candidate_available:
        return {
            "comparison_state": "unavailable",
            "reference_inventory_available": reference_available,
            "candidate_inventory_available": candidate_available,
            "added_tools": [],
            "removed_tools": [],
            "changed_tool_schemas": {},
            "changed_tool_metadata": {},
            "review_required": True,
        }

    reference_names = set(reference)
    candidate_names = set(candidate)
    changed_schemas: dict[str, Any] = {}
    changed_metadata: dict[str, Any] = {}

    for name in sorted(reference_names & candidate_names):
        before = reference[name]
        after = candidate[name]
        before_schema = before.get("inputSchema", before.get("input_schema"))
        after_schema = after.get("inputSchema", after.get("input_schema"))
        if stable_hash(before_schema) != stable_hash(after_schema):
            changed_schemas[name] = {"before": before_schema, "after": after_schema}

        before_metadata = {
            k: v for k, v in before.items() if k not in {"inputSchema", "input_schema"}
        }
        after_metadata = {
            k: v for k, v in after.items() if k not in {"inputSchema", "input_schema"}
        }
        if stable_hash(before_metadata) != stable_hash(after_metadata):
            changed_metadata[name] = {"before": before_metadata, "after": after_metadata}

    added_tools = sorted(candidate_names - reference_names)
    removed_tools = sorted(reference_names - candidate_names)
    review_required = bool(added_tools or removed_tools or changed_schemas or changed_metadata)

    return {
        "comparison_state": "comparable",
        "reference_inventory_available": reference_available,
        "candidate_inventory_available": candidate_available,
        "added_tools": added_tools,
        "removed_tools": removed_tools,
        "changed_tool_schemas": changed_schemas,
        "changed_tool_metadata": changed_metadata,
        "review_required": review_required,
    }


def _severity_rank(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[value]


def _observation_regressed(change: dict[str, str]) -> bool:
    before = change["before"]
    after = change["after"]

    if before == "not_required":
        return after in {"partial", "unavailable"}
    if after == "not_required":
        return before in {"complete", "partial", "unavailable"}

    rank = {"unavailable": 0, "partial": 1, "complete": 2}
    before_rank = rank.get(before)
    after_rank = rank.get(after)
    return before_rank is not None and after_rank is not None and after_rank < before_rank
