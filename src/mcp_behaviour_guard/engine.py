from __future__ import annotations

import asyncio
import json
import os
import uuid
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from .client import McpClient
from .correlation import (
    attribute_correlated_events,
    build_correlation_meta,
    correlated_observer_names,
    correlation_enabled,
    correlation_redaction_values,
)
from .evidence import contract_secrets, redact
from .models import (
    AuthorizationStatus,
    Contract,
    DeniedCheck,
    ExecutionStatus,
    Finding,
    FindingStatus,
    IdentitySpec,
    InvocationRecord,
    ObservationStatus,
    PathWithinCheck,
    ResponseNotContainsCheck,
    ResponseNotContainsEnvCheck,
    RunSummary,
    Severity,
    SideEffectKind,
    ToolContract,
)
from .observers import Observer, ObserverCollectionError, SideEffectEvent, build_observer
from .observers.base import ObservationScope
from .observers.ownership import observer_ownership, server_ownership_key
from .storage import RunStore
from .temporal import compact_drift_summary, compare_metadata_snapshots, metadata_fingerprint
from .util import get_path, matches_any, stable_hash, utc_now


class GuardEngine:
    def __init__(
        self,
        contract: Contract,
        contract_path: Path,
        store: RunStore,
        output_root: Path,
        lab_mode: bool,
    ) -> None:
        self.contract = contract
        self.contract_path = contract_path
        self.store = store
        self.output_root = output_root
        self.lab_mode = lab_mode
        self.run_id = uuid.uuid4().hex[:12]
        self.run_dir = output_root / self.run_id
        self.trace_path = self.run_dir / "traces" / "mcp-trace.jsonl"
        self.findings: list[Finding] = []
        self.invocations: list[InvocationRecord] = []
        self.observers: list[Observer] = [
            build_observer(name, spec) for name, spec in contract.observers.items()
        ]
        self._discovery_ok = False
        self._positive_controls: dict[str, bool] = {}
        self._identity_positive_controls: dict[tuple[str, str], bool] = {}
        self._secrets = contract_secrets(contract)
        self._current_operation_id: ContextVar[str | None] = ContextVar(
            f"mcp_guard_operation_{id(self)}",
            default=None,
        )

    async def run(self) -> RunSummary:
        target_key = server_ownership_key(self.contract.server)
        async with observer_ownership(self.observers, extra_keys=(target_key,)):
            return await self._run_with_ownership()

    async def _run_with_ownership(self) -> RunSummary:
        started_at = utc_now()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.trace_path.parent.mkdir(parents=True, exist_ok=True)
        self.store.start_run(
            run_id=self.run_id,
            target=self.contract.server.target_label,
            contract_path=str(self.contract_path),
            contract_hash=stable_hash(self.contract.model_dump(mode="json")),
            started_at=started_at,
        )

        discovered = await self._discover_tools()
        await self._check_inventory(discovered)
        await self._check_temporal_integrity()
        await self._check_access_matrix()
        await self._check_tool_side_effects()
        await self._check_tenant_isolation()
        await self._check_policy_probes()
        await self._check_session_isolation()
        await self._check_replay_protection()

        summary = RunSummary(
            run_id=self.run_id,
            target=self.contract.server.target_label,
            contract_path=str(self.contract_path),
            started_at=started_at,
            finished_at=utc_now(),
            findings=self.findings,
            invocations=self.invocations,
            transport=self.contract.server.transport,
            sdk_version=_mcp_sdk_version(),
            state_strategy="legacy_session"
            if self.contract.server.transport == "streamable-http"
            else "stdio_process",
        )
        self.store.finish_run(summary)
        return summary

    async def _discover_tools(self) -> list[dict[str, Any]]:
        last_error: Exception | None = None
        for identity_name, identity in self.contract.identities.items():
            try:
                client = McpClient(self.contract.server, identity_name, identity)
                tools = await client.list_tools()
                self._discovery_ok = True
                (self.run_dir / "tool-inventory.json").write_text(
                    json.dumps(redact(tools, self._secrets), indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                return tools
            except Exception as exc:  # discovery fallback should try all declared identities
                last_error = exc
        message = str(last_error) if last_error else "no identities were configured"
        self._add_finding(
            Finding(
                test_id="DISCOVERY-001",
                category="discovery",
                title="MCP tool discovery completed",
                status=FindingStatus.ERROR,
                severity=Severity.HIGH,
                expected="at least one identity can connect and list tools",
                observed=message,
                remediation="Check the MCP URL, authentication headers, TLS settings and server logs.",
            )
        )
        return []

    async def _check_temporal_integrity(self) -> None:
        temporal = self.contract.temporal_integrity
        if not temporal.enabled:
            return

        driver_name = temporal.driver_tool
        if not driver_name:
            return
        driver_contract = self.contract.tools[driver_name]
        test_id = "TEMPORAL-METADATA-001"
        if not self._tool_invocation_enabled(driver_contract):
            self._add_finding(self._lab_skip(test_id, "temporal_integrity", driver_name))
            return

        identity_name = temporal.identity or _first(driver_contract.permitted_identities)
        if not identity_name:
            self._add_finding(
                Finding(
                    test_id=test_id,
                    category="temporal_integrity",
                    title="MCP metadata stays stable during repeated use",
                    status=FindingStatus.ERROR,
                    severity=Severity.HIGH,
                    expected="a permitted identity for the temporal driver tool",
                    observed="no identity was available",
                )
            )
            return

        identity = self.contract.identities[identity_name]
        temporal_dir = self.run_dir / "temporal"
        temporal_dir.mkdir(parents=True, exist_ok=True)

        reference_snapshot: dict[str, Any] | None = None
        first_drift: dict[str, Any] | None = None
        invocation_errors: list[dict[str, Any]] = []
        notification_log: list[dict[str, Any]] = []
        checkpoints = 0
        stop_requested = False

        for session_number in range(1, temporal.sessions + 1):
            notifications: list[str] = []
            client = McpClient(self.contract.server, identity_name, identity)
            try:
                async with client.session(notification_sink=notifications) as (session, session_id):
                    initial_snapshot = await client.metadata_snapshot(session, temporal)
                    if reference_snapshot is None:
                        reference_snapshot = initial_snapshot

                    checkpoint_path = temporal_dir / f"session-{session_number:02d}-initial.json"
                    _write_json(
                        checkpoint_path,
                        {
                            "session": session_number,
                            "checkpoint": "initial",
                            "fingerprint": metadata_fingerprint(initial_snapshot),
                            "snapshot": initial_snapshot,
                        },
                        self._secrets,
                    )
                    checkpoints += 1

                    initial_diff = compare_metadata_snapshots(reference_snapshot, initial_snapshot)
                    if initial_diff["drift_detected"] and first_drift is None:
                        first_drift = {
                            "session": session_number,
                            "after_call": 0,
                            "summary": compact_drift_summary(initial_diff),
                            "diff_file": str(
                                (
                                    temporal_dir / f"session-{session_number:02d}-initial-diff.json"
                                ).relative_to(self.run_dir)
                            ),
                        }
                        _write_json(
                            temporal_dir / f"session-{session_number:02d}-initial-diff.json",
                            initial_diff,
                            self._secrets,
                        )
                        if temporal.stop_on_first_drift:
                            stop_requested = True

                    if stop_requested:
                        notification_log.append(
                            {"session": session_number, "notifications": list(notifications)}
                        )
                        break

                    for call_number in range(1, temporal.retests_per_session + 1):
                        invocation = await client.invoke_on_session(
                            session=session,
                            session_id=session_id,
                            test_id=f"{test_id}-S{session_number:02d}-C{call_number:02d}",
                            tool=driver_name,
                            arguments=temporal.driver_arguments,
                        )
                        self._record_invocation(invocation)
                        if invocation.allowed is not True:
                            invocation_errors.append(
                                {
                                    "session": session_number,
                                    "call": call_number,
                                    "error": invocation.error,
                                }
                            )
                            break

                        should_snapshot = temporal.rediscover_after_each_call or (
                            call_number == temporal.retests_per_session
                        )
                        if should_snapshot:
                            current_snapshot = await client.metadata_snapshot(session, temporal)
                            diff = compare_metadata_snapshots(reference_snapshot, current_snapshot)
                            snapshot_path = (
                                temporal_dir
                                / f"session-{session_number:02d}-after-{call_number:02d}.json"
                            )
                            _write_json(
                                snapshot_path,
                                {
                                    "session": session_number,
                                    "after_call": call_number,
                                    "fingerprint": metadata_fingerprint(current_snapshot),
                                    "notifications": list(notifications),
                                    "snapshot": current_snapshot,
                                },
                                self._secrets,
                            )
                            checkpoints += 1

                            if diff["drift_detected"]:
                                diff_path = (
                                    temporal_dir
                                    / f"session-{session_number:02d}-after-{call_number:02d}-diff.json"
                                )
                                _write_json(diff_path, diff, self._secrets)
                                if first_drift is None:
                                    first_drift = {
                                        "session": session_number,
                                        "after_call": call_number,
                                        "summary": compact_drift_summary(diff),
                                        "diff_file": str(diff_path.relative_to(self.run_dir)),
                                    }
                                if temporal.stop_on_first_drift:
                                    stop_requested = True
                                    break

                        if temporal.delay_between_calls_ms:
                            await asyncio.sleep(temporal.delay_between_calls_ms / 1000)

                    notification_log.append(
                        {"session": session_number, "notifications": list(notifications)}
                    )
            except Exception as exc:
                invocation_errors.append(
                    {
                        "session": session_number,
                        "call": None,
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    }
                )

            if stop_requested:
                break

        if reference_snapshot is None:
            status = FindingStatus.ERROR
            severity = Severity.HIGH
        elif first_drift is not None:
            status = FindingStatus.FAILED
            severity = temporal.severity
        elif invocation_errors:
            status = FindingStatus.ERROR
            severity = Severity.MEDIUM
        else:
            status = FindingStatus.PASSED
            severity = Severity.INFO

        self._add_finding(
            Finding(
                test_id=test_id,
                category="temporal_integrity",
                title="MCP metadata stays stable during repeated use",
                status=status,
                severity=severity,
                expected={
                    "metadata_drift": False,
                    "driver_tool": driver_name,
                    "sessions": temporal.sessions,
                    "retests_per_session": temporal.retests_per_session,
                    "monitored": {
                        "tools": temporal.monitor_tools,
                        "prompts": temporal.monitor_prompts,
                        "resources": temporal.monitor_resources,
                    },
                },
                observed={
                    "metadata_drift": first_drift is not None,
                    "first_drift": first_drift,
                    "checkpoints_written": checkpoints,
                    "list_change_notifications": notification_log,
                    "errors": invocation_errors,
                },
                evidence={
                    "temporal_snapshots": str(temporal_dir.relative_to(self.run_dir)),
                    "trace": self._trace_reference(),
                },
                remediation=(
                    "Treat changed tool, prompt or resource metadata as a new approval event. "
                    "Pin reviewed definitions and investigate the server or configuration source."
                    if first_drift is not None
                    else None
                ),
            )
        )

    async def _check_inventory(self, discovered: list[dict[str, Any]]) -> None:
        actual: set[str] = {
            str(item["name"]) for item in discovered if isinstance(item.get("name"), str)
        }
        expected = set(self.contract.tools)
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        status = (
            FindingStatus.ERROR
            if not self._discovery_ok
            else FindingStatus.PASSED
            if not missing and not unexpected
            else FindingStatus.FAILED
        )
        severity = Severity.INFO if status == FindingStatus.PASSED else Severity.HIGH
        self._add_finding(
            Finding(
                test_id="INVENTORY-001",
                category="capability_drift",
                title="Discovered tool inventory matches the contract",
                status=status,
                severity=severity,
                expected={"tools": sorted(expected)},
                observed={
                    "tools": sorted(actual),
                    "missing": missing,
                    "unexpected": unexpected,
                },
                evidence={"inventory": "tool-inventory.json"},
                remediation=(
                    "Review newly exposed or missing tools and update the contract only after approval."
                    if status == FindingStatus.FAILED
                    else None
                ),
            )
        )

    async def _check_access_matrix(self) -> None:
        for tool_name, tool in self.contract.tools.items():
            if not self._tool_invocation_enabled(tool):
                for identity_name in self.contract.identities:
                    test_id = f"AUTH-{tool_name}-{identity_name}".upper().replace("_", "-")
                    self._add_finding(self._lab_skip(test_id, "authorization", tool_name))
                continue

            ordered = sorted(
                self.contract.identities.items(),
                key=lambda item: item[0] not in tool.permitted_identities,
            )
            positive = False
            for identity_name, identity in ordered:
                test_id = f"AUTH-{tool_name}-{identity_name}".upper().replace("_", "-")
                (
                    invocation,
                    effect_events,
                    observation,
                    observer_errors,
                ) = await self._invoke_with_mutation_observation(
                    test_id,
                    identity_name,
                    identity,
                    tool_name,
                    tool.probe_arguments,
                )

                expected_allowed = identity_name in tool.permitted_identities
                if expected_allowed and invocation.authorization == AuthorizationStatus.ALLOW:
                    positive = True
                    self._identity_positive_controls[(tool_name, identity_name)] = True

                status = _authorization_assessment(invocation, expected_allowed, positive)
                if (
                    observation not in {ObservationStatus.NOT_REQUIRED, ObservationStatus.COMPLETE}
                    and status != FindingStatus.FAILED
                ):
                    status = FindingStatus.ERROR

                severity = (
                    Severity.INFO
                    if status == FindingStatus.PASSED
                    else Severity.CRITICAL
                    if invocation.allowed is True and not expected_allowed
                    else Severity.MEDIUM
                    if status == FindingStatus.ERROR
                    else Severity.HIGH
                )

                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="authorization",
                        title=f"{identity_name} access to {tool_name} follows the contract",
                        status=status,
                        severity=severity,
                        expected={"allowed": expected_allowed},
                        observed={
                            "probe_executed": (
                                invocation.execution != ExecutionStatus.NOT_ATTEMPTED
                            ),
                            "allowed": invocation.allowed,
                            "authorization": invocation.authorization.value,
                            "execution": invocation.execution.value,
                            "positive_control": positive,
                            "error": invocation.error,
                            "response": invocation.response,
                            "effects": _event_dicts(effect_events),
                            "observer_errors": observer_errors,
                        },
                        evidence={"trace": self._trace_reference()},
                        observation=observation,
                        remediation=(
                            "Enforce authorization at the server boundary and again inside "
                            "sensitive tool handlers."
                            if status == FindingStatus.FAILED
                            else None
                        ),
                    )
                )
            self._positive_controls[tool_name] = positive

    async def _check_tool_side_effects(self) -> None:
        if not self.observers:
            for tool_name, tool in self.contract.tools.items():
                if not _has_effect_claims(tool):
                    continue
                self._add_finding(
                    Finding(
                        test_id=f"BEHAVIOUR-{tool_name}".upper().replace("_", "-"),
                        category="runtime_behaviour",
                        title=f"Side effects for {tool_name} cannot be observed",
                        status=FindingStatus.ERROR,
                        severity=Severity.MEDIUM,
                        expected="an independent effect observer",
                        observed="no observers were configured",
                        observation=ObservationStatus.UNAVAILABLE,
                    )
                )
            return

        for tool_name, tool in self.contract.tools.items():
            if not _has_effect_claims(tool):
                continue
            test_id = f"BEHAVIOUR-{tool_name}".upper().replace("_", "-")
            if not self._tool_invocation_enabled(tool):
                self._add_finding(self._lab_skip(test_id, "runtime_behaviour", tool_name))
                continue
            identity_name = tool.side_effect_identity or _first(tool.permitted_identities)
            if not identity_name:
                continue
            identity = self.contract.identities[identity_name]

            required_kinds = _required_effect_kinds(tool)
            scope = self._new_observation_scope(test_id)
            async with observer_ownership(self.observers):
                begin_errors = await self._begin_observers()
                begin_observation = self._observer_coverage(begin_errors, required_kinds)
                if begin_observation == ObservationStatus.UNAVAILABLE or (
                    not tool.read_only and begin_observation != ObservationStatus.COMPLETE
                ):
                    self._add_finding(
                        Finding(
                            test_id=test_id,
                            category="runtime_behaviour",
                            title=f"Runtime side effects for {tool_name} could not be checked",
                            status=FindingStatus.ERROR,
                            severity=Severity.MEDIUM,
                            expected="working effect observers before the probe runs",
                            observed={"probe_executed": False, "observer_errors": begin_errors},
                            observation=begin_observation,
                        )
                    )
                    continue
                invocation = await self._invoke_for_operation(
                    scope.operation_ids[0],
                    test_id,
                    identity_name,
                    identity,
                    tool_name,
                    tool.probe_arguments,
                )
                events, observation, observer_errors = await self._collect_observers(
                    begin_errors,
                    required_kinds,
                    scope,
                )
            violations = _side_effect_violations(tool, events)

            if violations:
                status = FindingStatus.FAILED
            elif invocation.allowed is not True or observation != ObservationStatus.COMPLETE:
                status = FindingStatus.ERROR
            else:
                status = FindingStatus.PASSED

            if status == FindingStatus.ERROR:
                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="runtime_behaviour",
                        title=f"Runtime side effects for {tool_name} were observed",
                        status=status,
                        severity=Severity.MEDIUM,
                        expected="a successful probe call",
                        observed={
                            "error": invocation.error,
                            "events": _event_dicts(events),
                            "observer_errors": observer_errors,
                        },
                        evidence={"trace": self._trace_reference()},
                        observation=observation,
                    )
                )
                continue

            self._add_finding(
                Finding(
                    test_id=test_id,
                    category="runtime_behaviour",
                    title=f"{tool_name} performs only declared side effects",
                    status=status,
                    severity=Severity.INFO if status == FindingStatus.PASSED else Severity.HIGH,
                    expected={
                        "read_only": tool.read_only,
                        "allowed_network_destinations": tool.allowed_network_destinations,
                        "allowed_filesystem_writes": tool.allowed_filesystem_writes,
                        "forbidden_side_effects": [x.value for x in tool.forbidden_side_effects],
                    },
                    observed={
                        "events": _event_dicts(events),
                        "violations": violations,
                        "observer_errors": observer_errors,
                    },
                    evidence={"trace": self._trace_reference()},
                    observation=observation,
                    remediation=(
                        "Remove undeclared actions or explicitly constrain and document the required destinations and paths."
                        if status == FindingStatus.FAILED
                        else None
                    ),
                )
            )

    async def _check_tenant_isolation(self) -> None:
        for tool_name, tool in self.contract.tools.items():
            if not self._tool_invocation_enabled(tool):
                for identity_name in tool.tenant_probes:
                    test_id = f"TENANT-{tool_name}-{identity_name}".upper().replace("_", "-")
                    self._add_finding(self._lab_skip(test_id, "tenant_isolation", tool_name))
                continue

            for identity_name, probe in tool.tenant_probes.items():
                identity = self.contract.identities[identity_name]
                test_id = f"TENANT-{tool_name}-{identity_name}".upper().replace("_", "-")
                (
                    invocation,
                    effect_events,
                    observation,
                    observer_errors,
                ) = await self._invoke_with_mutation_observation(
                    test_id,
                    identity_name,
                    identity,
                    tool_name,
                    probe.arguments,
                )

                observed_tenant = get_path(invocation.response, probe.resource_tenant_path)
                expected_tenant = probe.expected_tenant or identity.tenant
                positive_control = self._identity_positive_controls.get(
                    (tool_name, identity_name), False
                )
                successful_result = (
                    invocation.allowed is True and invocation.execution == ExecutionStatus.SUCCEEDED
                )

                authorization_assertion = "not_asserted"
                ownership_assertion = "not_asserted"

                if probe.require_denial:
                    authorization_assertion = _authorization_assessment(
                        invocation,
                        expected_allowed=False,
                        positive_control=positive_control,
                    ).value
                elif expected_tenant is not None:
                    if not successful_result or observed_tenant is None:
                        ownership_assertion = "error"
                    elif observed_tenant != expected_tenant:
                        ownership_assertion = "failed"
                    else:
                        ownership_assertion = "passed"

                confidentiality_assertion = "not_asserted"
                confidentiality_match_count = 0
                if probe.confidentiality is not None:
                    confidentiality_match_count = probe.confidentiality.match_count(
                        invocation.response
                    )
                    if confidentiality_match_count:
                        confidentiality_assertion = "failed"
                    elif invocation.response is None:
                        confidentiality_assertion = "error"
                    else:
                        confidentiality_assertion = "passed"

                assertion_outcomes = (
                    authorization_assertion,
                    ownership_assertion,
                    confidentiality_assertion,
                )
                if "failed" in assertion_outcomes:
                    status = FindingStatus.FAILED
                elif "error" in assertion_outcomes or (
                    not probe.require_denial and not successful_result
                ):
                    status = FindingStatus.ERROR
                else:
                    status = FindingStatus.PASSED

                if (
                    observation not in {ObservationStatus.NOT_REQUIRED, ObservationStatus.COMPLETE}
                    and status != FindingStatus.FAILED
                ):
                    status = FindingStatus.ERROR

                failed_assertions = [
                    name
                    for name, outcome in (
                        ("authorization", authorization_assertion),
                        ("ownership", ownership_assertion),
                        ("confidentiality", confidentiality_assertion),
                    )
                    if outcome == "failed"
                ]
                inconclusive = status == FindingStatus.ERROR
                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="tenant_isolation",
                        title=f"{tool_name} enforces the {identity_name} tenant boundary",
                        status=status,
                        severity=Severity.CRITICAL
                        if status == FindingStatus.FAILED
                        else Severity.MEDIUM
                        if inconclusive
                        else Severity.INFO,
                        expected={
                            "denied": probe.require_denial,
                            "resource_tenant": expected_tenant,
                            "confidentiality": {
                                "configured": probe.confidentiality is not None,
                                "matching": (
                                    "case_sensitive_literal_string_leaves"
                                    if probe.confidentiality is not None
                                    else None
                                ),
                            },
                        },
                        observed={
                            "probe_executed": (
                                invocation.execution != ExecutionStatus.NOT_ATTEMPTED
                            ),
                            "allowed": invocation.allowed,
                            "authorization": invocation.authorization.value,
                            "execution": invocation.execution.value,
                            "positive_control": positive_control,
                            "resource_tenant": observed_tenant,
                            "authorization_assertion": authorization_assertion,
                            "ownership_assertion": ownership_assertion,
                            "confidentiality_assertion": confidentiality_assertion,
                            "confidentiality_match_count": confidentiality_match_count,
                            "failed_assertions": failed_assertions,
                            "response": invocation.response,
                            "error": invocation.error,
                            "effects": _event_dicts(effect_events),
                            "observer_errors": observer_errors,
                        },
                        evidence={"trace": self._trace_reference()},
                        observation=observation,
                        remediation=(
                            "Enforce tenant authorization before returning resources or "
                            "protected data across tenant boundaries."
                            if status == FindingStatus.FAILED
                            else None
                        ),
                    )
                )

    async def _check_policy_probes(self) -> None:
        for tool_name, tool in self.contract.tools.items():
            for probe in tool.policy_probes:
                if not self._tool_invocation_enabled(tool):
                    self._add_finding(self._lab_skip(probe.id, "policy_boundary", tool_name))
                    continue

                identity = self.contract.identities[probe.identity]
                (
                    invocation,
                    effect_events,
                    observation,
                    observer_errors,
                ) = await self._invoke_with_mutation_observation(
                    probe.id,
                    probe.identity,
                    identity,
                    tool_name,
                    probe.arguments,
                )

                violations: list[dict[str, Any]] = []
                for check in probe.checks:
                    if isinstance(check, DeniedCheck):
                        if invocation.allowed is True:
                            violations.append({"check": check.type, "reason": "call was allowed"})
                    elif isinstance(check, ResponseNotContainsEnvCheck):
                        response_text = json.dumps(invocation.response, default=str)
                        configured_environment = {
                            **self.contract.server.environment,
                            **identity.environment,
                        }
                        leaked = []
                        for name in check.env_names:
                            value = configured_environment.get(name) or os.getenv(name, "")
                            if value and value in response_text:
                                leaked.append(name)
                        if leaked:
                            violations.append(
                                {
                                    "check": check.type,
                                    "leaked_environment_variables": leaked,
                                }
                            )
                    elif isinstance(check, ResponseNotContainsCheck):
                        response_text = json.dumps(invocation.response, default=str)
                        present = [
                            value for value in check.values if value and value in response_text
                        ]
                        if present:
                            violations.append(
                                {
                                    "check": check.type,
                                    "forbidden_values_present": present,
                                }
                            )
                    elif invocation.allowed is not True:
                        # Successful-response predicates such as path checks do not
                        # apply to a denied/error response. Confidentiality predicates
                        # above still do.
                        continue
                    elif isinstance(check, PathWithinCheck):
                        raw_path = get_path(invocation.response, check.response_path)
                        if not _path_is_within(raw_path, check.roots):
                            violations.append(
                                {
                                    "check": check.type,
                                    "response_path": check.response_path,
                                    "observed": raw_path,
                                    "allowed_roots": [str(root) for root in check.roots],
                                }
                            )

                denial_expected = any(isinstance(check, DeniedCheck) for check in probe.checks)
                if violations:
                    status = FindingStatus.FAILED
                elif denial_expected:
                    confirmed_denial = (
                        invocation.authorization == AuthorizationStatus.DENY
                        and self._identity_positive_controls.get((tool_name, probe.identity), False)
                    )
                    status = FindingStatus.PASSED if confirmed_denial else FindingStatus.ERROR
                else:
                    status = (
                        FindingStatus.PASSED if invocation.allowed is True else FindingStatus.ERROR
                    )

                if (
                    observation not in {ObservationStatus.NOT_REQUIRED, ObservationStatus.COMPLETE}
                    and status != FindingStatus.FAILED
                ):
                    status = FindingStatus.ERROR

                errored = status == FindingStatus.ERROR
                self._add_finding(
                    Finding(
                        test_id=probe.id,
                        category="policy_boundary",
                        title=probe.description
                        or f"{tool_name} respects declared response and path boundaries",
                        status=status,
                        severity=Severity.MEDIUM
                        if errored
                        else probe.severity
                        if violations
                        else Severity.INFO,
                        expected={
                            "checks": [check.model_dump(mode="json") for check in probe.checks]
                        },
                        observed={
                            "probe_executed": (
                                invocation.execution != ExecutionStatus.NOT_ATTEMPTED
                            ),
                            "allowed": invocation.allowed,
                            "authorization": invocation.authorization.value,
                            "execution": invocation.execution.value,
                            "response": invocation.response,
                            "error": invocation.error,
                            "violations": violations,
                            "effects": _event_dicts(effect_events),
                            "observer_errors": observer_errors,
                        },
                        evidence={"trace": self._trace_reference()},
                        observation=observation,
                        remediation=(
                            "Validate paths after canonicalisation, minimize inherited "
                            "environment, and return only contract-approved data."
                            if violations
                            else None
                        ),
                    )
                )

    async def _check_session_isolation(self) -> None:
        for test in self.contract.session_tests:
            steps = (
                ("writer", test.write.tool, self.contract.tools[test.write.tool]),
                ("reader", test.read.tool, self.contract.tools[test.read.tool]),
            )
            blocked = False
            for step_name, tool_name, tool_contract in steps:
                allowed, coverage, required_kinds = self._tool_call_preflight(tool_contract)
                if allowed:
                    continue

                if not self._tool_invocation_enabled(tool_contract):
                    self._add_finding(self._lab_skip(test.id, "session_isolation", tool_name))
                else:
                    self._add_finding(
                        Finding(
                            test_id=test.id,
                            category="session_isolation",
                            title="Independent MCP clients do not share session state",
                            status=FindingStatus.ERROR,
                            severity=Severity.MEDIUM,
                            expected="all session steps pass safety and evidence preflight",
                            observed={
                                "probe_executed": False,
                                "blocked_step": step_name,
                                "blocked_tool": tool_name,
                                "required_effects": sorted(item.value for item in required_kinds),
                            },
                            observation=coverage,
                        )
                    )
                blocked = True
                break

            if blocked:
                continue

            marker = f"guard-{uuid.uuid4().hex}"
            writer = _with_session_header(
                self.contract.identities[test.writer_identity], f"writer-{uuid.uuid4().hex}"
            )
            reader = _with_session_header(
                self.contract.identities[test.reader_identity], f"reader-{uuid.uuid4().hex}"
            )
            write_arguments = dict(test.write.arguments)
            write_arguments[test.marker_argument] = marker

            (
                write_invocation,
                write_effects,
                write_observation,
                write_observer_errors,
            ) = await self._invoke_with_mutation_observation(
                f"{test.id}-WRITE",
                test.writer_identity,
                writer,
                test.write.tool,
                write_arguments,
            )

            if (
                write_invocation.execution == ExecutionStatus.NOT_ATTEMPTED
                or write_observation
                not in {ObservationStatus.NOT_REQUIRED, ObservationStatus.COMPLETE}
            ):
                self._add_finding(
                    Finding(
                        test_id=test.id,
                        category="session_isolation",
                        title="Independent MCP clients do not share session state",
                        status=FindingStatus.ERROR,
                        severity=Severity.MEDIUM,
                        expected={"reader_contains_writer_marker": False},
                        observed={
                            "writer_probe_executed": (
                                write_invocation.execution != ExecutionStatus.NOT_ATTEMPTED
                            ),
                            "writer_execution": write_invocation.execution.value,
                            "writer_error": write_invocation.error,
                            "writer_effects": _event_dicts(write_effects),
                            "writer_observer_errors": write_observer_errors,
                            "reader_probe_executed": False,
                        },
                        evidence={"trace": self._trace_reference()},
                        observation=write_observation,
                    )
                )
                continue

            (
                read_invocation,
                read_effects,
                read_observation,
                read_observer_errors,
            ) = await self._invoke_with_mutation_observation(
                f"{test.id}-READ",
                test.reader_identity,
                reader,
                test.read.tool,
                test.read.arguments,
            )

            session_observation = _merge_observation_statuses(
                write_observation,
                read_observation,
            )

            leaked = marker in json.dumps(read_invocation.response, default=str)
            errored = write_invocation.allowed is not True or read_invocation.allowed is not True

            if not leaked and (
                read_invocation.execution == ExecutionStatus.NOT_ATTEMPTED
                or read_observation
                not in {ObservationStatus.NOT_REQUIRED, ObservationStatus.COMPLETE}
            ):
                self._add_finding(
                    Finding(
                        test_id=test.id,
                        category="session_isolation",
                        title="Independent MCP clients do not share session state",
                        status=FindingStatus.ERROR,
                        severity=Severity.MEDIUM,
                        expected={"reader_contains_writer_marker": False},
                        observed={
                            "marker_leaked": False,
                            "writer_probe_executed": True,
                            "writer_execution": write_invocation.execution.value,
                            "writer_effects": _event_dicts(write_effects),
                            "writer_observer_errors": write_observer_errors,
                            "reader_probe_executed": (
                                read_invocation.execution != ExecutionStatus.NOT_ATTEMPTED
                            ),
                            "reader_execution": read_invocation.execution.value,
                            "reader_error": read_invocation.error,
                            "reader_effects": _event_dicts(read_effects),
                            "reader_observer_errors": read_observer_errors,
                        },
                        evidence={"trace": self._trace_reference()},
                        observation=session_observation,
                    )
                )
                continue

            status = (
                FindingStatus.FAILED
                if leaked
                else FindingStatus.ERROR
                if errored
                else FindingStatus.PASSED
            )

            self._add_finding(
                Finding(
                    test_id=test.id,
                    category="session_isolation",
                    title="Independent MCP clients do not share session state",
                    status=status,
                    severity=test.severity
                    if leaked
                    else Severity.MEDIUM
                    if errored
                    else Severity.INFO,
                    expected={"reader_contains_writer_marker": False},
                    observed={
                        "marker_leaked": leaked,
                        "writer_allowed": write_invocation.allowed,
                        "reader_allowed": read_invocation.allowed,
                        "writer_execution": write_invocation.execution.value,
                        "reader_execution": read_invocation.execution.value,
                        "writer_error": write_invocation.error,
                        "reader_error": read_invocation.error,
                        "reader_response": read_invocation.response,
                        "writer_effects": _event_dicts(write_effects),
                        "reader_effects": _event_dicts(read_effects),
                        "writer_observer_errors": write_observer_errors,
                        "reader_observer_errors": read_observer_errors,
                    },
                    evidence={"trace": self._trace_reference()},
                    observation=session_observation,
                    remediation=(
                        "Key mutable state by authenticated principal and MCP session, "
                        "and clear it when sessions terminate."
                        if leaked
                        else None
                    ),
                )
            )

    async def _check_replay_protection(self) -> None:
        for tool_name, tool in self.contract.tools.items():
            probe = tool.replay_probe
            if probe is None:
                continue

            test_id = f"REPLAY-{tool_name}".upper().replace("_", "-")
            replay_enabled = self.contract.safety.destructive_tests and (
                self.lab_mode or not self.contract.safety.require_lab_mode
            )
            if not replay_enabled:
                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="replay",
                        title=f"Duplicate execution protection for {tool_name}",
                        status=FindingStatus.SKIPPED,
                        severity=Severity.INFO,
                        expected="explicit lab mode and destructive_tests=true",
                        observed="test was not enabled",
                    )
                )
                continue

            identity_name = tool.side_effect_identity or _first(tool.permitted_identities)
            if not identity_name:
                continue
            identity = self.contract.identities[identity_name]
            if not self.observers:
                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="replay",
                        title=f"Duplicate execution protection for {tool_name}",
                        status=FindingStatus.ERROR,
                        severity=Severity.MEDIUM,
                        expected="at least one configured effect observer",
                        observed="no effect observers were configured",
                        observation=ObservationStatus.UNAVAILABLE,
                    )
                )
                continue

            required_kinds = _required_effect_kinds(tool) | {probe.event_kind}
            preflight_allowed, configured_observation, required_kinds = self._tool_call_preflight(
                tool,
                required_kinds=required_kinds,
            )
            if not preflight_allowed:
                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="replay",
                        title=f"Duplicate execution protection for {tool_name} could not be checked",
                        status=FindingStatus.ERROR,
                        severity=Severity.MEDIUM,
                        expected="configured effect coverage for replay and tool claims",
                        observed={
                            "probe_executed": False,
                            "required_effects": sorted(item.value for item in required_kinds),
                        },
                        observation=configured_observation,
                    )
                )
                continue

            scope = self._new_observation_scope(test_id, probe.attempts)
            async with observer_ownership(self.observers):
                begin_errors = await self._begin_observers()
                begin_observation = self._observer_coverage(begin_errors, required_kinds)
                if begin_observation != ObservationStatus.COMPLETE:
                    self._add_finding(
                        Finding(
                            test_id=test_id,
                            category="replay",
                            title=(
                                f"Duplicate execution protection for {tool_name} could not be checked"
                            ),
                            status=FindingStatus.ERROR,
                            severity=Severity.MEDIUM,
                            expected="working effect observers before replay begins",
                            observed={"probe_executed": False, "observer_errors": begin_errors},
                            observation=begin_observation,
                        )
                    )
                    continue
                invocations = await asyncio.gather(
                    *[
                        self._invoke_for_operation(
                            operation_id,
                            test_id,
                            identity_name,
                            identity,
                            tool_name,
                            probe.arguments,
                        )
                        for operation_id in scope.operation_ids
                    ]
                )
                events, observation, observer_errors = await self._collect_observers(
                    begin_errors,
                    required_kinds,
                    scope,
                )
            policy_required_kinds = _required_effect_kinds(tool)
            policy_observation = (
                self._observer_coverage(observer_errors, policy_required_kinds)
                if policy_required_kinds
                else ObservationStatus.NOT_REQUIRED
            )
            violations = _side_effect_violations(tool, events)
            if violations or (
                policy_required_kinds and policy_observation != ObservationStatus.COMPLETE
            ):
                self._add_finding(
                    Finding(
                        test_id=f"{test_id}-EFFECTS",
                        category="runtime_behaviour",
                        title=f"Mutation effects for {tool_name} during {test_id}",
                        status=(FindingStatus.FAILED if violations else FindingStatus.ERROR),
                        severity=(Severity.HIGH if violations else Severity.MEDIUM),
                        expected={
                            "required_effects": sorted(
                                item.value for item in policy_required_kinds
                            ),
                            "forbidden_side_effects": [
                                item.value for item in tool.forbidden_side_effects
                            ],
                            "allowed_network_destinations": tool.allowed_network_destinations,
                            "allowed_filesystem_writes": tool.allowed_filesystem_writes,
                            "allowed_process_commands": tool.allowed_process_commands,
                        },
                        observed={
                            "events": _event_dicts(events),
                            "violations": violations,
                            "observer_errors": observer_errors,
                        },
                        evidence={"trace": self._trace_reference()},
                        observation=observation,
                        remediation=(
                            "Remove undeclared effects or tighten the approved mutation boundary."
                            if violations
                            else None
                        ),
                    )
                )

            event_tool = probe.event_tool or tool_name
            matching = [
                event
                for event in events
                if event.kind == probe.event_kind and event.details.get("tool") == event_tool
            ]
            duplicate = len(matching) > probe.maximum_events
            successful = sum(item.allowed is True for item in invocations)
            status = (
                FindingStatus.FAILED
                if duplicate
                else FindingStatus.ERROR
                if successful == 0
                or len(matching) < probe.minimum_events
                or observation != ObservationStatus.COMPLETE
                else FindingStatus.PASSED
            )
            self._add_finding(
                Finding(
                    test_id=test_id,
                    category="replay",
                    title=f"{tool_name} is idempotent under concurrent duplicate requests",
                    status=status,
                    severity=Severity.HIGH
                    if duplicate
                    else Severity.MEDIUM
                    if status == FindingStatus.ERROR
                    else Severity.INFO,
                    expected={
                        "minimum_side_effects": probe.minimum_events,
                        "maximum_side_effects": probe.maximum_events,
                    },
                    observed={
                        "attempts": probe.attempts,
                        "successful_calls": successful,
                        "matching_side_effects": len(matching),
                        "events": _event_dicts(matching),
                        "observer_errors": observer_errors,
                    },
                    evidence={"trace": self._trace_reference()},
                    observation=observation,
                    remediation=(
                        "Require a server-side idempotency key and atomically record it with the state change."
                        if duplicate
                        else None
                    ),
                )
            )

    def _tool_call_preflight(
        self,
        tool: ToolContract,
        *,
        required_kinds: set[SideEffectKind] | None = None,
    ) -> tuple[bool, ObservationStatus, set[SideEffectKind]]:
        if not self._tool_invocation_enabled(tool):
            return False, ObservationStatus.NOT_REQUIRED, set()

        effective_required = (
            (set() if tool.read_only else _required_effect_kinds(tool))
            if required_kinds is None
            else set(required_kinds)
        )
        if not effective_required:
            return True, ObservationStatus.NOT_REQUIRED, effective_required

        coverage = self._observer_coverage({}, effective_required)
        return coverage == ObservationStatus.COMPLETE, coverage, effective_required

    def _tool_invocation_enabled(self, tool: ToolContract) -> bool:
        if tool.read_only:
            return True
        if not self.contract.safety.destructive_tests:
            return False
        return self.lab_mode or not self.contract.safety.require_lab_mode

    def _lab_skip(self, test_id: str, category: str, tool_name: str) -> Finding:
        return Finding(
            test_id=test_id,
            category=category,
            title=f"State-changing probe for {tool_name} requires lab mode",
            status=FindingStatus.SKIPPED,
            severity=Severity.INFO,
            expected="contract safety.destructive_tests=true and CLI --lab-mode",
            observed="probe was not executed",
        )

    async def _invoke_with_mutation_observation(
        self,
        test_id: str,
        identity_name: str,
        identity: IdentitySpec,
        tool: str,
        arguments: dict[str, Any],
    ) -> tuple[
        InvocationRecord,
        list[SideEffectEvent],
        ObservationStatus,
        dict[str, str],
    ]:
        tool_contract = self.contract.tools.get(tool)
        if tool_contract is None or tool_contract.read_only:
            invocation = await self._invoke(
                test_id,
                identity_name,
                identity,
                tool,
                arguments,
            )
            return invocation, [], ObservationStatus.NOT_REQUIRED, {}

        required_kinds = _required_effect_kinds(tool_contract)
        if not required_kinds:
            invocation = await self._invoke(
                test_id,
                identity_name,
                identity,
                tool,
                arguments,
            )
            return invocation, [], ObservationStatus.NOT_REQUIRED, {}

        scope = self._new_observation_scope(test_id)
        async with observer_ownership(self.observers):
            begin_errors = await self._begin_observers()
            begin_observation = self._observer_coverage(begin_errors, required_kinds)
            if begin_observation != ObservationStatus.COMPLETE:
                invocation = InvocationRecord(
                    test_id=test_id,
                    tool=tool,
                    identity=identity_name,
                    arguments=dict(arguments),
                    allowed=None,
                    authorization=AuthorizationStatus.NOT_APPLICABLE,
                    execution=ExecutionStatus.NOT_ATTEMPTED,
                    error=(
                        "not attempted: required side-effect observation was "
                        f"{begin_observation.value}"
                    ),
                    duration_ms=0,
                )
                self._record_invocation(invocation)
                return invocation, [], begin_observation, begin_errors

            invocation = await self._invoke_for_operation(
                scope.operation_ids[0],
                test_id,
                identity_name,
                identity,
                tool,
                arguments,
            )
            events, observation, observer_errors = await self._collect_observers(
                begin_errors,
                required_kinds,
                scope,
            )

        violations = _side_effect_violations(tool_contract, events)
        if violations or observation != ObservationStatus.COMPLETE:
            self._add_finding(
                Finding(
                    test_id=f"{test_id}-EFFECTS",
                    category="runtime_behaviour",
                    title=f"Mutation effects for {tool} during {test_id}",
                    status=(FindingStatus.FAILED if violations else FindingStatus.ERROR),
                    severity=(Severity.HIGH if violations else Severity.MEDIUM),
                    expected={
                        "required_effects": sorted(item.value for item in required_kinds),
                        "forbidden_side_effects": [
                            item.value for item in tool_contract.forbidden_side_effects
                        ],
                        "allowed_network_destinations": (
                            tool_contract.allowed_network_destinations
                        ),
                        "allowed_filesystem_writes": (tool_contract.allowed_filesystem_writes),
                        "allowed_process_commands": (tool_contract.allowed_process_commands),
                    },
                    observed={
                        "events": _event_dicts(events),
                        "violations": violations,
                        "observer_errors": observer_errors,
                    },
                    evidence={"trace": self._trace_reference()},
                    observation=observation,
                    remediation=(
                        "Remove undeclared effects or tighten the approved mutation boundary."
                        if violations
                        else None
                    ),
                )
            )

        return invocation, events, observation, observer_errors

    def _new_observation_scope(
        self,
        test_id: str,
        operation_count: int = 1,
    ) -> ObservationScope:
        return ObservationScope(
            run_id=self.run_id,
            check_id=test_id,
            window_id=uuid.uuid4().hex,
            operation_ids=tuple(uuid.uuid4().hex for _ in range(operation_count)),
        )

    async def _invoke_for_operation(
        self,
        operation_id: str,
        test_id: str,
        identity_name: str,
        identity: IdentitySpec,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        token = self._current_operation_id.set(operation_id)
        try:
            return await self._invoke(
                test_id,
                identity_name,
                identity,
                tool,
                arguments,
            )
        finally:
            self._current_operation_id.reset(token)

    async def _invoke(
        self,
        test_id: str,
        identity_name: str,
        identity: IdentitySpec,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        client = McpClient(self.contract.server, identity_name, identity)
        markers = (
            self.contract.tools[tool].denial_error_markers if tool in self.contract.tools else []
        )
        operation_id = self._current_operation_id.get()
        if operation_id is not None and correlation_enabled(self.observers):
            invocation = await client.invoke(
                test_id,
                tool,
                arguments,
                denial_error_markers=markers,
                meta=build_correlation_meta(self.run_id, operation_id),
            )
        else:
            invocation = await client.invoke(
                test_id,
                tool,
                arguments,
                denial_error_markers=markers,
            )
        if operation_id is not None and correlation_enabled(self.observers):
            invocation = invocation.model_copy(
                update={
                    "error": redact(
                        invocation.error,
                        set(self._secrets) | correlation_redaction_values(operation_id),
                    )
                }
            )

        self._record_invocation(invocation)
        return invocation

    def _record_invocation(self, invocation: InvocationRecord) -> None:
        export_secrets = set(self._secrets)
        operation_id = self._current_operation_id.get()
        if operation_id is not None and correlation_enabled(self.observers):
            export_secrets.update(correlation_redaction_values(operation_id))

        exported = invocation.model_copy(
            update={
                "arguments": {"names": sorted(invocation.arguments), "values": "[omitted]"},
                "response": "[omitted from exported evidence]",
                "error": redact(invocation.error, export_secrets),
                "session_id": None,
            }
        )
        self.invocations.append(exported)
        self.store.add_invocation(self.run_id, exported)
        with self.trace_path.open("a", encoding="utf-8") as handle:
            handle.write(exported.model_dump_json() + "\n")

    async def _begin_observers(self) -> dict[str, str]:
        outcomes = await asyncio.gather(
            *(observer.begin() for observer in self.observers), return_exceptions=True
        )
        for outcome in outcomes:
            if isinstance(outcome, asyncio.CancelledError):
                raise outcome
        return {
            observer.name: f"begin: {type(outcome).__name__}: {outcome}"
            for observer, outcome in zip(self.observers, outcomes, strict=True)
            if isinstance(outcome, BaseException)
        }

    def _observer_coverage(
        self,
        errors: dict[str, str],
        required_kinds: set[SideEffectKind] | None = None,
    ) -> ObservationStatus:
        healthy = [observer for observer in self.observers if observer.name not in errors]
        if not healthy:
            return ObservationStatus.UNAVAILABLE

        def complete_kinds(observer: Observer) -> set[SideEffectKind]:
            declared = getattr(observer, "complete_observes", None)
            if declared is None:
                # Backward-compatible for internal test doubles; all production
                # observers declare completeness explicitly.
                return set(getattr(observer, "observes", set()))
            return set(declared)

        if required_kinds is None:
            has_partial_only_coverage = any(
                set(getattr(observer, "observes", set())) - complete_kinds(observer)
                for observer in healthy
            )
            return (
                ObservationStatus.PARTIAL
                if errors or has_partial_only_coverage
                else ObservationStatus.COMPLETE
            )

        complete_covered: set[SideEffectKind] = set()
        for observer in healthy:
            complete_covered.update(complete_kinds(observer))

        return (
            ObservationStatus.COMPLETE
            if required_kinds.issubset(complete_covered)
            else ObservationStatus.PARTIAL
        )

    async def _collect_observers(
        self,
        begin_errors: dict[str, str],
        required_kinds: set[SideEffectKind] | None = None,
        scope: ObservationScope | None = None,
    ) -> tuple[list[SideEffectEvent], ObservationStatus, dict[str, str]]:
        healthy = [observer for observer in self.observers if observer.name not in begin_errors]
        outcomes = await asyncio.gather(
            *(observer.collect() for observer in healthy), return_exceptions=True
        )
        errors = dict(begin_errors)
        events: list[SideEffectEvent] = []
        partial_observers: set[str] = set()
        for observer, outcome in zip(healthy, outcomes, strict=True):
            if isinstance(outcome, asyncio.CancelledError):
                raise outcome
            if isinstance(outcome, ObserverCollectionError):
                events.extend(outcome.events)
                partial_observers.add(observer.name)
                errors[observer.name] = f"collect: {type(outcome).__name__}: {outcome}"
            elif isinstance(outcome, BaseException):
                errors[observer.name] = f"collect: {type(outcome).__name__}: {outcome}"
            else:
                events.extend(outcome)

        coverage = self._observer_coverage(errors, required_kinds)
        if coverage == ObservationStatus.UNAVAILABLE and partial_observers:
            partial_kinds: set[SideEffectKind] = set()
            for observer in healthy:
                if observer.name in partial_observers:
                    partial_kinds.update(getattr(observer, "observes", set()))
            if required_kinds is None or bool(required_kinds & partial_kinds):
                coverage = ObservationStatus.PARTIAL

        if correlation_enabled(self.observers):
            if scope is None:
                names = correlated_observer_names(healthy)
                correlation_errors = {
                    name: "correlation: observation scope is required" for name in names
                }
                events = [event for event in events if event.observer not in names]
            else:
                events, correlation_errors = attribute_correlated_events(
                    events,
                    self.observers,
                    scope,
                )

            if correlation_errors:
                for observer_name, message in correlation_errors.items():
                    existing = errors.get(observer_name)
                    errors[observer_name] = f"{existing}; {message}" if existing else message

                coverage = self._observer_coverage(errors, required_kinds)
                if coverage == ObservationStatus.UNAVAILABLE:
                    affected_partial_kinds: set[SideEffectKind] = set()
                    partial_names = partial_observers | set(correlation_errors)
                    for observer in self.observers:
                        if observer.name in partial_names:
                            affected_partial_kinds.update(getattr(observer, "observes", set()))
                    if required_kinds is None or bool(required_kinds & affected_partial_kinds):
                        coverage = ObservationStatus.PARTIAL

        return events, coverage, errors

    def _add_finding(self, finding: Finding) -> None:
        exported = finding.model_copy(
            update={
                "expected": redact(finding.expected, self._secrets),
                "observed": redact(finding.observed, self._secrets),
                "evidence": redact(finding.evidence, self._secrets),
            }
        )
        self.findings.append(exported)
        self.store.add_finding(self.run_id, exported)

    def _trace_reference(self) -> str:
        return str(self.trace_path.relative_to(self.run_dir))


def _write_json(path: Path, payload: Any, secrets: set[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(redact(payload, secrets), indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )


def _merge_observation_statuses(
    *statuses: ObservationStatus,
) -> ObservationStatus:
    active = [status for status in statuses if status != ObservationStatus.NOT_REQUIRED]
    if not active:
        return ObservationStatus.NOT_REQUIRED
    if ObservationStatus.UNAVAILABLE in active:
        return ObservationStatus.UNAVAILABLE
    if ObservationStatus.PARTIAL in active:
        return ObservationStatus.PARTIAL
    return ObservationStatus.COMPLETE


def _authorization_assessment(
    invocation: InvocationRecord, expected_allowed: bool, positive_control: bool
) -> FindingStatus:
    if expected_allowed:
        if invocation.authorization == AuthorizationStatus.ALLOW:
            return FindingStatus.PASSED
        if invocation.authorization == AuthorizationStatus.DENY:
            return FindingStatus.FAILED
        return FindingStatus.ERROR
    if invocation.authorization == AuthorizationStatus.ALLOW:
        return FindingStatus.FAILED
    if invocation.authorization == AuthorizationStatus.DENY and positive_control:
        return FindingStatus.PASSED
    return FindingStatus.ERROR


def _mcp_sdk_version() -> str | None:
    try:
        return version("mcp")
    except PackageNotFoundError:
        return None


@dataclass(frozen=True)
class EffectClaim:
    mode: Literal["deny_all", "allowlist"]
    patterns: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()


_ALLOWLIST_CLAIMS: dict[SideEffectKind, tuple[str, str, str]] = {
    SideEffectKind.NETWORK_REQUEST: (
        "allowed_network_destinations",
        "destination",
        "network destination is not allowlisted",
    ),
    SideEffectKind.FILESYSTEM_WRITE: (
        "allowed_filesystem_writes",
        "path",
        "filesystem path is not allowlisted",
    ),
    SideEffectKind.PROCESS_EXECUTION: (
        "allowed_process_commands",
        "command",
        "process command is not allowlisted",
    ),
}


def _effect_claims(contract: ToolContract) -> dict[SideEffectKind, EffectClaim]:
    claims: dict[SideEffectKind, EffectClaim] = {}

    def add_deny(kind: SideEffectKind, source: str) -> None:
        existing = claims.get(kind)
        sources = existing.sources if existing is not None else ()
        if source not in sources:
            sources = (*sources, source)
        claims[kind] = EffectClaim(mode="deny_all", sources=sources)

    if contract.read_only:
        for kind in (
            SideEffectKind.FILESYSTEM_WRITE,
            SideEffectKind.DATABASE_WRITE,
            SideEffectKind.PROCESS_EXECUTION,
            SideEffectKind.MESSAGE_DISPATCH,
        ):
            add_deny(kind, "read_only")

    for kind in contract.forbidden_side_effects:
        add_deny(kind, "forbidden_side_effects")

    for kind, (field_name, _detail_key, _reason) in _ALLOWLIST_CLAIMS.items():
        values = getattr(contract, field_name)
        if values is None:
            continue
        if not values:
            add_deny(kind, field_name)
            continue

        existing = claims.get(kind)
        if existing is None:
            claims[kind] = EffectClaim(
                mode="allowlist",
                patterns=tuple(values),
                sources=(field_name,),
            )
        elif field_name not in existing.sources:
            claims[kind] = EffectClaim(
                mode=existing.mode,
                patterns=existing.patterns,
                sources=(*existing.sources, field_name),
            )

    return claims


def _required_effect_kinds(contract: ToolContract) -> set[SideEffectKind]:
    return set(_effect_claims(contract))


def _has_effect_claims(contract: ToolContract) -> bool:
    return bool(_effect_claims(contract))


def _side_effect_violations(
    contract: ToolContract,
    events: list[SideEffectEvent],
) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    claims = _effect_claims(contract)

    for event in events:
        claim = claims.get(event.kind)
        if claim is None:
            continue

        reason: str | None = None
        if claim.mode == "deny_all":
            if "forbidden_side_effects" in claim.sources:
                reason = "side-effect kind is explicitly forbidden"
            elif "read_only" in claim.sources:
                reason = "read-only tool caused a state-changing side effect"
            else:
                rule = _ALLOWLIST_CLAIMS.get(event.kind)
                reason = rule[2] if rule is not None else "side-effect kind is not allowed"
        else:
            rule = _ALLOWLIST_CLAIMS.get(event.kind)
            if rule is None:
                reason = "side-effect kind is not allowed"
            else:
                _field_name, detail_key, mismatch_reason = rule
                observed_value = str(event.details.get(detail_key, ""))
                if not matches_any(observed_value, list(claim.patterns)):
                    reason = mismatch_reason

        if reason:
            violations.append({"reason": reason, "event": asdict(event)})

    return violations


def _path_is_within(value: Any, roots: list[Path]) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        candidate = Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    for root in roots:
        try:
            candidate.relative_to(root.expanduser().resolve(strict=False))
            return True
        except ValueError:
            continue
    return False


def _event_dicts(events: list[SideEffectEvent]) -> list[dict[str, Any]]:
    return [asdict(event) for event in events]


def _first(items: list[str]) -> str | None:
    return items[0] if items else None


def _with_session_header(identity: IdentitySpec, session: str) -> IdentitySpec:
    headers = dict(identity.headers)
    headers["X-Guard-Session"] = session
    return identity.model_copy(update={"headers": headers})
