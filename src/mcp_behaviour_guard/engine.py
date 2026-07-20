from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .client import McpClient
from .models import (
    Contract,
    DeniedCheck,
    Finding,
    FindingStatus,
    IdentitySpec,
    InvocationRecord,
    PathWithinCheck,
    ResponseNotContainsCheck,
    ResponseNotContainsEnvCheck,
    RunSummary,
    Severity,
    SideEffectKind,
    ToolContract,
)
from .observers import Observer, SideEffectEvent, build_observer
from .storage import RunStore
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

    async def run(self) -> RunSummary:
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
        )
        self.store.finish_run(summary)
        return summary

    async def _discover_tools(self) -> list[dict[str, Any]]:
        last_error: Exception | None = None
        for identity_name, identity in self.contract.identities.items():
            try:
                client = McpClient(self.contract.server, identity_name, identity)
                tools = await client.list_tools()
                (self.run_dir / "tool-inventory.json").write_text(
                    json.dumps(tools, indent=2, sort_keys=True), encoding="utf-8"
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
                expected="at least one identity can initialize and list tools",
                observed=message,
                remediation="Check the MCP URL, authentication headers, TLS settings and server logs.",
            )
        )
        return []

    async def _check_inventory(self, discovered: list[dict[str, Any]]) -> None:
        actual: set[str] = {
            str(item["name"]) for item in discovered if isinstance(item.get("name"), str)
        }
        expected = set(self.contract.tools)
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        status = FindingStatus.PASSED if not missing and not unexpected else FindingStatus.FAILED
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
            for identity_name, identity in self.contract.identities.items():
                test_id = f"AUTH-{tool_name}-{identity_name}".upper().replace("_", "-")
                invocation = await self._invoke(
                    test_id,
                    identity_name,
                    identity,
                    tool_name,
                    tool.probe_arguments,
                )
                expected_allowed = identity_name in tool.permitted_identities
                passed = invocation.allowed == expected_allowed
                severity = (
                    Severity.CRITICAL
                    if invocation.allowed and not expected_allowed
                    else Severity.HIGH
                )
                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="authorization",
                        title=f"{identity_name} access to {tool_name} follows the contract",
                        status=FindingStatus.PASSED if passed else FindingStatus.FAILED,
                        severity=Severity.INFO if passed else severity,
                        expected={"allowed": expected_allowed},
                        observed={
                            "allowed": invocation.allowed,
                            "error": invocation.error,
                            "response": invocation.response,
                        },
                        evidence={"trace": self._trace_reference()},
                        remediation=(
                            "Enforce authorization at the server boundary and again inside sensitive tool handlers."
                            if not passed
                            else None
                        ),
                    )
                )

    async def _check_tool_side_effects(self) -> None:
        if not self.observers:
            return

        for tool_name, tool in self.contract.tools.items():
            test_id = f"BEHAVIOUR-{tool_name}".upper().replace("_", "-")
            if not self._tool_invocation_enabled(tool):
                self._add_finding(self._lab_skip(test_id, "runtime_behaviour", tool_name))
                continue
            identity_name = tool.side_effect_identity or _first(tool.permitted_identities)
            if not identity_name:
                continue
            identity = self.contract.identities[identity_name]

            await self._begin_observers()
            invocation = await self._invoke(
                test_id,
                identity_name,
                identity,
                tool_name,
                tool.probe_arguments,
            )
            events = await self._collect_observers()
            violations = _side_effect_violations(tool, events)

            if not invocation.allowed:
                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="runtime_behaviour",
                        title=f"Runtime side effects for {tool_name} were observed",
                        status=FindingStatus.ERROR,
                        severity=Severity.MEDIUM,
                        expected="a successful probe call",
                        observed={"error": invocation.error, "events": _event_dicts(events)},
                        evidence={"trace": self._trace_reference()},
                    )
                )
                continue

            passed = not violations
            self._add_finding(
                Finding(
                    test_id=test_id,
                    category="runtime_behaviour",
                    title=f"{tool_name} performs only declared side effects",
                    status=FindingStatus.PASSED if passed else FindingStatus.FAILED,
                    severity=Severity.INFO if passed else Severity.HIGH,
                    expected={
                        "read_only": tool.read_only,
                        "allowed_network_destinations": tool.allowed_network_destinations,
                        "allowed_filesystem_writes": tool.allowed_filesystem_writes,
                        "forbidden_side_effects": [x.value for x in tool.forbidden_side_effects],
                    },
                    observed={"events": _event_dicts(events), "violations": violations},
                    evidence={"trace": self._trace_reference()},
                    remediation=(
                        "Remove undeclared actions or explicitly constrain and document the required destinations and paths."
                        if not passed
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
                invocation = await self._invoke(
                    test_id,
                    identity_name,
                    identity,
                    tool_name,
                    probe.arguments,
                )
                observed_tenant = get_path(invocation.response, probe.resource_tenant_path)
                expected_tenant = probe.expected_tenant or identity.tenant

                violation = invocation.allowed and (
                    probe.require_denial
                    or (expected_tenant is not None and observed_tenant != expected_tenant)
                )
                self._add_finding(
                    Finding(
                        test_id=test_id,
                        category="tenant_isolation",
                        title=f"{tool_name} enforces the {identity_name} tenant boundary",
                        status=FindingStatus.FAILED if violation else FindingStatus.PASSED,
                        severity=Severity.CRITICAL if violation else Severity.INFO,
                        expected={
                            "denied": probe.require_denial,
                            "resource_tenant": expected_tenant,
                        },
                        observed={
                            "allowed": invocation.allowed,
                            "resource_tenant": observed_tenant,
                            "response": invocation.response,
                            "error": invocation.error,
                        },
                        evidence={"trace": self._trace_reference()},
                        remediation=(
                            "Resolve the resource first, then authorize against its owning tenant rather than trusting caller-supplied identifiers."
                            if violation
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
                invocation = await self._invoke(
                    probe.id,
                    probe.identity,
                    identity,
                    tool_name,
                    probe.arguments,
                )
                violations: list[dict[str, Any]] = []
                for check in probe.checks:
                    if isinstance(check, DeniedCheck):
                        if invocation.allowed:
                            violations.append({"check": check.type, "reason": "call was allowed"})
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

                errored = not invocation.allowed and not any(
                    isinstance(check, DeniedCheck) for check in probe.checks
                )
                status = (
                    FindingStatus.ERROR
                    if errored
                    else FindingStatus.FAILED
                    if violations
                    else FindingStatus.PASSED
                )
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
                            "allowed": invocation.allowed,
                            "response": invocation.response,
                            "error": invocation.error,
                            "violations": violations,
                        },
                        evidence={"trace": self._trace_reference()},
                        remediation=(
                            "Validate paths after canonicalisation, minimize inherited environment, and return only contract-approved data."
                            if violations
                            else None
                        ),
                    )
                )

    async def _check_session_isolation(self) -> None:
        for test in self.contract.session_tests:
            write_tool = self.contract.tools[test.write.tool]
            if not self._tool_invocation_enabled(write_tool):
                self._add_finding(self._lab_skip(test.id, "session_isolation", test.write.tool))
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

            write_invocation = await self._invoke(
                f"{test.id}-WRITE",
                test.writer_identity,
                writer,
                test.write.tool,
                write_arguments,
            )
            read_invocation = await self._invoke(
                f"{test.id}-READ",
                test.reader_identity,
                reader,
                test.read.tool,
                test.read.arguments,
            )
            leaked = marker in json.dumps(read_invocation.response, default=str)
            errored = not write_invocation.allowed or not read_invocation.allowed
            status = (
                FindingStatus.ERROR
                if errored
                else FindingStatus.FAILED
                if leaked
                else FindingStatus.PASSED
            )
            self._add_finding(
                Finding(
                    test_id=test.id,
                    category="session_isolation",
                    title="Independent MCP clients do not share session state",
                    status=status,
                    severity=Severity.MEDIUM
                    if errored
                    else test.severity
                    if leaked
                    else Severity.INFO,
                    expected={"reader_contains_writer_marker": False},
                    observed={
                        "marker_leaked": leaked,
                        "writer_allowed": write_invocation.allowed,
                        "reader_allowed": read_invocation.allowed,
                        "reader_response": read_invocation.response,
                    },
                    evidence={"trace": self._trace_reference()},
                    remediation=(
                        "Key mutable state by authenticated principal and MCP session, and clear it when sessions terminate."
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
            await self._begin_observers()
            invocations = await asyncio.gather(
                *[
                    self._invoke(test_id, identity_name, identity, tool_name, probe.arguments)
                    for _ in range(probe.attempts)
                ]
            )
            events = await self._collect_observers()
            event_tool = probe.event_tool or tool_name
            matching = [
                event
                for event in events
                if event.kind == probe.event_kind and event.details.get("tool") == event_tool
            ]
            duplicate = len(matching) > probe.maximum_events
            self._add_finding(
                Finding(
                    test_id=test_id,
                    category="replay",
                    title=f"{tool_name} is idempotent under concurrent duplicate requests",
                    status=FindingStatus.FAILED if duplicate else FindingStatus.PASSED,
                    severity=Severity.HIGH if duplicate else Severity.INFO,
                    expected={"maximum_side_effects": probe.maximum_events},
                    observed={
                        "attempts": probe.attempts,
                        "successful_calls": sum(item.allowed for item in invocations),
                        "matching_side_effects": len(matching),
                        "events": _event_dicts(matching),
                    },
                    evidence={"trace": self._trace_reference()},
                    remediation=(
                        "Require a server-side idempotency key and atomically record it with the state change."
                        if duplicate
                        else None
                    ),
                )
            )

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

    async def _invoke(
        self,
        test_id: str,
        identity_name: str,
        identity: IdentitySpec,
        tool: str,
        arguments: dict[str, Any],
    ) -> InvocationRecord:
        client = McpClient(self.contract.server, identity_name, identity)
        invocation = await client.invoke(test_id, tool, arguments)
        self.invocations.append(invocation)
        self.store.add_invocation(self.run_id, invocation)
        with self.trace_path.open("a", encoding="utf-8") as handle:
            handle.write(invocation.model_dump_json() + "\n")
        return invocation

    async def _begin_observers(self) -> None:
        await asyncio.gather(*(observer.begin() for observer in self.observers))

    async def _collect_observers(self) -> list[SideEffectEvent]:
        batches = await asyncio.gather(*(observer.collect() for observer in self.observers))
        return [event for batch in batches for event in batch]

    def _add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.store.add_finding(self.run_id, finding)

    def _trace_reference(self) -> str:
        return str(self.trace_path.relative_to(self.run_dir))


def _side_effect_violations(
    contract: ToolContract,
    events: list[SideEffectEvent],
) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    state_changing = {
        SideEffectKind.FILESYSTEM_WRITE,
        SideEffectKind.DATABASE_WRITE,
        SideEffectKind.MESSAGE_DISPATCH,
        SideEffectKind.PROCESS_EXECUTION,
    }

    for event in events:
        reason: str | None = None
        if event.kind in contract.forbidden_side_effects:
            reason = "side-effect kind is explicitly forbidden"
        elif contract.read_only and event.kind in state_changing:
            reason = "read-only tool caused a state-changing side effect"
        elif event.kind == SideEffectKind.NETWORK_REQUEST:
            destination = str(event.details.get("destination", ""))
            if not matches_any(destination, contract.allowed_network_destinations):
                reason = "network destination is not allowlisted"
        elif event.kind == SideEffectKind.FILESYSTEM_WRITE:
            path = str(event.details.get("path", ""))
            if not matches_any(path, contract.allowed_filesystem_writes):
                reason = "filesystem path is not allowlisted"
        elif event.kind == SideEffectKind.PROCESS_EXECUTION:
            command = str(event.details.get("command", ""))
            if not matches_any(command, contract.allowed_process_commands):
                reason = "process command is not allowlisted"

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
