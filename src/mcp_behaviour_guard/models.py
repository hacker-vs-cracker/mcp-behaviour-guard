from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class AuthorizationStatus(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class ExecutionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_ATTEMPTED = "not_attempted"
    UNKNOWN = "unknown"


class ObservationStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    NOT_REQUIRED = "not_required"


class AssessmentStatus(StrEnum):
    # Bandit B105 false positive: assessment status, not a credential.
    PASS = "pass"  # nosec B105
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"


class SideEffectKind(StrEnum):
    NETWORK_REQUEST = "network_request"
    FILESYSTEM_WRITE = "filesystem_write"
    DATABASE_WRITE = "database_write"
    PROCESS_EXECUTION = "process_execution"
    MESSAGE_DISPATCH = "message_dispatch"
    CREDENTIAL_ACCESS = "credential_access"


class ServerSpec(BaseModel):
    name: str
    transport: Literal["streamable-http", "stdio"] = "streamable-http"
    url: str | None = None
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    cwd: Path | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=15, gt=0, le=300)
    verify_tls: bool = True
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])

    @model_validator(mode="after")
    def transport_fields_are_valid(self) -> ServerSpec:
        if self.transport == "streamable-http" and not self.url:
            raise ValueError("streamable-http servers require server.url")
        if self.transport == "stdio" and not self.command:
            raise ValueError("stdio servers require server.command")
        return self

    @property
    def target_label(self) -> str:
        if self.transport == "streamable-http":
            return self.url or self.name
        command = " ".join([self.command or "", *self.args]).strip()
        return f"stdio:{command}"


class IdentitySpec(BaseModel):
    headers: dict[str, str] = Field(default_factory=dict)
    environment: dict[str, str] = Field(default_factory=dict)
    tenant: str | None = None
    role: str | None = None
    description: str | None = None


class TenantProbe(BaseModel):
    arguments: dict[str, Any]
    resource_tenant_path: str = "tenant"
    expected_tenant: str | None = None
    require_denial: bool = True


class ReplayProbe(BaseModel):
    arguments: dict[str, Any]
    attempts: int = Field(default=3, ge=2, le=20)
    event_kind: SideEffectKind = SideEffectKind.DATABASE_WRITE
    event_tool: str | None = None
    maximum_events: int = Field(default=1, ge=0)
    minimum_events: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def required_effect_is_within_limit(self) -> ReplayProbe:
        if self.minimum_events > self.maximum_events:
            raise ValueError("replay minimum_events cannot exceed maximum_events")
        return self


class DeniedCheck(BaseModel):
    type: Literal["denied"]


class PathWithinCheck(BaseModel):
    type: Literal["path_within"]
    response_path: str
    roots: list[Path]


class ResponseNotContainsEnvCheck(BaseModel):
    type: Literal["response_not_contains_env"]
    env_names: list[str]


class ResponseNotContainsCheck(BaseModel):
    type: Literal["response_not_contains"]
    values: list[str]


PolicyCheck = Annotated[
    DeniedCheck | PathWithinCheck | ResponseNotContainsEnvCheck | ResponseNotContainsCheck,
    Field(discriminator="type"),
]


class PolicyProbe(BaseModel):
    id: str
    identity: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    checks: list[PolicyCheck]
    severity: Severity = Severity.HIGH
    description: str | None = None


class ToolContract(BaseModel):
    description: str | None = None
    permitted_identities: list[str]
    probe_arguments: dict[str, Any] = Field(default_factory=dict)
    denial_error_markers: list[str] = Field(default_factory=list)
    side_effect_identity: str | None = None
    read_only: bool = False
    approval_required: bool = False
    allowed_network_destinations: list[str] = Field(default_factory=list)
    allowed_filesystem_writes: list[str] = Field(default_factory=list)
    allowed_process_commands: list[str] = Field(default_factory=list)
    forbidden_side_effects: list[SideEffectKind] = Field(default_factory=list)
    tenant_probes: dict[str, TenantProbe] = Field(default_factory=dict)
    policy_probes: list[PolicyProbe] = Field(default_factory=list)
    replay_probe: ReplayProbe | None = None

    @field_validator("permitted_identities")
    @classmethod
    def permitted_identities_must_not_repeat(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("permitted_identities contains duplicates")
        return value


class ToolCallSpec(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class SessionIsolationTest(BaseModel):
    id: str
    writer_identity: str
    reader_identity: str
    write: ToolCallSpec
    read: ToolCallSpec
    marker_argument: str
    severity: Severity = Severity.HIGH


class HttpAuditObserverSpec(BaseModel):
    type: Literal["http_audit"]
    events_url: str
    reset_url: str
    timeout_seconds: float = Field(default=5, gt=0, le=60)
    observes: list[SideEffectKind] = Field(default_factory=list)


class FilesystemObserverSpec(BaseModel):
    type: Literal["filesystem"]
    roots: list[Path]
    ignore: list[str] = Field(default_factory=lambda: [".DS_Store", "*.tmp"])
    observes: list[SideEffectKind] = Field(
        default_factory=lambda: [SideEffectKind.FILESYSTEM_WRITE]
    )

    @field_validator("observes")
    @classmethod
    def filesystem_coverage_is_fixed(
        cls,
        value: list[SideEffectKind],
    ) -> list[SideEffectKind]:
        if value != [SideEffectKind.FILESYSTEM_WRITE]:
            raise ValueError("filesystem observers can only observe filesystem_write")
        return value


class JsonlAuditObserverSpec(BaseModel):
    type: Literal["jsonl_audit"]
    path: Path
    truncate_on_begin: bool = True
    observes: list[SideEffectKind] = Field(default_factory=list)


ObserverSpec = HttpAuditObserverSpec | FilesystemObserverSpec | JsonlAuditObserverSpec


class SafetySpec(BaseModel):
    destructive_tests: bool = False
    require_lab_mode: bool = True
    target_allowlist: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allowed_stdio_commands: list[str] = Field(
        default_factory=lambda: ["python", "python3", "uv", "node", "npx", "docker"]
    )


ReportFormat: TypeAlias = Literal["json", "html", "junit", "sarif"]


def _default_report_formats() -> list[ReportFormat]:
    return ["json", "html", "junit", "sarif"]


class ReportSpec(BaseModel):
    formats: list[ReportFormat] = Field(default_factory=_default_report_formats)


class AlertSpec(BaseModel):
    enabled: bool = False
    minimum_severity: Severity = Severity.HIGH
    webhook_url: str | None = None
    only_new: bool = True
    repeat_after_hours: float | None = Field(default=None, gt=0)


class TemporalIntegritySpec(BaseModel):
    enabled: bool = False
    identity: str | None = None
    driver_tool: str | None = None
    driver_arguments: dict[str, Any] = Field(default_factory=dict)
    sessions: int = Field(default=2, ge=1, le=10)
    retests_per_session: int = Field(default=5, ge=1, le=50)
    delay_between_calls_ms: int = Field(default=0, ge=0, le=60000)
    rediscover_after_each_call: bool = True
    stop_on_first_drift: bool = True
    monitor_tools: bool = True
    monitor_prompts: bool = True
    monitor_resources: bool = True
    probe_argumentless_prompts: bool = True
    prompt_probes: dict[str, dict[str, str]] = Field(default_factory=dict)
    severity: Severity = Severity.HIGH


class ContractMetadata(BaseModel):
    generated_draft: bool = False
    generated_at: str | None = None
    notes: list[str] = Field(default_factory=list)


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    metadata: ContractMetadata = Field(default_factory=ContractMetadata)
    server: ServerSpec
    identities: dict[str, IdentitySpec]
    tools: dict[str, ToolContract]
    session_tests: list[SessionIsolationTest] = Field(default_factory=list)
    observers: dict[str, ObserverSpec] = Field(default_factory=dict, discriminator=None)
    safety: SafetySpec = Field(default_factory=SafetySpec)
    reports: ReportSpec = Field(default_factory=ReportSpec)
    alerts: AlertSpec = Field(default_factory=AlertSpec)
    temporal_integrity: TemporalIntegritySpec = Field(default_factory=TemporalIntegritySpec)

    @model_validator(mode="after")
    def references_exist(self) -> Contract:
        identities = set(self.identities)
        tools = set(self.tools)

        for tool_name, tool in self.tools.items():
            missing = set(tool.permitted_identities) - identities
            if missing:
                raise ValueError(
                    f"tool {tool_name!r} references missing identities: {sorted(missing)}"
                )
            if tool.side_effect_identity and tool.side_effect_identity not in identities:
                raise ValueError(f"tool {tool_name!r} has an unknown side_effect_identity")
            missing_probe_identities = set(tool.tenant_probes) - identities
            if missing_probe_identities:
                raise ValueError(
                    f"tool {tool_name!r} has tenant probes for unknown identities: "
                    f"{sorted(missing_probe_identities)}"
                )
            for probe in tool.policy_probes:
                if probe.identity not in identities:
                    raise ValueError(
                        f"tool {tool_name!r} policy probe {probe.id!r} references "
                        f"unknown identity {probe.identity!r}"
                    )

        for test in self.session_tests:
            if test.writer_identity not in identities or test.reader_identity not in identities:
                raise ValueError(f"session test {test.id!r} references an unknown identity")
            if test.write.tool not in tools or test.read.tool not in tools:
                raise ValueError(f"session test {test.id!r} references an unknown tool")

        temporal = self.temporal_integrity
        if temporal.enabled:
            if not temporal.driver_tool:
                raise ValueError("temporal_integrity.enabled requires driver_tool")
            if temporal.driver_tool not in tools:
                raise ValueError(
                    f"temporal_integrity references unknown driver tool {temporal.driver_tool!r}"
                )
            if temporal.identity and temporal.identity not in identities:
                raise ValueError(
                    f"temporal_integrity references unknown identity {temporal.identity!r}"
                )
            driver_contract = self.tools[temporal.driver_tool]
            if not driver_contract.read_only:
                raise ValueError("temporal_integrity driver_tool must be marked read_only: true")
            if temporal.identity and temporal.identity not in driver_contract.permitted_identities:
                raise ValueError(
                    "temporal_integrity identity must be permitted to call the driver tool"
                )
            if not (
                temporal.monitor_tools or temporal.monitor_prompts or temporal.monitor_resources
            ):
                raise ValueError("temporal_integrity must monitor at least one metadata family")

        return self


class InvocationRecord(BaseModel):
    test_id: str
    tool: str
    identity: str
    arguments: dict[str, Any]
    allowed: bool | None
    authorization: AuthorizationStatus = AuthorizationStatus.UNKNOWN
    execution: ExecutionStatus = ExecutionStatus.NOT_ATTEMPTED
    response: Any = None
    error: str | None = None
    duration_ms: float
    session_id: str | None = None
    protocol_version: str | None = None
    transport: str | None = None

    @model_validator(mode="after")
    def preserve_legacy_success_records(self) -> InvocationRecord:
        if self.allowed is True and self.authorization == AuthorizationStatus.UNKNOWN:
            self.authorization = AuthorizationStatus.ALLOW
        if self.allowed is True and self.execution == ExecutionStatus.NOT_ATTEMPTED:
            self.execution = ExecutionStatus.SUCCEEDED
        return self


class Finding(BaseModel):
    test_id: str
    category: str
    title: str
    status: FindingStatus
    severity: Severity
    expected: Any
    observed: Any
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None
    observation: ObservationStatus = ObservationStatus.NOT_REQUIRED


class RunSummary(BaseModel):
    schema_version: int = 2
    run_id: str
    target: str
    contract_path: str
    started_at: str
    finished_at: str
    findings: list[Finding]
    invocations: list[InvocationRecord]
    transport: str | None = None
    sdk_version: str | None = None
    state_strategy: str | None = None

    @property
    def assessment(self) -> AssessmentStatus:
        if any(item.status == FindingStatus.FAILED for item in self.findings):
            return AssessmentStatus.FAIL
        if any(item.status == FindingStatus.ERROR for item in self.findings):
            return AssessmentStatus.INCONCLUSIVE
        if any(item.status == FindingStatus.SKIPPED for item in self.findings):
            return AssessmentStatus.NOT_TESTED
        if not any(item.status == FindingStatus.PASSED for item in self.findings):
            return AssessmentStatus.NOT_TESTED
        return AssessmentStatus.PASS

    @model_serializer(mode="wrap")
    def include_assessment(self, handler: Any) -> dict[str, Any]:
        result: dict[str, Any] = handler(self)
        result["assessment"] = self.assessment.value
        return result

    @property
    def failed(self) -> int:
        return sum(f.status in {FindingStatus.FAILED, FindingStatus.ERROR} for f in self.findings)

    @property
    def passed(self) -> int:
        return sum(f.status == FindingStatus.PASSED for f in self.findings)
