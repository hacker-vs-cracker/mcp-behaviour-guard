from __future__ import annotations

from pathlib import Path

import pytest

from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import (
    AuthorizationStatus,
    Contract,
    ExecutionStatus,
    FindingStatus,
    InvocationRecord,
)
from mcp_behaviour_guard.storage import RunStore
from mcp_behaviour_guard.util import utc_now


def _guard(tmp_path: Path, contract_data: dict) -> tuple[GuardEngine, RunStore]:
    contract = Contract.model_validate(contract_data)
    store = RunStore(tmp_path / "guard.db")
    guard = GuardEngine(
        contract,
        tmp_path / "contract.yaml",
        store,
        tmp_path / "reports",
        False,
    )
    guard.run_dir.mkdir(parents=True)
    guard.trace_path.parent.mkdir(parents=True)
    store.start_run(
        guard.run_id,
        contract.server.target_label,
        "contract.yaml",
        "hash",
        utc_now(),
    )
    return guard, store


@pytest.mark.asyncio
async def test_denial_does_not_skip_confidentiality_checks(tmp_path: Path) -> None:
    marker = "SYNTHETIC_PROTECTED_DATA_20260917"
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {"user": {}},
            "tools": {
                "lookup": {
                    "permitted_identities": ["user"],
                    "read_only": True,
                    "policy_probes": [
                        {
                            "id": "POLICY-DENIAL-CONFIDENTIALITY",
                            "identity": "user",
                            "arguments": {"tenant": "other"},
                            "checks": [
                                {"type": "denied"},
                                {
                                    "type": "response_not_contains",
                                    "values": [marker],
                                },
                            ],
                        }
                    ],
                }
            },
        },
    )
    guard._positive_controls["lookup"] = True

    async def denied_with_data(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del identity, arguments
        return InvocationRecord(
            test_id=test_id,
            tool=tool,
            identity=identity_name,
            arguments={},
            allowed=False,
            authorization=AuthorizationStatus.DENY,
            execution=ExecutionStatus.REJECTED,
            response={
                "error": "access denied",
                "protected_data": marker,
            },
            error="tool returned isError=true",
            duration_ms=0,
        )

    guard._invoke = denied_with_data  # type: ignore[method-assign]

    try:
        await guard._check_policy_probes()
        finding = next(
            item for item in guard.findings if item.test_id == "POLICY-DENIAL-CONFIDENTIALITY"
        )
        assert finding.status == FindingStatus.FAILED
        assert any(
            item.get("check") == "response_not_contains" for item in finding.observed["violations"]
        )
    finally:
        store.close()


@pytest.mark.asyncio
async def test_tenant_denial_requires_same_identity_positive_control(
    tmp_path: Path,
) -> None:
    guard, store = _guard(
        tmp_path,
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {
                "admin": {},
                "user": {"tenant": "tenant-a"},
            },
            "tools": {
                "lookup": {
                    "permitted_identities": ["admin", "user"],
                    "read_only": True,
                    "probe_arguments": {"tenant": "tenant-a"},
                    "tenant_probes": {
                        "user": {
                            "arguments": {"tenant": "tenant-b"},
                            "expected_tenant": "tenant-a",
                            "require_denial": True,
                        }
                    },
                }
            },
        },
    )

    async def identity_specific_result(
        test_id,
        identity_name,
        identity,
        tool,
        arguments,
    ):
        del identity, arguments
        if test_id == "AUTH-LOOKUP-ADMIN":
            return InvocationRecord(
                test_id=test_id,
                tool=tool,
                identity=identity_name,
                arguments={},
                allowed=True,
                authorization=AuthorizationStatus.ALLOW,
                execution=ExecutionStatus.SUCCEEDED,
                response={"tenant": "tenant-a"},
                duration_ms=0,
            )
        if test_id == "AUTH-LOOKUP-USER":
            return InvocationRecord(
                test_id=test_id,
                tool=tool,
                identity=identity_name,
                arguments={},
                allowed=None,
                authorization=AuthorizationStatus.UNKNOWN,
                execution=ExecutionStatus.FAILED,
                error="user positive control failed",
                duration_ms=0,
            )
        return InvocationRecord(
            test_id=test_id,
            tool=tool,
            identity=identity_name,
            arguments={},
            allowed=False,
            authorization=AuthorizationStatus.DENY,
            execution=ExecutionStatus.REJECTED,
            response={"error": "access denied"},
            error="tool returned isError=true",
            duration_ms=0,
        )

    guard._invoke = identity_specific_result  # type: ignore[method-assign]

    try:
        await guard._check_access_matrix()
        await guard._check_tenant_isolation()
        finding = next(item for item in guard.findings if item.test_id == "TENANT-LOOKUP-USER")
        assert finding.status == FindingStatus.ERROR
        assert finding.observed["positive_control"] is False
    finally:
        store.close()
