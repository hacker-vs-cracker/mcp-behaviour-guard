from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_behaviour_guard.models import Contract


def _base_contract() -> dict[str, object]:
    return {
        "version": 1,
        "server": {
            "name": "local-demo",
            "transport": "stdio",
            "command": "python",
        },
        "identities": {"reviewer": {"role": "security_tester"}},
        "tools": {
            "format_text": {
                "permitted_identities": ["reviewer"],
                "probe_arguments": {"text": "demo"},
                "read_only": True,
            }
        },
    }


def test_temporal_integrity_requires_a_known_driver_tool() -> None:
    payload = _base_contract()
    payload["temporal_integrity"] = {
        "enabled": True,
        "driver_tool": "missing_tool",
    }

    with pytest.raises(ValidationError, match="unknown driver tool"):
        Contract.model_validate(payload)


def test_temporal_integrity_retest_count_is_bounded() -> None:
    payload = _base_contract()
    payload["temporal_integrity"] = {
        "enabled": True,
        "identity": "reviewer",
        "driver_tool": "format_text",
        "retests_per_session": 51,
    }

    with pytest.raises(ValidationError, match="less than or equal to 50"):
        Contract.model_validate(payload)


def test_temporal_integrity_rejects_state_changing_driver() -> None:
    payload = _base_contract()
    payload["tools"]["format_text"]["read_only"] = False  # type: ignore[index]
    payload["temporal_integrity"] = {
        "enabled": True,
        "identity": "reviewer",
        "driver_tool": "format_text",
    }

    with pytest.raises(ValidationError, match="must be marked read_only"):
        Contract.model_validate(payload)


def test_temporal_integrity_accepts_a_reviewed_safe_driver() -> None:
    payload = _base_contract()
    payload["temporal_integrity"] = {
        "enabled": True,
        "identity": "reviewer",
        "driver_tool": "format_text",
        "driver_arguments": {"text": "canary"},
        "sessions": 3,
        "retests_per_session": 7,
        "monitor_tools": True,
        "monitor_prompts": False,
        "monitor_resources": False,
    }

    contract = Contract.model_validate(payload)

    assert contract.temporal_integrity.retests_per_session == 7
    assert contract.temporal_integrity.sessions == 3


def test_temporal_identity_must_be_allowed_to_use_driver() -> None:
    payload = _base_contract()
    payload["identities"]["outsider"] = {"role": "guest"}  # type: ignore[index]
    payload["temporal_integrity"] = {
        "enabled": True,
        "identity": "outsider",
        "driver_tool": "format_text",
    }

    with pytest.raises(ValidationError, match="must be permitted"):
        Contract.model_validate(payload)
