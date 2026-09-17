from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_behaviour_guard.config import ContractError, load_contract
from mcp_behaviour_guard.models import Contract


def _base_contract() -> dict:
    return {
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
            }
        },
    }


def test_nested_contract_typo_is_rejected() -> None:
    data = _base_contract()
    data["tools"]["lookup"]["read_onyl"] = True

    with pytest.raises(ValidationError):
        Contract.model_validate(data)


def test_duplicate_yaml_mapping_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text(
        "version: 1\n"
        "server:\n"
        "  name: offline\n"
        "  url: http://127.0.0.1:8000/mcp\n"
        "identities:\n"
        "  user: {}\n"
        "tools:\n"
        "  lookup:\n"
        "    permitted_identities: [user]\n"
        "    read_only: true\n"
        "    read_only: false\n",
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="duplicate"):
        load_contract(path)


def test_strict_validation_error_does_not_echo_expanded_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "DUMMY_R8_SECRET_DO_NOT_EXPORT_20260917"
    monkeypatch.setenv("MCPBG_R8_SECRET", marker)
    path = tmp_path / "secret-extra-field.yaml"
    path.write_text(
        "version: 1\n"
        "server:\n"
        "  name: offline\n"
        "  url: http://127.0.0.1:8000/mcp\n"
        "identities:\n"
        "  user: {}\n"
        "tools:\n"
        "  lookup:\n"
        "    permitted_identities: [user]\n"
        "    read_only: true\n"
        '    read_onyl: "${MCPBG_R8_SECRET}"\n',
        encoding="utf-8",
    )

    with pytest.raises(ContractError) as exc_info:
        load_contract(path)

    message = str(exc_info.value)
    assert "read_onyl" in message
    assert marker not in message


def test_arbitrary_argument_and_header_payload_keys_remain_supported() -> None:
    contract = Contract.model_validate(
        {
            "version": 1,
            "server": {
                "name": "offline",
                "url": "http://127.0.0.1:8000/mcp",
            },
            "identities": {
                "user": {
                    "headers": {
                        "X-Arbitrary-Header": "value",
                    }
                }
            },
            "tools": {
                "lookup": {
                    "permitted_identities": ["user"],
                    "probe_arguments": {
                        "customer": {
                            "arbitrary_nested_key": "value",
                        }
                    },
                }
            },
        }
    )

    assert contract.tools["lookup"].probe_arguments["customer"]["arbitrary_nested_key"] == "value"
    assert contract.identities["user"].headers["X-Arbitrary-Header"] == "value"
