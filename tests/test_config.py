from pathlib import Path

import pytest

from mcp_behaviour_guard.config import ContractError, load_contract

BASE_CONTRACT = """
version: 1
server:
  name: test
  url: http://127.0.0.1:8000/mcp
identities:
  user:
    headers:
      Authorization: Bearer ${TEST_TOKEN}
tools:
  ping:
    permitted_identities: [user]
    probe_arguments: {}
"""


def test_contract_expands_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_TOKEN", "secret-token")
    path = tmp_path / "contract.yaml"
    path.write_text(BASE_CONTRACT, encoding="utf-8")

    contract = load_contract(path)

    assert contract.identities["user"].headers["Authorization"] == "Bearer secret-token"


def test_contract_rejects_missing_environment(tmp_path: Path) -> None:
    path = tmp_path / "contract.yaml"
    path.write_text(BASE_CONTRACT, encoding="utf-8")

    with pytest.raises(ContractError, match="TEST_TOKEN"):
        load_contract(path)


def test_contract_rejects_unknown_identity(tmp_path: Path) -> None:
    path = tmp_path / "contract.yaml"
    path.write_text(
        BASE_CONTRACT.replace("[user]", "[administrator]").replace("${TEST_TOKEN}", "token"),
        encoding="utf-8",
    )

    with pytest.raises(ContractError, match="missing identities"):
        load_contract(path)
