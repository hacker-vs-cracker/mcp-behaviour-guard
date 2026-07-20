from pathlib import Path

from mcp_behaviour_guard.engine import GuardEngine
from mcp_behaviour_guard.models import Contract
from mcp_behaviour_guard.storage import RunStore


def _contract() -> Contract:
    return Contract.model_validate(
        {
            "version": 1,
            "server": {"name": "test", "url": "http://127.0.0.1:8000/mcp"},
            "identities": {"user": {}},
            "tools": {
                "lookup": {
                    "permitted_identities": ["user"],
                    "read_only": True,
                },
                "update": {
                    "permitted_identities": ["user"],
                    "read_only": False,
                },
            },
            "safety": {
                "destructive_tests": True,
                "require_lab_mode": True,
            },
        }
    )


def test_state_changing_tool_requires_lab_mode(tmp_path: Path) -> None:
    contract = _contract()
    store = RunStore(tmp_path / "guard.db")
    try:
        normal = GuardEngine(contract, Path("contract.yaml"), store, tmp_path, lab_mode=False)
        lab = GuardEngine(contract, Path("contract.yaml"), store, tmp_path, lab_mode=True)

        assert normal._tool_invocation_enabled(contract.tools["lookup"])
        assert not normal._tool_invocation_enabled(contract.tools["update"])
        assert lab._tool_invocation_enabled(contract.tools["update"])
    finally:
        store.close()
