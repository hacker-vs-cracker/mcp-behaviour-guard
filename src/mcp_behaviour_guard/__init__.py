"""MCP Behaviour Guard."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runner import RunResult

__version__ = "0.4.0"


async def run_contract(
    contract_path: Path | str,
    *,
    output: Path | str = "reports",
    database: Path | str = ".guard/guard.db",
    lab_mode: bool = False,
) -> RunResult:
    from .runner import run_contract as execute

    return await execute(contract_path, output=output, database=database, lab_mode=lab_mode)
