from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import load_contract, validate_target
from .engine import GuardEngine
from .models import RunSummary
from .reporting import write_reports
from .storage import RunStore


@dataclass(frozen=True)
class RunResult:
    summary: RunSummary
    run_dir: Path
    reports: list[Path]


async def run_contract(
    contract_path: Path | str,
    *,
    output: Path | str = Path("reports"),
    database: Path | str = Path(".guard/guard.db"),
    lab_mode: bool = False,
) -> RunResult:
    """Run the same contract engine used by the CLI, without a shell command."""
    path = Path(contract_path)
    contract = load_contract(path)
    validate_target(contract, lab_mode=lab_mode)

    store = RunStore(Path(database))
    try:
        engine = GuardEngine(contract, path, store, Path(output), lab_mode)
        summary = await engine.run()
        reports = write_reports(summary, engine.run_dir, contract.reports.formats)
        return RunResult(summary=summary, run_dir=engine.run_dir, reports=reports)
    finally:
        store.close()
