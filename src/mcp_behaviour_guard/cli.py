from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path
from typing import Literal

import httpx
import typer
from rich.console import Console
from rich.table import Table

from .ai import OllamaAdvisor, write_suggestions
from .alerts import send_alerts
from .baseline import capture_baseline, compare_baselines, load_baseline, write_baseline
from .client import McpClient
from .config import ContractError, load_contract, validate_target
from .contract_tools import (
    contract_placeholders,
    expand_tenants,
    generate_contract_draft,
    parse_key_value,
    write_yaml,
)
from .engine import GuardEngine
from .models import IdentitySpec, RunSummary, ServerSpec, Severity
from .reporting import finding_sort_key, write_reports
from .storage import RunStore

app = typer.Typer(no_args_is_help=True, help="Deterministic MCP security contract testing.")
baseline_app = typer.Typer(no_args_is_help=True, help="Capture and compare behaviour baselines.")
ai_app = typer.Typer(no_args_is_help=True, help="Optional local-AI test suggestions.")
contract_app = typer.Typer(no_args_is_help=True, help="Generate and compile security contracts.")
app.add_typer(baseline_app, name="baseline")
app.add_typer(ai_app, name="ai")
app.add_typer(contract_app, name="contract")
console = Console()


@app.command()
def run(
    contract_path: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Option(Path("reports"), "--output", "-o"),
    database: Path = typer.Option(Path(".guard/guard.db"), "--database"),
    lab_mode: bool = typer.Option(False, "--lab-mode", help="Enable declared replay tests."),
    no_fail: bool = typer.Option(False, "--no-fail", help="Always exit with code zero."),
) -> None:
    """Run the security contract against an MCP server."""
    summary, run_dir, report_paths = _execute_contract(
        contract_path=contract_path,
        output=output,
        database=database,
        lab_mode=lab_mode,
    )
    _print_summary(summary, run_dir, report_paths)
    if summary.failed and not no_fail:
        raise typer.Exit(1)


@app.command()
def monitor(
    contract_path: Path = typer.Argument(..., exists=True, readable=True),
    interval_seconds: int = typer.Option(3600, "--interval", min=60),
    output: Path = typer.Option(Path("reports"), "--output", "-o"),
    database: Path = typer.Option(Path(".guard/guard.db"), "--database"),
    lab_mode: bool = typer.Option(False, "--lab-mode"),
    once: bool = typer.Option(False, "--once", help="Run one monitoring cycle and exit."),
    webhook_url: str | None = typer.Option(None, "--webhook-url"),
    minimum_severity: Severity | None = typer.Option(None, "--minimum-severity"),
    continue_on_error: bool = typer.Option(
        True,
        "--continue-on-error/--stop-on-error",
        help="Keep interval monitoring alive after a failed scan cycle.",
    ),
) -> None:
    """Run on an interval and alert only on high/critical failures by default."""
    while True:
        try:
            contract = load_contract(contract_path)
            summary, run_dir, report_paths = _execute_contract(
                contract_path=contract_path,
                output=output,
                database=database,
                lab_mode=lab_mode,
            )
            _print_summary(summary, run_dir, report_paths)

            alert_url = webhook_url or contract.alerts.webhook_url
            threshold = minimum_severity or contract.alerts.minimum_severity
            if alert_url and (contract.alerts.enabled or webhook_url):
                store = RunStore(database)
                try:
                    result = send_alerts(
                        summary=summary,
                        store=store,
                        webhook_url=alert_url,
                        minimum=threshold,
                        only_new=contract.alerts.only_new,
                        repeat_after_hours=contract.alerts.repeat_after_hours,
                    )
                finally:
                    store.close()
                console.print(
                    f"Alerts: selected={len(result.selected)} sent={len(result.sent)} "
                    f"suppressed={len(result.suppressed)}"
                )
            else:
                console.print(
                    "[dim]Alerts are disabled; configure alerts.webhook_url or --webhook-url.[/dim]"
                )
        except Exception as exc:
            console.print(f"[red]Monitoring cycle failed:[/red] {exc}")
            if once or not continue_on_error:
                raise typer.Exit(2) from exc

        if once:
            return
        console.print(f"Next scan in {interval_seconds} seconds. Press Ctrl+C to stop.")
        try:
            time.sleep(interval_seconds)
        except KeyboardInterrupt:
            console.print("Monitoring stopped.")
            return


@app.command()
def history(
    database: Path = typer.Option(Path(".guard/guard.db"), "--database"),
    limit: int = typer.Option(20, min=1, max=200),
) -> None:
    """Show recent runs saved in SQLite."""
    store = RunStore(database)
    try:
        rows = store.recent_runs(limit)
    finally:
        store.close()

    table = Table("Run", "Started", "Status", "Target", "Contract")
    for row in rows:
        table.add_row(
            row["run_id"],
            row["started_at"],
            row["status"],
            row["target"],
            row["contract_path"],
        )
    console.print(table)


@app.command()
def doctor(
    contract_path: Path | None = typer.Argument(None, exists=True, readable=True),
    ollama_url: str = typer.Option("http://127.0.0.1:11434"),
) -> None:
    """Check the local runtime and optional services."""
    rows: list[tuple[str, str, str]] = []
    py_ok = sys.version_info[:2] == (3, 11)
    rows.append(("Python", platform.python_version(), "ok" if py_ok else "expected 3.11"))
    rows.append(("Platform", platform.platform(), "ok"))
    rows.append(
        (
            "Docker",
            shutil.which("docker") or "not found",
            "ok" if shutil.which("docker") else "optional/missing",
        )
    )

    try:
        response = httpx.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=2)
        response.raise_for_status()
        models = [item.get("name", "") for item in response.json().get("models", [])]
        status = "ok" if "llama3.1:8b" in models else "llama3.1:8b not found"
        rows.append(("Ollama", ", ".join(models[:5]) or "running", status))
    except Exception as exc:
        rows.append(("Ollama", str(exc), "optional/unavailable"))

    if contract_path:
        try:
            contract = load_contract(contract_path)
            validate_target(contract, lab_mode=False)
            if contract.server.transport == "streamable-http":
                url = contract.server.url or ""
                health_url = url.rsplit("/mcp", 1)[0] + "/healthz"
                response = httpx.get(health_url, timeout=2)
                rows.append(("Target", contract.server.target_label, str(response.status_code)))
            else:
                identity_name, identity = next(iter(contract.identities.items()))
                tools = asyncio.run(
                    McpClient(contract.server, identity_name, identity).list_tools()
                )
                rows.append(("Target", contract.server.target_label, f"ok ({len(tools)} tools)"))
        except Exception as exc:
            rows.append(("Target", str(exc), "unavailable"))

    table = Table("Component", "Detected", "Status")
    for row in rows:
        table.add_row(*row)
    console.print(table)


@contract_app.command("generate")
def contract_generate(
    output: Path = typer.Option(Path("contracts/generated-draft.yaml"), "--output", "-o"),
    transport: str = typer.Option("streamable-http", "--transport"),
    name: str = typer.Option("discovered-mcp", "--name"),
    url: str | None = typer.Option(None, "--url"),
    command: str | None = typer.Option(None, "--command"),
    arg: list[str] = typer.Option([], "--arg"),
    cwd: Path | None = typer.Option(None, "--cwd"),
    bearer_token_env: str | None = typer.Option(None, "--bearer-token-env"),
    identity_env: list[str] = typer.Option([], "--identity-env", help="CHILD_ENV=SOURCE_ENV"),
    server_env: list[str] = typer.Option([], "--server-env", help="CHILD_ENV=SOURCE_ENV"),
    infer_read_only: bool = typer.Option(False, "--infer-read-only"),
) -> None:
    """Discover tools and generate a conservative draft contract."""
    if transport not in {"streamable-http", "stdio"}:
        raise typer.BadParameter("transport must be streamable-http or stdio")
    transport_value: Literal["streamable-http", "stdio"] = (
        "stdio" if transport == "stdio" else "streamable-http"
    )

    try:
        discovery_identity_environment = parse_key_value(identity_env, read_environment=True)
        contract_identity_environment = contract_placeholders(identity_env)
        discovery_server_environment = parse_key_value(server_env, read_environment=True)
        contract_server_environment = contract_placeholders(server_env)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    discovery_headers: dict[str, str] = {}
    contract_headers: dict[str, str] = {}
    if bearer_token_env:
        token = os.getenv(bearer_token_env)
        if token is None:
            raise typer.BadParameter(f"environment variable {bearer_token_env!r} is not set")
        discovery_headers["Authorization"] = f"Bearer {token}"
        contract_headers["Authorization"] = f"Bearer ${{{bearer_token_env}}}"

    discovery_server = ServerSpec(
        name=name,
        transport=transport_value,
        url=url,
        command=command,
        args=arg,
        cwd=cwd,
        environment=discovery_server_environment,
        verify_tls=not (url or "").startswith("http://"),
    )
    contract_server = discovery_server.model_copy(
        update={"environment": contract_server_environment}
    )
    discovery_identity = IdentitySpec(
        headers=discovery_headers,
        environment=discovery_identity_environment,
        description="Identity used only for initial discovery.",
    )
    contract_identity = IdentitySpec(
        headers=contract_headers,
        environment=contract_identity_environment,
        description="Review and replace this generated identity before scanning.",
    )

    try:
        payload = asyncio.run(
            generate_contract_draft(
                server=discovery_server,
                discovery_identity=discovery_identity,
                contract_identity=contract_identity,
                infer_read_only=infer_read_only,
                contract_server=contract_server,
            )
        )
    except Exception as exc:
        console.print(f"[red]Discovery failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    write_yaml(payload, output)
    console.print(f"Draft contract written: [bold]{output}[/bold]")
    console.print(
        "[yellow]Review identities, permissions, probes and side effects before running it.[/yellow]"
    )


@contract_app.command("expand-tenants")
def contract_expand_tenants(
    base_contract: Path = typer.Argument(..., exists=True, readable=True),
    tenants: Path = typer.Argument(..., exists=True, readable=True),
    role_policy: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Option(Path("contracts/generated-tenants.yaml"), "--output", "-o"),
) -> None:
    """Compile tenant CSV rows and role permissions into a concrete contract."""
    try:
        payload = expand_tenants(base_contract, tenants, role_policy)
    except ValueError as exc:
        console.print(f"[red]Tenant expansion failed:[/red] {exc}")
        raise typer.Exit(2) from exc
    write_yaml(payload, output)
    console.print(f"Expanded contract written: [bold]{output}[/bold]")


@baseline_app.command("capture")
def baseline_capture(
    contract_path: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Option(Path("baselines/baseline.json"), "--output", "-o"),
    lab_mode: bool = typer.Option(False, "--lab-mode"),
) -> None:
    """Capture tool schemas, response shapes and observed side-effect signatures."""
    contract = load_contract(contract_path)
    validate_target(contract, lab_mode=False)
    baseline = asyncio.run(capture_baseline(contract, lab_mode=lab_mode))
    write_baseline(baseline, output)
    console.print(f"Baseline written: [bold]{output}[/bold]")


@baseline_app.command("compare")
def baseline_compare(
    contract_path: Path = typer.Argument(..., exists=True, readable=True),
    baseline_path: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Option(Path("baseline-diff.json"), "--output", "-o"),
    lab_mode: bool = typer.Option(False, "--lab-mode"),
) -> None:
    """Compare the current target with a saved behavioural baseline."""
    contract = load_contract(contract_path)
    validate_target(contract, lab_mode=False)
    current = asyncio.run(capture_baseline(contract, lab_mode=lab_mode))
    result = compare_baselines(load_baseline(baseline_path), current)
    output.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    console.print_json(data=result)
    if result["drift_detected"]:
        raise typer.Exit(1)


@ai_app.command("suggest")
def ai_suggest(
    contract_path: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Option(Path("ai-suggestions.json"), "--output", "-o"),
    model: str = typer.Option("llama3.1:8b", "--model"),
    ollama_url: str = typer.Option("http://127.0.0.1:11434", "--ollama-url"),
) -> None:
    """Ask a local Ollama model for untrusted candidate test cases."""
    contract = load_contract(contract_path)
    validate_target(contract, lab_mode=False)
    identity_name, identity = next(iter(contract.identities.items()))
    tools = asyncio.run(McpClient(contract.server, identity_name, identity).list_tools())
    advisor = OllamaAdvisor(model=model, base_url=ollama_url)
    payload = asyncio.run(advisor.suggest_tests(contract, tools))
    write_suggestions(payload, output)
    console.print(f"Candidate tests written: [bold]{output}[/bold]")
    console.print(
        "[yellow]These suggestions are not executed and never affect pass/fail results.[/yellow]"
    )


def _execute_contract(
    contract_path: Path,
    output: Path,
    database: Path,
    lab_mode: bool,
) -> tuple[RunSummary, Path, list[Path]]:
    try:
        contract = load_contract(contract_path)
        validate_target(contract, lab_mode=lab_mode)
    except ContractError as exc:
        console.print(f"[red]Contract error:[/red] {exc}")
        raise typer.Exit(2) from exc

    store = RunStore(database)
    try:
        engine = GuardEngine(contract, contract_path, store, output, lab_mode)
        summary = asyncio.run(engine.run())
        report_paths = write_reports(summary, engine.run_dir, contract.reports.formats)
    finally:
        store.close()
    return summary, engine.run_dir, report_paths


def _print_summary(summary: RunSummary, run_dir: Path, report_paths: list[Path]) -> None:
    table = Table(title=f"MCP Behaviour Guard · {summary.run_id}")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Test")
    table.add_column("Finding")
    for finding in sorted(summary.findings, key=finding_sort_key):
        style = {
            "passed": "green",
            "failed": "red",
            "error": "yellow",
            "skipped": "dim",
        }[finding.status.value]
        table.add_row(
            finding.severity.value,
            f"[{style}]{finding.status.value}[/{style}]",
            finding.test_id,
            finding.title,
        )
    console.print(table)
    console.print(f"Reports: [bold]{run_dir}[/bold]")
    for path in report_paths:
        console.print(f"  - {path.name}")


if __name__ == "__main__":
    app()
