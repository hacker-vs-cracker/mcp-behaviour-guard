from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

ROOT = Path(os.getenv("DEMO_STDIO_ROOT", "demo_runtime/stdio")).expanduser().resolve()
WORKSPACE = ROOT / "workspace"
SECRET_FILE = ROOT / "agent-secrets.txt"
AUDIT_FILE = Path(os.getenv("DEMO_STDIO_AUDIT", str(ROOT / "audit.jsonl"))).resolve()
SHARED_NOTE = ROOT / "shared-agent-note.txt"

WORKSPACE.mkdir(parents=True, exist_ok=True)
AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
(WORKSPACE / "README.txt").write_text("Safe local-agent workspace file.\n", encoding="utf-8")
SECRET_FILE.write_text("local-agent-secret-material\n", encoding="utf-8")

mcp = FastMCP(
    "mcp-behaviour-guard-stdio-demo",
    instructions=(
        "A deliberately vulnerable local coding-agent MCP server. "
        "It never executes the recorded command strings."
    ),
)


@mcp.tool()
def workspace_read(path: str) -> dict[str, Any]:
    """Read a file from the local coding workspace."""
    candidate = (WORKSPACE / path).resolve()

    # Deliberate boundary flaw: the check permits any file under ROOT rather than WORKSPACE.
    # A value such as ../agent-secrets.txt therefore escapes the intended workspace.
    if not candidate.is_relative_to(ROOT):
        raise PermissionError("path is outside the demo root")
    if not candidate.is_file():
        raise FileNotFoundError(path)

    return {
        "path": str(candidate),
        "content": candidate.read_text(encoding="utf-8"),
        "identity": os.getenv("MCP_GUARD_IDENTITY", "local_agent"),
    }


@mcp.tool()
def diagnostics() -> dict[str, str]:
    """Return local MCP server diagnostics without credentials."""
    # Deliberate inherited-environment leak, representative of unsafe local MCP tooling.
    return {
        "identity": os.getenv("MCP_GUARD_IDENTITY", "local_agent"),
        "role": os.getenv("MCP_GUARD_ROLE", "developer"),
        "agent_token": os.getenv("DEMO_AGENT_TOKEN", "missing"),
    }


@mcp.tool()
def run_project_task(task: str, extra_args: str = "") -> dict[str, Any]:
    """Run an approved project task inside the workspace."""
    # Deliberate argument-injection flaw. The demo records the resulting string but does not
    # launch a subprocess, so the repository remains safe to execute locally.
    command = f"{task} {extra_args}".strip()
    _record_event(
        {
            "kind": "process_execution",
            "tool": "run_project_task",
            "command": command,
            "executed": False,
            "identity": os.getenv("MCP_GUARD_IDENTITY", "local_agent"),
        }
    )
    return {"accepted": True, "command": command, "executed": False}


@mcp.tool()
def set_workspace_note(note: str) -> dict[str, Any]:
    """Store a note for the current local-agent session."""
    # Deliberate cross-client state flaw: all STDIO processes use one shared file.
    SHARED_NOTE.write_text(note, encoding="utf-8")
    _record_event(
        {
            "kind": "filesystem_write",
            "tool": "set_workspace_note",
            "path": str(SHARED_NOTE),
        }
    )
    return {"stored": True}


@mcp.tool()
def get_workspace_note() -> dict[str, str]:
    """Read the note stored for the current local-agent session."""
    return {"note": SHARED_NOTE.read_text(encoding="utf-8") if SHARED_NOTE.exists() else ""}


def _record_event(event: dict[str, Any]) -> None:
    with AUDIT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


if __name__ == "__main__":
    mcp.run(transport="stdio")
