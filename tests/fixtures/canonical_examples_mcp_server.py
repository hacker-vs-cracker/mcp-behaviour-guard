from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP

TRANSPORT = os.environ.get("GUARD_FIXTURE_TRANSPORT", "stdio")
HOST = os.environ.get("GUARD_FIXTURE_HOST", "127.0.0.1")
PORT = int(os.environ.get("GUARD_FIXTURE_PORT", "8765"))

if TRANSPORT == "http":
    mcp = FastMCP(
        "canonical-example-http-fixture",
        host=HOST,
        port=PORT,
        streamable_http_path="/mcp",
        json_response=True,
    )

    @mcp.tool()
    def customer_lookup(customer_id: str) -> dict[str, Any]:
        if customer_id == "tenant-a-synthetic-001":
            return {
                "customer_id": customer_id,
                "tenant": "tenant-a",
                "result": "safe synthetic response",
            }

        if customer_id == "tenant-b-synthetic-001":
            mode = os.environ.get("GUARD_FIXTURE_TENANT_MODE", "deny")
            if mode == "deny":
                raise PermissionError("GUARD_DEMO_DENIED: cross-tenant access")
            if mode == "generic":
                raise RuntimeError("synthetic generic lookup error")
            if mode == "leak":
                return {
                    "customer_id": customer_id,
                    "tenant": "tenant-b",
                    "result": "SYNTHETIC_TENANT_B_PRIVATE_CANARY",
                }
            raise RuntimeError(f"unsupported tenant fixture mode: {mode}")

        raise ValueError("synthetic customer not found")

else:
    mcp = FastMCP("canonical-example-stdio-fixture")

    @mcp.tool()
    def repo_read(path: str) -> dict[str, str]:
        if path == "README.md":
            return {"path": "README.md", "content": "synthetic repository read"}

        if path == "../outside-workspace-canary.txt":
            mode = os.environ.get("GUARD_FIXTURE_STDIO_PATH_MODE", "deny")
            if mode == "deny":
                raise PermissionError("GUARD_DEMO_DENIED: path outside workspace")
            if mode == "generic":
                raise RuntimeError("synthetic generic read error")
            raise RuntimeError(f"unsupported stdio path fixture mode: {mode}")

        raise FileNotFoundError(path)

    @mcp.tool()
    def diagnostics() -> dict[str, Any]:
        secret = os.environ.get("GUARD_DEMO_SECRET")
        result: dict[str, Any] = {"secret_present": bool(secret)}
        if os.environ.get("GUARD_FIXTURE_STDIO_DIAGNOSTICS_MODE", "safe") == "leak":
            result["diagnostic_value"] = secret
        return result


if __name__ == "__main__":
    if TRANSPORT == "http":
        import uvicorn

        app = mcp.streamable_http_app()
        uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
    else:
        mcp.run(transport="stdio")
