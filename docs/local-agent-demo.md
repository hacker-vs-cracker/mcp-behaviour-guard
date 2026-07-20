# Local-agent STDIO demo

This demo shows how the same local STDIO MCP server can be launched directly by the guard or configured in familiar coding-agent hosts.

## Direct security test

```bash
export DEMO_AGENT_TOKEN=local-demo-token
mcp-guard run contracts/stdio-demo.yaml --lab-mode --no-fail
```

This is the preferred security-test path because inputs, identities, sessions, evidence and expected outcomes are controlled by the contract.

## Claude Code example

Copy `examples/clients/claude-code.mcp.json` to `.mcp.json` only in a local demonstration checkout, set `DEMO_AGENT_TOKEN`, and review the project-scoped server approval before starting it.

The official Claude Code configuration supports project-scoped `.mcp.json` files with a top-level `mcpServers` mapping and environment-variable expansion.

## VS Code / GitHub Copilot example

Copy `examples/clients/vscode-mcp.json` to `.vscode/mcp.json` in a demonstration checkout. The example enables STDIO server sandboxing and restricts writes to `demo_runtime/stdio`.

Current VS Code documentation warns that local MCP servers can run arbitrary code and recommends reviewing the server configuration and using trust/sandbox controls. Keep unfamiliar repositories in Restricted Mode until reviewed.

## Safety statement

The examples connect hosts to a deliberately vulnerable server. They are not exploits of Claude Code, GitHub Copilot or VS Code. The server records unsafe command construction but never executes the injected command string.
