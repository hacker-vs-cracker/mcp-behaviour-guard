# Local STDIO demo

This demo shows how the same local STDIO MCP server can be launched directly by the guard or configured in an editor host.

## Direct security test

```bash
export DEMO_AGENT_TOKEN=local-demo-token
mcp-guard run contracts/stdio-demo.yaml --lab-mode --no-fail
```

This is the preferred security-test path because inputs, identities, sessions, evidence and expected outcomes are controlled by the contract.

## Editor host example

Copy `examples/clients/vscode-mcp.json` to `.vscode/mcp.json` in a demonstration checkout. The example enables STDIO server sandboxing and restricts writes to `demo_runtime/stdio`.

Review local MCP server configuration before allowing it to run, especially executable paths, arguments, environment mapping, filesystem access and network permissions.

## Safety statement

The example connects the host to a deliberately vulnerable demonstration server. The server records unsafe command construction but never executes the injected command string.
