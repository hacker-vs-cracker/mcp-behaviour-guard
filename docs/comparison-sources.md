# MCP security landscape comparison — source notes

**Checked:** 20 July 2026

This document supports the scope comparison used in `README.md` and `images/mcp-security-landscape.gif`.

The comparison describes the projects' documented feature focus. It is not a detection benchmark, market ranking, completeness assessment, or claim that the projects do not support additional features.

## Sources

### Snyk Agent Scan

- Repository: https://github.com/snyk/agent-scan
- Scanning guide: https://github.com/snyk/agent-scan/blob/main/docs/scanning.md
- Issue-code reference: https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md

The project documents inventory/discovery of agent components and scanning of agent configurations, MCP servers and skills for categories including prompt injection, tool poisoning, toxic flows and malware-oriented content.

### Trail of Bits MCP Context Protector

- Repository: https://github.com/trailofbits/mcp-context-protector

The project documents a wrapper for MCP servers with trust-on-first-use configuration pinning, blocking of unapproved configuration changes, response guardrail scanning/quarantine and ANSI control-character sanitization.

### LastMile AI mcp-eval

- Repository: https://github.com/lastmile-ai/mcp-eval

The project documents evaluation of MCP servers and agents through real agent-to-server execution, assertions, multiple test styles and OpenTelemetry-based observability, with a focus on quality, performance and reliability.

### MCP Behaviour Guard

The comparison statements are limited to implemented repository features:

- Streamable HTTP and STDIO clients
- human-reviewed YAML security contracts
- multi-identity and tenant authorization checks
- session-isolation probes
- configured side-effect observation
- replay/idempotency checks behind a safety gate
- behavioural baselines
- SQLite evidence storage and HTML/JSON/JSONL/JUnit/SARIF outputs

## Agent configuration references

- VS Code MCP configuration reference: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- VS Code MCP management guide: https://code.visualstudio.com/docs/agent-customization/mcp-servers
- Claude Code MCP documentation: https://code.claude.com/docs/en/mcp
- OpenClaw MCP CLI documentation: https://docs.openclaw.ai/cli/mcp
- MCP documentation: https://modelcontextprotocol.io/docs/getting-started/intro

## Interpretation

The four projects occupy different, partly overlapping layers:

1. discover and scan component/configuration/content risk;
2. wrap and protect live MCP traffic;
3. evaluate agent/server quality and reliability;
4. verify runtime security behaviour against an explicit contract.

Using this diagram in a public post should retain the subtitle and footer so readers can see that it is a published-scope comparison rather than a performance benchmark.
