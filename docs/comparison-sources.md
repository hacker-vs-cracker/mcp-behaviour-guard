# MCP security landscape comparison — source notes

**Checked:** 28 August 2026

This document supports the scope comparison used in `README.md`. It describes published feature focus; it is not a detection benchmark, market ranking, completeness assessment, or claim that another project cannot support adjacent features.

## Sources

### Snyk Agent Scan

- Repository: https://github.com/snyk/agent-scan
- Scanning guide: https://github.com/snyk/agent-scan/blob/main/docs/scanning.md
- Issue-code reference: https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md

Published scope includes inventory/discovery of agent components and scanning of agent configurations, MCP servers and skills for categories including prompt injection, tool poisoning, toxic flows and malware payloads.

### Trail of Bits MCP Context Protector

- Repository: https://github.com/trailofbits/mcp-context-protector

Published scope includes an MCP wrapper with configuration pinning, blocking of unapproved configuration changes, response guardrail scanning/quarantine and control-character sanitization.


### MCP Behaviour Guard

The comparison statements are limited to repository features that are implemented and testable:

- Streamable HTTP and STDIO clients;
- human-reviewed YAML security contracts;
- multi-identity and tenant authorization checks;
- session-isolation probes;
- configured side-effect observation;
- replay/idempotency checks behind a safety gate;
- persistent-session temporal metadata fingerprinting;
- MCP host-configuration provenance snapshots/diffs;
- behavioural baselines; and
- SQLite evidence storage plus HTML/JSON/JSONL/JUnit/SARIF outputs.

## Attack-pattern references

- Pillar Security, Deadbugz disclosure: https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign
- OWASP MCP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html

These references informed the temporal-integrity and configuration-provenance tests. They do not establish that Behaviour Guard prevents every variation of those attacks.

## Agent configuration references

- VS Code MCP configuration reference: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- VS Code MCP management guide: https://code.visualstudio.com/docs/agent-customization/mcp-servers
- MCP documentation: https://modelcontextprotocol.io/docs/getting-started/intro
