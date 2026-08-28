# Threat model

## Protected properties

MCP Behaviour Guard focuses on observable security properties:

- tool and operation authorization;
- tenant/object ownership boundaries;
- session and client-process isolation;
- workspace and repository path boundaries;
- inherited secret handling;
- declared filesystem, network and process behaviour;
- idempotent state changes; and
- stable capability and schema boundaries;
- stable tool/prompt/resource metadata during an approved session; and
- reviewed provenance for MCP host configuration changes.

## Adversaries and failure modes

- unauthenticated or low-privilege MCP clients;
- confused-deputy calls made through a connected host;
- malicious or compromised tool metadata;
- untrusted repository content containing indirect instructions;
- unsafe construction of shell commands from tool arguments or environment variables;
- local MCP servers with excessive filesystem/network privileges;
- accidental retries and concurrent duplicate operations;
- server upgrades that expand privileges or side effects;
- runtime-gated metadata mutation after benign initial calls;
- supply-chain changes that introduce new MCP endpoints or local commands; and
- implementation bugs that cross tenant, path or session boundaries.

## How the demos map to recent patterns

| Demonstration check | Security pattern | Reference |
|---|---|---|
| STDIO workspace path escape | MCP tool accepts a path outside its intended repository/workspace | GitHub-reviewed CVE-2026-27735 / GHSA-vjqx-cfc4-9h6v |
| STDIO unsafe process command | User-controlled MCP input reaches shell command construction | GitHub-reviewed CVE-2026-25546 / GHSA-8jx2-rhfh-q928 |
| Unauthorized local tool use | Local control surface exposes powerful server configuration or command actions without adequate authentication | GitHub-reviewed CVE-2026-23744 / GHSA-232v-j27c-5pp6 |
| Inherited environment disclosure | Local agent/MCP process inherits sensitive environment values | Unreviewed GitHub Advisory Database entry CVE-2026-35020 / GHSA-jgg3-qqhf-7rx7; used only as threat inspiration |
| Workspace/session boundaries | Project files can influence agent actions; local MCP servers may have broad file, code and service access | Current VS Code agent security and Workspace Trust documentation |

The project does not claim that its demo reproduces a complete exploit chain against a host application. It extracts testable server-side properties: approved executable, approved arguments, approved paths, secret-free output, least privilege and isolated state.

## Runtime-gated metadata drift

Pillar Security disclosed the Deadbugz campaign on August 12, 2026. In the observed server, metadata remained benign until three normal tool calls; later `tools/list` and `prompts/get` responses changed. The campaign also used GitHub pull requests to introduce remote MCP configuration or hidden local Python artifacts.

Version 0.3.0 adds two tests derived from those observable properties: persistent-session metadata fingerprinting and host-configuration provenance. The included demo reproduces only a three-call metadata change with inert text. It does not reproduce credential-seeking instructions, exfiltration or the campaign infrastructure, and the project does not claim to prevent every Deadbugz variant.

Reference: https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign

## Primary references

- https://github.com/advisories/GHSA-vjqx-cfc4-9h6v
- https://github.com/advisories/GHSA-8jx2-rhfh-q928
- https://github.com/advisories/GHSA-232v-j27c-5pp6
- https://github.com/advisories/GHSA-jgg3-qqhf-7rx7
- https://code.visualstudio.com/docs/agents/security
- https://code.visualstudio.com/docs/editing/workspaces/workspace-trust
- https://code.visualstudio.com/docs/agent-customization/mcp-servers
- https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http

## Out of scope for the MVP

- discovering unknown network vulnerabilities;
- exploiting public targets;
- autonomous offensive-agent behaviour;
- malware analysis;
- complete prompt-injection classification;
- denial-of-service testing;
- full syscall observation;
- proving absence of sleeper logic beyond configured temporal test depth;
- classifying a changed host configuration as malware; and
- proving correctness of the target's own audit endpoint.
