# MCP Behaviour Guard

**Deterministic security contracts and regression evidence for MCP servers used by AI agents and developer automation.**

`mcp-behaviour-guard` is for development and security teams building MCP-backed agents, coding assistants, internal copilots, support automations, or CI/CD workflows and wanting a repeatable way to test the **MCP server boundary** before trusting it with business systems.

It does not judge whether an LLM "reasoned correctly." It tests observable properties of the MCP server and its reviewed contract: authorization, tenant/session isolation, side effects, replay behaviour, metadata drift, host-configuration drift, and saved-run regressions.

## Where development teams use it

| Automation scenario | What the team wants to prevent | Useful Behaviour Guard functions |
|---|---|---|
| Internal support agent connected to CRM/ticketing MCP tools | One tenant/customer seeing another tenant's records | identities, `tenant_probes`, confidentiality canaries, session tests |
| Finance/procurement agent using a third-party enrichment MCP server | Tool-description poisoning or a later metadata "rug pull" after approval | `temporal_integrity`, host-config snapshot/check, saved-run comparison |
| Coding assistant using a local STDIO MCP server | Path escape, inherited-secret leakage, arbitrary command execution | restricted STDIO launch, `policy_probes`, process/filesystem effect claims |
| Remote MCP service in a developer platform | Unauthenticated access, unexpected redirects/egress, excessive side effects | identities, restricted HTTP destinations, network-effect claims |
| Agent that performs state-changing operations | Duplicate updates when the agent retries | `replay_probe` plus independent effect observation |
| MCP server release pipeline | A candidate silently changes authorization, tools, evidence coverage, or behaviour | `mcp-guard run`, JUnit/SARIF, `baseline compare-saved` |
| Long-running production assurance | A previously approved server changes tools/prompts/resources later | `mcp-guard monitor --interval`, temporal integrity, alerts, config provenance |

Recent 2026 patterns illustrate why these boundaries matter:

- [Deadbugz](https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign) used GitHub pull requests to introduce MCP configuration and delayed malicious metadata until after ordinary tool calls.
- [Microsoft's finance-agent tool-poisoning scenario](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/) shows how a changed third-party MCP tool description can cause an agent to collect and forward data beyond the user's intended task.
- [Microsoft's Azure MCP security guidance](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/security) treats tool/schema changes as security-relevant and recommends constraining local MCP execution.
- [Microsoft's AI-app misconfiguration research](https://www.microsoft.com/en-us/security/blog/2026/05/14/configuration-becomes-vulnerability-exploitable-misconfigurations-ai-apps/) describes remotely exposed MCP servers with insufficient authentication reaching sensitive internal systems.

Behaviour Guard tests the server-side and evidence boundaries visible to the configured contract. It is not a universal detector for every prompt-injection, malware, host-compromise, or agent-reasoning failure.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install mcp-behaviour-guard
```

The CLI is `mcp-guard`.

## Developer workflow

```bash
# 1. Generate a conservative draft from a dev/staging MCP server.
mcp-guard contract generate \
  --transport streamable-http \
  --name support-mcp \
  --url https://mcp.dev.example.com/mcp \
  --bearer-token-env SUPPORT_MCP_TOKEN \
  --output contracts/support-mcp.yaml

# 2. Review identities, tenant rules, side effects and safety boundaries.
# Discovery does NOT know your organization's real authorization policy.

# 3. Run the reviewed contract against synthetic dev/staging fixtures.
mcp-guard run contracts/support-mcp.yaml \
  --output reports/candidate \
  --database .guard/candidate.db
```

For state-changing probes, use synthetic fixtures and the existing lab/destructive-test safety boundary. Do not aim destructive checks at production data.

## Other automation hooks

Track host-configuration drift when a developer tool changes `.vscode/mcp.json` or another supported
MCP host configuration:

```bash
mcp-guard config snapshot .vscode/mcp.json --output policy/vscode-mcp.json
mcp-guard config check .vscode/mcp.json policy/vscode-mcp.json
```

Run once from another scheduler/CI job, or use Guard's built-in interval monitor:

```bash
# One monitored cycle with webhook alerting.
mcp-guard monitor contracts/support-mcp.yaml \
  --once \
  --minimum-severity high \
  --webhook-url "$MCP_GUARD_WEBHOOK"

# Or keep the process alive and re-run every hour.
mcp-guard monitor contracts/support-mcp.yaml \
  --interval 3600 \
  --minimum-severity high \
  --webhook-url "$MCP_GUARD_WEBHOOK"
```

Reports can include JSON, HTML, JUnit and SARIF. `mcp-guard history` reads recent SQLite-backed run
history. Configuration drift is a review signal, not a malware verdict, and interval monitoring
re-runs the reviewed contract rather than approving a newly generated policy.

## Example 1: multi-tenant support agent contract

This is a **starter pattern**, not a copy/paste production policy.

```yaml
version: 1

server:
  name: support-platform-mcp
  transport: streamable-http
  url: https://mcp.staging.example.com/mcp

  # Keep the MCP request and every followed redirect on reviewed origins.
  http_destination:
    allowed_origins:
      - https://mcp.staging.example.com
    allow_redirects: false

identities:
  tenant_a_agent:
    tenant: tenant-a
    role: support_agent
    headers:
      # Keep real credentials outside Git.
      Authorization: Bearer ${TENANT_A_MCP_TOKEN}

  tenant_b_agent:
    tenant: tenant-b
    role: support_agent
    headers:
      Authorization: Bearer ${TENANT_B_MCP_TOKEN}

tools:
  customer_lookup:
    description: Return a customer record owned by the caller's tenant.
    permitted_identities:
      - tenant_a_agent
      - tenant_b_agent

    # Positive-control input.
    probe_arguments:
      customer_id: tenant-a-synthetic-001

    read_only: true
    side_effect_identity: tenant_a_agent

    # [] is an active deny-all policy for this effect family.
    # Use null/omit when you are not making that policy claim.
    allowed_network_destinations: []
    allowed_filesystem_writes: []

    tenant_probes:
      tenant_a_agent:
        # Ask tenant A's identity for a synthetic tenant B object.
        arguments:
          customer_id: tenant-b-synthetic-001

        resource_tenant_path: tenant
        expected_tenant: tenant-a
        require_denial: true

        # Synthetic protected content that must not be disclosed.
        confidentiality:
          values:
            - SYNTHETIC_TENANT_B_PRIVATE_CANARY
```

**Use this when:** a support/copilot agent can query CRM, ticketing, HR, finance, or other tenant-scoped business data.

`read_only: true` is a real side-effect claim. For approval-style absence assurance, configure matching
observer coverage for the effect families Guard requires. Missing observation is not silently converted
into proof that no side effect occurred. The repository's HTTP demo shows a complete observed pattern.

## Example 2: local coding-assistant MCP server

```yaml
version: 1

server:
  name: reviewed-local-dev-tools
  transport: stdio

  command: /path/to/project/.venv/bin/python
  args:
    - -m
    - company_mcp.devtools
  cwd: /path/to/project

  stdio_launch:
    mode: restricted

    # Canonical executable reviewed by the team.
    allowed_executables:
      - /canonical/path/to/python3.11

    # Prevent launch from unrelated checkouts/directories.
    allowed_cwd_roots:
      - /path/to/project

    # Start with a minimal inherited environment.
    inherit_environment:
      - PATH

identities:
  developer_agent:
    role: developer
    tenant: local-workspace

tools:
  repo_read:
    description: Read files only from the approved project workspace.
    permitted_identities:
      - developer_agent
    probe_arguments:
      path: README.md
    side_effect_identity: developer_agent
    read_only: true

    policy_probes:
      - id: DEV-PATH-ESCAPE-001
        identity: developer_agent
        description: A repo reader must not escape the reviewed workspace.
        arguments:
          path: ../outside-workspace-canary.txt
        severity: critical
        checks:
          - type: denied

  diagnostics:
    description: Return diagnostics without echoing developer credentials.
    permitted_identities:
      - developer_agent
    probe_arguments: {}
    side_effect_identity: developer_agent
    read_only: true

    policy_probes:
      - id: DEV-ENV-LEAK-001
        identity: developer_agent
        arguments: {}
        severity: critical
        checks:
          - type: response_not_contains_env
            env_names:
              - AWS_SECRET_ACCESS_KEY
              - GITHUB_TOKEN
              - NPM_TOKEN
```

**Use this when:** Claude Code, Codex, VS Code/GitHub Copilot, or another MCP-capable development host launches a local server with project, command, or credential access.

Replace every placeholder path with a real local path before validation. In restricted mode,
`allowed_executables` must identify existing canonical executable targets and `allowed_cwd_roots`
must identify existing approved roots. `read_only: true` also requires appropriate observer evidence
when you want absence-of-side-effect assurance.

Restricted launch is policy hardening, not an OS sandbox.

## Example 3: delayed tool/prompt metadata-change fragment

```yaml
tools:
  format_text:
    description: Harmless read-only driver used to advance the session.
    permitted_identities:
      - reviewer
    probe_arguments:
      text: guard-canary
    side_effect_identity: reviewer
    read_only: true

temporal_integrity:
  enabled: true
  identity: reviewer
  driver_tool: format_text

  # Repeated safe calls can expose call-count-gated metadata drift.
  driver_arguments:
    text: temporal-canary
  sessions: 2
  retests_per_session: 5
  rediscover_after_each_call: true
  stop_on_first_drift: true

  monitor_tools: true
  monitor_prompts: true
  monitor_resources: false

  probe_argumentless_prompts: true
  prompt_probes:
    assistant_guidance: {}

  severity: high
```

**Use this when:** a third-party or newly updated MCP server could change tool/prompt/resource metadata after installation or normal use.

## Example 4: retry/idempotency contract fragment

```yaml
tools:
  customer_update:
    permitted_identities:
      - administrator

    probe_arguments:
      customer_id: synthetic-customer-001
      display_name: Baseline Name
      operation_id: access-probe

    side_effect_identity: administrator
    read_only: false

    replay_probe:
      # Repeat one logical mutation.
      arguments:
        customer_id: synthetic-customer-001
        display_name: Replay Candidate
        operation_id: replay-operation-001
      attempts: 3

      # Match this to independent effect observation in your test environment.
      event_kind: database_write
      event_tool: customer_update

      # Three calls should produce at most one business mutation.
      maximum_events: 1
```

Replay assurance requires matching observer coverage. Zero observed effects are not automatically proof of idempotency.

## CI and release-regression pattern

```bash
mcp-guard baseline compare-saved \
  reports/approved-reference \
  reports/candidate \
  --output saved-run-diff.json
```

Exit semantics:

- `0`: supported/comparable and no current comparison dimension requires review.
- `1`: review required due to conformance, regression, coverage, capability, or context change.
- `2`: invalid/unsupported comparison.

An exit `0` is **not** cryptographic proof that the reference was independently approved. Protecting the reference, policy, candidate identity, environment and final CI gate is a separate trust-boundary problem.

## Python automation

```python
import asyncio

from mcp_behaviour_guard import run_contract

result = asyncio.run(
    run_contract(
        "contracts/support-mcp.yaml",
        output="reports/automation-run",
    )
)

print("assessment:", result.summary.assessment.value)
print("evidence:", result.run_dir)

# Choose your own pipeline policy for fail/inconclusive/not_tested.
if result.summary.assessment.value != "pass":
    raise SystemExit(1)
```

Use the CLI for conventional process exit codes and shell-friendly CI composition. Use the Python API when Guard is a stage inside a larger Python automation.

## What it does not claim

Behaviour Guard does not claim to:

- prove an MCP server is malware-free;
- prove an AI agent will reason safely;
- replace OAuth/IAM, sandboxing, EDR, network policy, or runtime authorization;
- infer your organization's correct security policy from tool descriptions;
- make an unprotected saved reference trustworthy by itself.

See:
- [GitHub project overview](https://github.com/hacker-vs-cracker/mcp-behaviour-guard)
- [Developer automation playbook](https://github.com/hacker-vs-cracker/mcp-behaviour-guard/blob/main/docs/developer-automation-playbook.md)
- [Contract reference](https://github.com/hacker-vs-cracker/mcp-behaviour-guard/blob/main/docs/contract-reference.md)
- [Saved-run comparison](https://github.com/hacker-vs-cracker/mcp-behaviour-guard/blob/main/docs/saved-run-comparison.md)
