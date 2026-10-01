# MCP Behaviour Guard

**Deterministic security contracts and regression evidence for MCP servers used by AI agents and developer automation.**

`mcp-behaviour-guard` is for development and security teams building MCP-backed agents, coding assistants, internal copilots, support automations, or CI/CD workflows and wanting a repeatable way to test the **MCP server boundary** before trusting it with business systems.

It does not judge whether an LLM "reasoned correctly." It tests observable properties of the MCP server and its reviewed contract: authorization, tenant/session isolation, side effects, replay behaviour, metadata drift, host-configuration drift, and saved-run regressions.

## Supply-chain trust

The default branch is protected by pull-request and required-CI rules. The repository security workflow runs SHA-pinned CodeQL, pinned `pip-audit`, and GitHub Dependency Review. Releases use GitHub OIDC Trusted Publishing to PyPI with digital attestations for uploaded distributions. These controls provide provenance and known-vulnerability/static-analysis signals; they are not proof that the package is vulnerability-free or incapable of malicious behaviour.

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

`monitor --once` is monitoring/alerting behavior, not a CI approval decision.
A completed monitor cycle can return normally when its recorded assessment is
non-pass. For approval use `mcp-guard run`, the Python assessment, or a
separately protected trusted gate. `--no-fail` is for demo/diagnostic retention
and must not become the approval verdict.

The canonical example YAML files below live in the GitHub repository; they are not
installed as wheel package data. If you installed from PyPI, clone or download the
repository to use these source templates, or open the explicit repository links below.

## Example 1: multi-tenant support agent contract

Use the source template at
<https://github.com/hacker-vs-cracker/mcp-behaviour-guard/blob/main/contracts/examples/tenant-isolation.yaml>.

Repository tests behaviorally demonstrate the specific synthetic positive control,
recognized denial, generic-error non-denial, and confidentiality-canary cases. That
bounded demonstration is not proof that an arbitrary deployment is safe.

It deliberately uses one permitted tenant-A identity for both the tenant-A
positive control and the tenant-B negative resource probe. This matches Guard's
same-identity positive-control rule and avoids requiring one tenant-A request to
succeed for multiple tenant identities.

The synthetic fixture's denial convention is explicit:

```yaml
denial_error_markers:
  - GUARD_DEMO_DENIED
```

An arbitrary MCP error is not authorization-denial evidence. The negative probe
also uses a synthetic confidentiality canary rather than production data.

`read_only: true` remains a real side-effect claim. Configure matching observer
coverage when making approval-style absence claims.

## Example 2: local coding-assistant MCP server

Use the source template at
<https://github.com/hacker-vs-cracker/mcp-behaviour-guard/blob/main/contracts/examples/local-coding-assistant.yaml>.

Repository tests behaviorally demonstrate the specific synthetic positive control,
recognized path denial, generic-error non-denial, child canary delivery and deliberate
canary-disclosure cases. The file is a template, not a ready-to-run deployment recipe.

The environment-leak example configures one explicit non-production canary:

```yaml
server:
  environment:
    GUARD_DEMO_SECRET: synthetic-guard-demo-secret-value
```

and checks exactly `GUARD_DEMO_SECRET` with `response_not_contains_env`.
Do not inject real AWS, GitHub, registry, or other production credentials merely
to make an example observable.

The path-denial example uses the explicit `GUARD_DEMO_DENIED` convention.

Without restricted `stdio_launch`, the child starts from the evaluator parent's
environment and then receives the configured contract/identity values. The synthetic
canary makes one leak check deterministic; it does not sanitize inherited AWS, GitHub,
registry, cloud or other real variables, and it is not containment. For a real
deployment, use restricted STDIO launch with actual reviewed executable/cwd paths and
an explicit `inherit_environment` allowlist, or a sanitized disposable container/VM.

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

`--output` is an output root. Each `run` creates a generated leaf run directory.
Pass the exact reviewed leaf directories to `compare-saved`:

```bash
REFERENCE_RUN_DIR="reports/approved-reference/<reference-run-id>"
CANDIDATE_RUN_DIR="reports/candidate/<candidate-run-id>"

mcp-guard baseline compare-saved \
  "$REFERENCE_RUN_DIR" \
  "$CANDIDATE_RUN_DIR" \
  --output saved-run-diff.json
```

Use the exact `run_dir` printed/returned by Guard. Do not recursively select a
report or guess the newest directory.

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
