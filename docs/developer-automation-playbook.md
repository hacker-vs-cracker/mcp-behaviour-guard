# Developer automation playbook

This guide maps MCP Behaviour Guard features to practical development and security workflows.

The goal is not a universal MCP malware scanner. The goal is to make reviewed security claims executable and repeatable around the MCP server boundary.

## 1. Internal support or service-desk agent

Typical architecture:

```text
Support agent
  -> MCP server
       -> CRM
       -> ticketing
       -> knowledge base
```

Security questions:

- Can tenant A retrieve tenant B's records?
- Does a read-only support identity reach update/admin tools?
- Can one agent session read markers created in another session?
- Can diagnostic/error responses leak synthetic protected values or configured secrets?

Use:

- identities and `permitted_identities`
- `tenant_probes`
- tenant confidentiality canaries
- `session_tests`
- custom `policy_probes`

Run the reviewed contract against synthetic staging fixtures before promoting a server build. Export JUnit/SARIF with the rest of the pipeline evidence.

When a tool is declared `read_only` or carries explicit side-effect allow/deny claims, configure the
observer coverage required for the assurance you want. A missing observer is uncertainty, not proof
that the effect did not occur.

## 2. Finance/procurement agent with a third-party MCP server

A third-party server may be initially reviewed and later change tool descriptions, prompts, endpoints, or host configuration.

Relevant 2026 patterns:

- Pillar Security's Deadbugz research documented an MCP supply-chain campaign with delayed malicious metadata after ordinary calls.
- Microsoft described a finance-agent tool-poisoning scenario where changed MCP metadata causes an agent to collect and forward additional invoice data.

Use:

- host-configuration snapshot/check
- `temporal_integrity`
- capability inventory
- saved-run comparison

These controls detect reviewed configuration/metadata changes. They do not prove every malicious prompt payload or model manipulation is absent.

## 3. Local coding assistant or developer co-worker

A local STDIO MCP server may inherit shell state, cloud credentials, repository access, or command capability.

Security questions:

- Is the reviewed executable the one actually launched?
- Can the server start outside the approved checkout?
- Which parent environment variables reach the child?
- Can a read tool escape the project root?
- Can a test/build tool execute arbitrary commands?

Use:

- restricted STDIO launch
- path policy probes
- `response_not_contains_env`
- filesystem/process side-effect claims
- independent observers where complete evidence is required

Replace the placeholder executable/workspace paths in the commented example with real existing paths.
Restricted STDIO validation expects reviewed canonical executable identity and approved existing cwd roots.

Use OS/container isolation for stronger containment. Restricted launch is not a sandbox.

## 4. Remote MCP service used by an application team

Security questions:

- Is anonymous or invalid-token access rejected?
- Can redirects move authenticated traffic to another origin?
- Is a supposedly read-only tool causing network/filesystem/database writes?
- Does the service expose more tools after an update?

Use:

- identity/access-matrix probes
- restricted HTTP destinations
- configured side-effect claims
- capability comparison
- `mcp-guard monitor --interval` for built-in interval assurance

## 5. Retrying agent that performs mutations

For tools such as `create_ticket`, `approve_invoice`, `send_message`, `update_customer`, or `provision_resource`, a retry can become a duplicate business action.

Use `replay_probe` with a synthetic object and independently observed effects. The useful claim is about the observed business mutation, not merely whether the MCP call returned success.

## 6. MCP server CI / release promotion

Candidate execution:

```bash
mcp-guard run contracts/server.yaml \
  --output reports/candidate \
  --database .guard/candidate.db
```

Guard writes a generated leaf run directory below the output root. Retain that
whole leaf directory, including `report.json`, `receipt.json`, and any declared
tool inventory.

Offline regression comparison:

```bash
REFERENCE_RUN_DIR="reports/approved-reference/<reference-run-id>"
CANDIDATE_RUN_DIR="reports/candidate/<candidate-run-id>"

mcp-guard baseline compare-saved \
  "$REFERENCE_RUN_DIR" \
  "$CANDIDATE_RUN_DIR" \
  --output saved-run-diff.json
```

Use the exact `run_dir` printed by the CLI or returned by the Python API. Do not
recursively select a report or infer the newest directory.

The comparator validates supported artifacts and comparison semantics, but does
not establish independent reference authority, protected policy, candidate
identity, credentials/deployment identity, or protected final gate.

`monitor --once` is monitoring/alerting behavior rather than the approval
decision. `--no-fail` can preserve demo/diagnostic output but its zero exit must
never be treated as approval.

## 7. Tested contract: tenant-scoped business service

Use `contracts/examples/tenant-isolation.yaml`.

The canonical example is parser-tested. It uses the same permitted tenant-A
identity for its positive control and tenant-B negative resource probe, an
explicit `GUARD_DEMO_DENIED` marker, and a synthetic confidentiality canary.

## 8. Tested contract: local developer tooling

Use `contracts/examples/local-coding-assistant.yaml`.

The canonical example is parser-tested. It configures an explicit synthetic
`GUARD_DEMO_SECRET` canary for `response_not_contains_env` and an explicit
`GUARD_DEMO_DENIED` path-denial convention. Never use real cloud, GitHub,
registry, or production credentials just to make the example testable.

For a real local MCP deployment, add restricted STDIO launch with actual
reviewed executable and cwd paths. Restricted launch is policy hardening, not
an OS sandbox.

## 9. Commented contract fragment: delayed metadata / rug-pull check

```yaml
tools:
  format_text:
    permitted_identities: [reviewer]
    probe_arguments:
      text: reviewed-canary
    side_effect_identity: reviewer
    read_only: true

temporal_integrity:
  enabled: true
  identity: reviewer
  driver_tool: format_text

  # Safe call used only to advance the session.
  driver_arguments:
    text: temporal-canary

  sessions: 2
  retests_per_session: 5

  # Re-read metadata after every call.
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

## 10. Python embedding pattern

```python
import asyncio

from mcp_behaviour_guard import run_contract


async def verify_mcp_server() -> None:
    result = await run_contract(
        "contracts/server.yaml",
        output="reports/automation-run",
    )

    print("assessment:", result.summary.assessment.value)
    print("run_dir:", result.run_dir)

    if result.summary.assessment.value != "pass":
        raise RuntimeError(f"MCP security contract did not pass: {result.summary.assessment.value}")


asyncio.run(verify_mcp_server())
```

Use the Python API when Guard is embedded in a larger orchestrator. Prefer the CLI when standard exit codes and CI shell composition are simpler.

## 11. What to protect outside Guard

For approval-grade automation, separately protect:

- the reviewed contract;
- the approved saved reference;
- the exact Guard build/version;
- the candidate commit or build digest;
- test identity/credentials;
- fixture/deployment identity;
- workflow/job identity;
- final gate logic.

This is why a trustworthy CI/reference-authority demonstration is separate from saved-run artifact integrity.
