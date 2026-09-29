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

Retain the whole run directory, including `report.json`, `receipt.json`, and any declared tool inventory.

Offline regression comparison:

```bash
mcp-guard baseline compare-saved \
  reports/approved-reference \
  reports/candidate \
  --output saved-run-diff.json
```

The comparator can validate supported artifacts and comparison semantics, but it cannot establish by itself that:

- the reference came from an independent approval authority;
- the candidate could not modify the reference;
- the contract/policy was protected;
- credentials/deployment/job identity came from a trusted authority;
- the final CI gate was protected.

Those are the trust bindings for the separate trusted-CI/reference-authority layer.

The YAML below is intentionally a starter pattern. Complete deployment contracts also need
target-specific safety settings, observer configuration, report choices and any other claims required
by the assurance level you want. See `docs/contract-reference.md` for the full schema.

## 7. Commented contract: tenant-scoped business service

```yaml
version: 1

server:
  name: crm-mcp-staging
  transport: streamable-http
  url: https://crm-mcp.staging.example.com/mcp
  http_destination:
    # Do not silently send MCP/auth traffic to an unreviewed redirect origin.
    allowed_origins:
      - https://crm-mcp.staging.example.com
    allow_redirects: false

identities:
  support_a:
    tenant: tenant-a
    role: support
    headers:
      Authorization: Bearer ${SUPPORT_A_TOKEN}

  support_b:
    tenant: tenant-b
    role: support
    headers:
      Authorization: Bearer ${SUPPORT_B_TOKEN}

tools:
  customer_lookup:
    permitted_identities: [support_a, support_b]

    # Positive-control request for the allowed identity.
    probe_arguments:
      customer_id: tenant-a-synthetic-001

    side_effect_identity: support_a
    read_only: true

    # Active deny-all claims require matching observer coverage.
    allowed_network_destinations: []
    allowed_filesystem_writes: []

    tenant_probes:
      support_a:
        # Deliberately ask tenant A for a tenant B fixture.
        arguments:
          customer_id: tenant-b-synthetic-001

        resource_tenant_path: tenant
        expected_tenant: tenant-a
        require_denial: true

        # Synthetic protected tenant-B content.
        confidentiality:
          values:
            - SYNTHETIC_TENANT_B_PRIVATE_CANARY
```

## 8. Commented contract: local developer tooling

```yaml
version: 1

server:
  name: local-dev-mcp
  transport: stdio
  command: /project/.venv/bin/python
  args: [-m, company_mcp.devtools]
  cwd: /project

  stdio_launch:
    mode: restricted

    # Canonical interpreter identity reviewed by the team.
    allowed_executables:
      - /canonical/python3.11

    # Prevent launch from another checkout.
    allowed_cwd_roots:
      - /project

    # Explicitly inherit only what the child needs.
    inherit_environment:
      - PATH

identities:
  developer:
    role: developer
    tenant: local-workspace

tools:
  repo_read:
    permitted_identities: [developer]
    probe_arguments:
      path: README.md
    side_effect_identity: developer
    read_only: true

    policy_probes:
      - id: LOCAL-PATH-ESCAPE-001
        identity: developer
        arguments:
          path: ../outside-canary.txt
        severity: critical
        checks:
          - type: denied

  diagnostics:
    permitted_identities: [developer]
    probe_arguments: {}
    side_effect_identity: developer
    read_only: true

    policy_probes:
      - id: LOCAL-ENV-LEAK-001
        identity: developer
        arguments: {}
        severity: critical
        checks:
          - type: response_not_contains_env
            env_names:
              - AWS_SECRET_ACCESS_KEY
              - GITHUB_TOKEN
              - NPM_TOKEN
```

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
        raise RuntimeError(
            f"MCP security contract did not pass: "
            f"{result.summary.assessment.value}"
        )

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
