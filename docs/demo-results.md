# Demonstration results

The deliberately vulnerable labs are expected to fail. A successful harness run means the guard completes normally, produces evidence and confirms the planted defects.

## Streamable HTTP lab

A validated lab run produced 32 checks:

- 25 passed controls or expected denials;
- 7 confirmed failures;
- 0 unexpected execution errors.

Confirmed categories:

| Category | Evidence-backed result |
|---|---|
| Tool authorization | Non-administrator identities invoked the administrator-only `customer_update` tool |
| Tenant isolation | Tenant A retrieved a Tenant B customer record |
| Undeclared egress | `customer_lookup` contacted the mock telemetry service |
| Undeclared filesystem write | the independent watcher observed a read-only tool modify a cache file |
| Session isolation | a Tenant B session read a marker written by Tenant A |
| Replay/idempotency | three concurrent calls with the same operation ID produced three writes |

Run it with:

```bash
docker compose up --build -d
mcp-guard run contracts/http-demo.yaml --lab-mode --no-fail
```

## STDIO local-agent lab

The STDIO server is launched separately for identity contexts and logs controlled audit events to JSONL. It contains planted defects for:

| Category | Evidence-backed result |
|---|---|
| Path boundary | `workspace_read` resolves `../agent-secrets.txt` outside the approved workspace |
| Secret handling | `diagnostics` returns the inherited `DEMO_AGENT_TOKEN` value |
| Tool authorization | restricted/anonymous contexts can reach tools outside their policy |
| Process policy | `run_project_task` constructs an undeclared command containing injected shell text |
| Session isolation | state written by one local agent process is readable by another |

The unsafe command is recorded as evidence and is never executed.

Run it with:

```bash
export DEMO_AGENT_TOKEN=local-demo-token
mcp-guard run contracts/stdio-demo.yaml --lab-mode --no-fail
```

Open the generated `index.html` or the committed [sample report](sample-stdio-report.html) to review critical-first expandable rows.
