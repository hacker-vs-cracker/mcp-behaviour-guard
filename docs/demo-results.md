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


## Temporal metadata-drift lab

The temporal demo is intentionally harmless. `format_text` only returns supplied text. The server changes its tool description and a prompt payload after the third successful call in the same STDIO session, then emits tool/prompt list-change notifications.

```bash
mcp-guard run contracts/temporal-demo.yaml --no-fail
```

Expected result: `TEMPORAL-METADATA-001` fails at **high** severity and records `first_drift.after_call: 3`, along with before/after metadata snapshots under the run's `temporal/` evidence directory.


## v0.3 local validation

The v0.3 release candidate was exercised against the real Python 3.11 MCP environment before release.

### Temporal integrity

The inert temporal demo completed normally and produced:

- `TEMPORAL-METADATA-001`: **high / failed**, as intentionally planted;
- metadata drift detected after call **3** in the same MCP session;
- changed tool metadata: `format_text`;
- changed prompt payload: `assistant_guidance`;
- captured `notifications/tools/list_changed`;
- captured `notifications/prompts/list_changed`;
- no temporal execution errors.

The failed contract result is the expected security outcome: the server violated the approved metadata-stability contract.

### Existing STDIO regression

The original deliberately vulnerable STDIO lab remained unchanged in behaviour:

- 24 checks total;
- 14 passed controls;
- 10 intentionally planted failures;
- no unexpected execution errors.

### Existing Streamable HTTP regression

The original deliberately vulnerable HTTP lab remained unchanged in behaviour:

- 32 checks total;
- 25 passed controls;
- 7 intentionally planted failures;
- no unexpected execution errors.

### Host-configuration provenance

A clean approved configuration produced:

- `drift_detected: false`;
- process exit code `0`.

A simulated configuration change then added a second MCP server and changed a host sandbox control. Behaviour Guard produced:

- `drift_detected: true`;
- process exit code `1`;
- added server: `review-me`;
- `host_controls_changed: true`.

A dummy Authorization value used during the test was not present verbatim in either the approved baseline or generated drift evidence.
