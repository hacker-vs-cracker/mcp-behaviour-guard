# Contract reference

## `metadata`

Generated drafts include:

- `generated_draft`: indicates that discovery created the file;
- `generated_at`: generation timestamp; and
- `notes`: mandatory review warnings and compiler provenance.

## `server`

Common fields:

- `name`: human-readable target name.
- `transport`: `streamable-http` or `stdio`.
- `timeout_seconds`: per-client timeout.
- `environment`: environment variables inherited by a STDIO server process.

Streamable HTTP fields:

- `url`: MCP endpoint.
- `verify_tls`: disable only for authorized local labs.
- `allowed_hosts`: hosts accepted by local target validation.

STDIO fields:

- `command`: executable used to launch the server.
- `args`: argument list passed without shell interpolation.
- `cwd`: child-process working directory.

## `identities`

An identity may declare:

- HTTP `headers`;
- STDIO `environment`;
- `tenant`;
- `role`; and
- a description.

Values support `${NAME}` and `${NAME:-default}` expansion. Do not commit real tokens. Prefer environment variables without defaults outside local demos.

## `tools`

- `permitted_identities`: identities expected to invoke the tool successfully.
- `probe_arguments`: safe schema-valid input used by access and behaviour probes.
- `denial_error_markers`: optional case-insensitive phrases in a tool error that the contract identifies as a denial. An `isError` result alone is not a denial. Prefer a documented structured denial code when the server provides one. A phrase can also appear in a business or validation error, so review it against the target and run a permitted positive control.
- `side_effect_identity`: permitted identity used for side-effect observation.
- `read_only`: prohibits observed filesystem, database, process and messaging writes.
- `allowed_network_destinations`: network side-effect policy.
- `allowed_filesystem_writes`: filesystem-write side-effect policy.
- `allowed_process_commands`: process-execution side-effect policy.

For these three allowlist fields:

- omitted or `null`: no policy claim for that effect family;
- `[]`: deny all effects of that family and require matching observer coverage;
- a non-empty list: allow only matching effects and require matching observer coverage.

v0.4.3 corrects empty-list semantics. Contracts that previously used `[]` only as
a placeholder should use `null` instead. User-authored `[]` values are not
automatically migrated because `[]` now means an intentional deny-all claim.
- `forbidden_side_effects`: side-effect kinds that always fail.
- `tenant_probes`: identity-specific cross-tenant inputs.
- `policy_probes`: custom deterministic response/security checks.
- `replay_probe`: concurrent duplicate-call configuration.

Replay probes require at least one observed effect (`minimum_events`, default 1) and enforce `maximum_events` (default 1). No observed effect is inconclusive, not proof of idempotency.

Supported side-effect kinds:

- `network_request`
- `filesystem_write`
- `database_write`
- `process_execution`
- `message_dispatch`
- `credential_access`

## `policy_probes`

A policy probe selects an identity, arguments, severity and one or more checks.

Supported checks:

### `denied`

The tool call must be rejected.

### `path_within`

A response path must resolve within one of the approved roots.

```yaml
checks:
  - type: path_within
    response_path: path
    roots:
      - /approved/workspace
```

### `response_not_contains_env`

The response must not contain values from named environment variables.

```yaml
checks:
  - type: response_not_contains_env
    env_names: [API_TOKEN, CLOUD_SECRET]
```

### `response_not_contains`

The normalized response must not contain the declared literal values.

## `tenant_probes`

A tenant probe supplies arguments expected to target a forbidden object. `resource_tenant_path` is a dotted path into the normalized response. `require_denial: true` is strongest: any successful call fails even if the response lacks tenant metadata.

## `session_tests`

A session test writes a unique marker using one identity/session and reads using another. For STDIO, each identity can launch an independent child process. The check fails when the second response contains the marker.

## `observers`

### HTTP audit observer

```yaml
runtime:
  type: http_audit
  events_url: http://127.0.0.1:8000/audit/events
  reset_url: http://127.0.0.1:8000/audit/reset
```

The event endpoint returns a list or `{ "events": [...] }`.

### Filesystem observer

```yaml
workspace:
  type: filesystem
  roots: [demo_runtime]
  ignore: ["*.tmp"]
```

The filesystem observer compares before/after snapshots. It can detect persistent
creates, modifications, and deletions, but it cannot prove that no transient
write occurred between snapshots. Its filesystem coverage is therefore reported
as partial; use an event-backed JSONL or HTTP audit observer when complete
filesystem-write assurance is required before a mutating probe can run.

When multiple configured roots share the same basename, exported event paths use
`<basename>#<n>/...` labels (for example `data#1/file.txt`) so evidence remains
unambiguous without exporting absolute host paths.

### JSONL audit observer

```yaml
stdio_audit:
  type: jsonl_audit
  path: demo_runtime/stdio/audit.jsonl
  truncate_on_begin: true
```

JSONL is useful for controlled local demos. It is not a substitute for independent OS observation against an untrusted native process.

## `alerts`

```yaml
alerts:
  enabled: true
  webhook_url: ${MCP_GUARD_WEBHOOK}
  minimum_severity: high
  only_new: true
  repeat_after_hours: 24
```

- `minimum_severity`: alert threshold; `high` includes critical.
- `only_new`: suppress a previously fingerprinted finding.
- `repeat_after_hours`: optional reminder interval for unresolved findings.

## `safety`

- `destructive_tests`: permits replay probes in this contract.
- `require_lab_mode`: documents that explicit lab mode is expected.
- `target_allowlist`: prevents execution against undeclared HTTP hosts.
- `allowed_stdio_commands`: allows only named local executables.

Replay tests run only when `destructive_tests` is true and the CLI receives `--lab-mode`.


## `temporal_integrity`

Temporal integrity is disabled unless explicitly configured. It is intended for servers whose metadata may change after initial discovery.

```yaml
temporal_integrity:
  enabled: true
  identity: reviewer
  driver_tool: format_text
  driver_arguments:
    text: behaviour-guard-canary
  sessions: 2
  retests_per_session: 5
  delay_between_calls_ms: 0
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

- `driver_tool`: reviewed tool used to advance the runtime gate. It must be marked `read_only: true` in `tools` and be permitted for the selected identity.
- `retests_per_session`: number of repeated calls in one MCP session; allowed range is 1-50.
- `sessions`: independent sessions to run; allowed range is 1-10.
- `rediscover_after_each_call`: compare metadata after every driver call rather than only at the end.
- `prompt_probes`: optional `prompts/get` calls included in the fingerprint.
- `stop_on_first_drift`: stop once the first reproducible drift checkpoint is written.

State-changing tools are not valid temporal drivers. The existing destructive-test/lab-mode gate still applies to replay and other state-changing checks elsewhere in the contract. A finite number of temporal calls cannot prove that a server has no delayed, probabilistic or client-specific trigger.

## MCP host configuration provenance

```bash
mkdir -p policy
mcp-guard config snapshot .vscode/mcp.json --output policy/vscode-mcp.json
mcp-guard config check .vscode/mcp.json policy/vscode-mcp.json
```

Snapshots keep server transport, endpoint/command, arguments, working directory and redacted environment/header structure. Additional server controls are retained as privacy-preserving fingerprints so changes to fields such as enablement, sandboxing, OAuth/TLS, timeouts and tool filters are not silently ignored. VS Code-style top-level `sandbox` and `inputs` blocks are fingerprinted as host controls. JSON, JSON-with-comments and common JSON5-style host configuration syntax are accepted. A drift result means the definition changed and needs review; it is not a malware verdict.
