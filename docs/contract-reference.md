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
- `side_effect_identity`: permitted identity used for side-effect observation.
- `read_only`: prohibits observed filesystem, database, process and messaging writes.
- `allowed_network_destinations`: glob patterns matched against observer destinations.
- `allowed_filesystem_writes`: glob patterns matched against observer paths.
- `allowed_process_commands`: exact/glob patterns for observed process command strings.
- `forbidden_side_effects`: side-effect kinds that always fail.
- `tenant_probes`: identity-specific cross-tenant inputs.
- `policy_probes`: custom deterministic response/security checks.
- `replay_probe`: concurrent duplicate-call configuration.

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
