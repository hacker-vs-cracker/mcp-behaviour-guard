# Architecture

## Design goals

1. Deterministic pass/fail decisions.
2. Reproducible evidence for every failed check.
3. Safe defaults for state-changing tests.
4. Portable operation on macOS and Ubuntu.
5. Shared testing logic across Streamable HTTP and STDIO.
6. Small observer interfaces that can accept stronger sensors later.

## Main components

### Contract loader

`config.py` loads YAML, expands `${ENV_VAR}` placeholders and validates references between identities, tools and probes with Pydantic.

### Contract draft generator

`contract_tools.py` connects to an MCP server, discovers tool metadata and creates a conservative draft. Discovery can populate names, descriptions, input schemas and placeholder probe values. It deliberately cannot decide the organization's authorization policy.

### Tenant compiler

The tenant compiler combines a base contract, a CSV identity inventory and reusable role policy. It supports HTTP header credentials, STDIO environment credentials and optional per-tenant `allow_tools` or `deny_tools` exceptions.

### MCP client abstraction

`client.py` exposes one interface over:

- official SDK `streamable_http_client` sessions; and
- official SDK `stdio_client` child processes.

The engine does not need separate HTTP and STDIO rule implementations. Identity-specific headers or environment variables are applied by the client layer.

### Guard engine

`engine.py` executes these check groups:

- discovery and inventory;
- access matrix;
- runtime side effects;
- policy probes, including path and secret-response checks;
- tenant isolation;
- session isolation; and
- concurrent replay/idempotency.

The engine records every invocation before generating reports.

### Observers

Observers implement asynchronous `begin()` and `collect()` methods.

The MVP includes:

- `HttpAuditObserver` for controlled audit APIs and egress sinks;
- `FilesystemObserver` for created or modified files under declared roots; and
- `JsonlAuditObserver` for local STDIO child-process events.

An eBPF, OpenTelemetry, database-audit or proxy observer can implement the same protocol later.

### Evidence store

SQLite stores run metadata, invocations, findings and alert fingerprints. JSONL traces and report files are also written so evidence is not locked into SQLite.

### Reporting

`reporting.py` normalizes output across HTML, JSON, JUnit XML and SARIF. HTML findings are sorted by severity, presented as rows and expanded on demand to show expected, observed, evidence and remediation fields.

### Monitoring and alerting

`mcp-guard monitor` runs the same deterministic scan path on an interval. High/critical findings are fingerprinted and checked against SQLite before a generic webhook is sent. Monitoring can continue after transient cycle errors or fail fast with `--stop-on-error`.

### Baseline engine

A baseline stores tool metadata, response shapes and normalized side-effect signatures. Comparison is deterministic and does not use an LLM.

### Optional AI adviser

The Ollama adviser receives redacted contract metadata and tool schemas. It can propose candidate tests, but there is no code path from its output to a finding result.

## Trust boundaries

The target server, its descriptions, returned data, project files and optional AI suggestions are untrusted. The human-reviewed contract, allowlists, observer evidence and deterministic evaluation code form the decision boundary.

The demo audit APIs and JSONL events are useful because the demos are controlled. For an independent assessment, prefer evidence generated outside the target process, such as a restricted proxy, container filesystem, database audit log, OpenTelemetry collector or OS-level sensor.
