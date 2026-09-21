# Changelog

## Unreleased
- Add opt-in restricted STDIO launch policy with canonical executable/cwd approval, minimal parent-environment inheritance, authoritative Guard identity metadata, and launcher-path preservation for virtualenv/wrapper semantics; keep legacy STDIO behaviour unchanged and document that this is policy hardening rather than OS-level sandboxing.
- Extend opt-in MCP metadata correlation to shared HTTP audit streams using non-destructive begin snapshots and append-only suffix attribution; keep legacy uncorrelated HTTP reset behavior unchanged.
- Add opt-in MCP metadata correlation for shared JSONL audit streams, attribute events to the current Guard operation, fail closed on missing or malformed required correlation, preserve partial observer evidence, and keep Guard correlation data out of exported evidence.
- Add opt-in bounded settling and position-based deduplication for JSONL and HTTP effect observers, preserving confirmed runtime events while downgrading inconsistent later telemetry.
- Expand supported CPython versions from 3.11 to 3.11-3.14, align `mcp-guard doctor`, and add an Ubuntu CI compatibility matrix while keeping primary Docker/integration execution pinned to 3.11.14.
- Serialize overlapping same-host, same-user Guard runs and observer windows for matching configured ownership keys so uncorrelated JSONL, HTTP, filesystem, and baseline evidence is not cross-attributed.
- Add internal per-operation observation identities for replay/check scoping without changing schema-v2 invocation evidence.
- Reject duplicate or overlapping observer sources and canonicalize target/resource aliases used for ownership.
- Harden POSIX same-host, same-user process leases with opaque lock names, stable `/tmp` namespace, ownership checks, restrictive permissions, deterministic lock ordering, and cancellation-safe release.

## 0.4.3 - 2026-09-17
- Harden exported target labels so normal evidence does not expose HTTP credentials, query/path data, or STDIO arguments.
- Preserve confirmed observer events through later malformed telemetry, detect JSONL continuity loss, and keep confirmed violations dominant over observation uncertainty.
- Bound snapshot filesystem observation to partial absence assurance and require complete matching observation before potentially mutating probes execute.
- Tighten denied-call confidentiality and relevant positive-control handling without treating generic invocation failure as authorization denial.
- Correct side-effect allowlists to tri-state semantics and centralize effect-claim handling for both observation requirements and violation assessment.
- Reject nested contract typos and duplicate YAML keys with secret-safe validation errors while preserving intentionally flexible payload maps.
- Strengthen CI with semantic demo-report verification, immutable action pins, explicit runner-image validation, UID/CLI smoke checks, and multi-architecture build validation.

## 0.4.2 - 2026-09-17
- Document normal PyPI installation separately from source/development setup for the included labs.
- Add OpenAI Codex and clarify that MCP-capable hosts are tested at the configured MCP server boundary, not as reasoning benchmarks.
- Add PyPI, CI, Python and license badges plus bounded Trusted Publishing and attestation provenance wording.
- Remove the completed v0.4.1 manual publishing recovery path and v0.4.1-specific artifact hash exception; normal release-event Trusted Publishing remains unchanged.

## 0.4.1 - 2026-09-17
- Fix the duplicated Safety and limitations heading in the README.
- Add package-index project links for the repository, issue tracker and changelog.
- Modernize MIT license metadata to the SPDX/PEP 639 format.
- Prepare package metadata for the initial PyPI publication.

## 0.4.0 - 2026-09-16
- Distinguish confirmed denials from failed connections and generic tool errors.
- Require a working positive control before a negative authorization check passes.
- Report observer outages and zero-effect replay runs as inconclusive.
- Do not start replay or state-changing behaviour probes when required observers fail to start.
- Omit raw invocation arguments and responses from exported traces and reports.
- Expose the contract runner to Python callers and add a separate CLI runner image.
- Keep MCP SDK v2 migration and PyPI publishing out of this patch.

## 0.3.0

- Removed the optional suggestion command and its external suggestion-service probe from the CLI.
- Added persistent-session temporal-integrity checks with configurable re-tests per session.
- Temporal drivers are contract-validated as reviewed read-only tools before execution.
- Added deterministic fingerprints and before/after evidence for tool, prompt and resource metadata.
- Added prompt payload probes and capture of MCP list-change notifications.
- Added a harmless three-call sleeper demo that changes metadata without touching credentials or external services.
- Added redacted MCP host-configuration snapshot/diff commands for supply-chain provenance checks, including additional server controls and VS Code-style sandbox/input blocks.
- Added JSONC/JSON5-style parsing for common editor MCP configuration files.
- Added CI coverage that verifies the temporal demo detects drift after the third call.
- Kept the MCP Python SDK pinned at `1.28.1`; SDK 2.x / protocol 2026-07-28 subscription handling is intentionally left for a separately validated migration.


## 0.2.0

- Added first-class STDIO transport support.
- Added a deliberately vulnerable local-agent MCP demonstration.
- Added conservative contract draft generation from MCP discovery.
- Added CSV and role-policy tenant compilation with per-tenant allow/deny exceptions.
- Added deterministic path-boundary and inherited-secret response probes.
- Added JSONL side-effect observation for controlled STDIO labs.
- Added interval monitoring, high/critical webhook alerts and SQLite deduplication.
- Improved HTML reports with critical-first rows, filtering and expandable evidence.
- Added MCP configuration examples for local and editor-based clients.
- Added macOS launchd and Ubuntu cron scheduling templates.
- Added HTTP and STDIO integration checks to CI.

## 0.1.0

- Initial Streamable HTTP security-contract harness.
- Authorization, tenant isolation, session isolation, side-effect, replay and baseline checks.
- SQLite, HTML, JSON, JUnit and SARIF reporting.
