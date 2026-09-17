# Changelog

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
