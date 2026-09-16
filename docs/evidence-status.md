# Interpreting a run

A negative test needs two things: a permitted identity must complete a positive call, and the denied call must return a contract-declared denial signal. A failed connection, timeout, invalid argument or generic MCP `isError` result cannot establish denial.

The JSON report separates invocation, finding and run-level fields:

| Field | Meaning |
| --- | --- |
| `authorization` | `allow`, `deny`, `unknown`, or `not_applicable` |
| `execution` | `succeeded`, `rejected`, `failed`, `timeout`, `not_attempted`, or `unknown` |
| `observation` | `complete`, `partial`, `unavailable`, or `not_required` |
| `assessment` | `pass`, `fail`, `inconclusive`, or `not_tested` |

`observation` is attached to findings that need side-effect evidence. A prohibited effect still fails if one observer is down. Without a prohibited effect, partial or unavailable coverage is inconclusive. Replay also needs a successful call and at least one matching observed effect before it can pass.

Replay and state-changing behaviour probes require healthy observers that cover the effect kinds needed by that check. An unrelated observer outage does not by itself block execution, but missing required coverage makes the result partial or unavailable rather than clean evidence.

Malformed audit events are an observer error. They must not be quietly dropped and mistaken for an empty, healthy audit stream.

CLI exit codes: 0 for pass, 1 for a confirmed failed claim, 2 for an inconclusive or untested run. `--no-fail` overrides those codes for demonstrations.

Invocation arguments, tool responses, prompt payloads and session identifiers are omitted from exported run evidence. Known configured secrets and bearer tokens are filtered from remaining strings. Tool metadata, observer details and filenames can still contain sensitive business information. Use synthetic fixtures, restrict artifact access and review reports before forwarding them to CI or a SIEM.

This development version still uses MCP Python SDK 1.28.1. Its HTTP tests and session language apply to the legacy stateful protocol. Do not use a clean temporal result as evidence of current `2026-07-28` stateless protocol behaviour until the SDK migration and compatibility suite have been completed.
