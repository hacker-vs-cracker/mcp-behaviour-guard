# Temporal integrity

Some MCP servers are dynamic by design. That makes metadata changes legitimate in some systems, but it also means a one-time discovery pass cannot establish that an approved tool stays the same later in the session.

The temporal-integrity check keeps one MCP connection open, captures an initial metadata snapshot, makes a configured number of safe tool calls, then re-fetches the selected metadata families. Tool, prompt, prompt-payload and resource entries are canonicalized and hashed. A changed hash produces a structural before/after diff and a finding; the check evaluates structural drift rather than wording intent.

The first snapshot in a run is the reference for **within-run temporal drift**. It is not automatically a previously human-approved definition. Use the reviewed contract, normal behaviour baselines, and host-configuration provenance alongside this check when you need an approval-time reference.

## Why a human-selected driver tool

The scanner needs an operation that can advance a call-count or server-state gate without introducing its own write. The contract therefore names the driver and its arguments, and configuration validation requires that tool to be marked `read_only: true` and permitted for the selected identity. Use inert test input. State-changing tools are rejected as temporal drivers rather than made acceptable by `--lab-mode`.

## Evidence

Each enabled run writes files under `reports/<run-id>/temporal/`:

- initial metadata snapshot per session;
- post-call snapshots at configured checkpoints;
- structural diff files when metadata changes; and
- notifications observed on the MCP connection.

The main report records the first session/call where drift was observed.

## What it can and cannot show

It can show that metadata changed during the exact sequence tested. It cannot prove that a server will never change after a larger call count, a time delay, a particular client fingerprint, a particular identity, a restart, or a probabilistic trigger.

This is why the feature complements reviewed contracts, scheduled tests, host configuration provenance and runtime enforcement rather than replacing them.

## Attack-informed origin

The feature was added after Pillar Security's August 2026 Deadbugz disclosure described an MCP server whose metadata changed after three benign tool calls. The local demo copies the timing pattern only; its changed metadata is explicitly synthetic and performs no credential or network operation.

Source: https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign
