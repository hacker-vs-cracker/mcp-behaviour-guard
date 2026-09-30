# Saved-run comparison

`mcp-guard baseline compare-saved` compares two previously generated MCP Behaviour Guard run
directories without contacting the target MCP server.

Use it when a team wants to compare a reviewed reference run with a candidate run while keeping
current conformance, regression, coverage, capability drift, and comparison context separate.

## Artifacts to retain

Keep the run directory together. For offline comparison, the important files are:

- `report.json` - required schema-v2 findings and run metadata;
- `receipt.json` - required external receipt sidecar that binds the saved run context and artifact
  digests;
- `tool-inventory.json` - retain it when the receipt declares a tool-inventory digest.

HTML, JUnit, SARIF, traces, and other reports can still be useful operational evidence, but
`compare-saved` does not reconstruct a missing `report.json` from them.

`receipt.json` is written beside the reports. The public `RunResult.reports` list currently contains
the normal report files and does not include the receipt sidecar. Preserve the whole run directory
rather than relying only on that list.

## Active baseline versus offline saved-run comparison

These are different operations.

| Command | Contacts target | Purpose |
|---|---:|---|
| `mcp-guard baseline capture CONTRACT` | Yes | Capture the target's current tools, response shapes, and configured side-effect observations. |
| `mcp-guard baseline compare CONTRACT BASELINE` | Yes | Capture the target again and compare it with an active behavioural baseline. |
| `mcp-guard baseline compare-saved REFERENCE_DIR CANDIDATE_DIR` | No | Compare two already-saved run artifact directories. |

The offline comparator must not call the MCP target, run a contract, or capture a new baseline.

## Basic use

```bash
REFERENCE_RUN_DIR="reports/reference-root/<reference-run-id>"
CANDIDATE_RUN_DIR="reports/candidate-root/<candidate-run-id>"

mcp-guard baseline compare-saved \
  "$REFERENCE_RUN_DIR" \
  "$CANDIDATE_RUN_DIR" \
  --output saved-run-diff.json
```

The JSON result is also printed to the terminal.

## Exit codes

| Exit | Meaning |
|---:|---|
| `0` | The artifacts are supported and comparable, the candidate currently conforms, and no comparison dimension requires review. |
| `1` | The artifacts were readable, but review is required because context changed, candidate conformance is non-pass, a regression/coverage issue exists, or capability comparison requires review. |
| `2` | The saved artifacts or comparison are invalid/unsupported, including incompatible normalization, unsupported identity/context transitions, or unverified sensitive semantic fields. |

An exit code is a gate signal, not a substitute for reading the result dimensions.

## Result dimensions

The comparator deliberately keeps several questions separate:

- **comparability** - whether the two saved runs can be interpreted as the same declared comparison
  context, a changed context, or an unsupported comparison;
- **conformance** - whether each run's findings represent a pass, fail, or non-pass assessment;
- **regression** - new/fixed/persistent failures, errors, status changes, and severity changes;
- **coverage** - missing/new/skipped checks, observation changes/regressions, and loss of a declared
  capability inventory;
- **capabilities** - tool inventory additions, removals, or changed schemas that may require review;
- **freshness** - currently explicit `unknown`; the comparator does not infer evidence age or TTL.

A target input digest change is informational by design because a candidate target/version can be the
intended variable under test. It does not independently authorize the candidate.

## Comparability and `unknown_fields`

Some receipt context can legitimately be unknown. When both sides have the same unknown field, the
comparison can remain usable for exploratory declared-contract regression analysis and the field is
listed in `comparability.unknown_fields`.

That does **not** prove approval-grade identity equivalence. In particular, an exit `0` with
`unknown_fields` must not be described as cryptographic proof that deployment, principal, runner,
or other external identity was independently authorized.

One-sided known/unknown identity transitions fail closed. Known context changes are classified by
their semantics rather than silently treated as equivalent.

## Normalization version 3

Current saved-run comparison requires:

```text
receipt schema:        1
normalization version: 3
report schema:         2
```

Normalization v3 makes credential-map and semantic-argument handling depend on
their structural model path rather than the spelling of a named-map entry. A
valid tool, identity, tenant-probe key, or other named entry such as `headers`
or `environment` therefore cannot select credential-map behavior merely by
name.

V3 preserves the intended v2 behavior for typed semantic numbers/booleans and
known credentials, while correcting released v2 inputs that could otherwise be
emitted as comparison-eligible under the wrong structural interpretation.

Normalization v1, v2, and v3 digests are not assurance-equivalent. Historical
v1/v2 receipts remain immutable historical evidence. The corrected comparator
accepts v3 for approval-style saved-run comparison.

**Migration:** generate fresh runs with the corrected v3 writer. Do not edit or
rewrite historical receipts.

## Secret and ambiguous-value treatment

The receipt writer is designed to avoid exporting known secret values while preserving meaningful
comparison semantics:

- known credentials and known secret values use stable redaction markers;
- typed semantic values such as numbers and booleans remain meaningful even when their key contains
  words such as `token`, `secret`, or `credential`;
- an arbitrary sensitive-looking semantic string that cannot be safely classified is replaced by a
  non-secret marker and recorded in `normalization.unverified_sensitive_fields`;
- a receipt with non-empty `unverified_sensitive_fields` is not eligible for approval-style saved-run
  comparison and exits `2`.

This is intentionally bounded handling. MCP Behaviour Guard is not a general secrets-management
platform.

## Integrity is not provenance or approval

`receipt.json` binds details such as:

- report digest;
- optional tool-inventory digest;
- contract source digest;
- policy/check projections;
- runner and transport context;
- logical target and available identity/deployment context.

Those bindings help detect missing, inconsistent, or changed artifacts. They do **not** by themselves
prove that:

- the reference was approved by an independent authority;
- the candidate commit/build was authorized;
- the contract/policy was protected from candidate modification;
- credentials, deployment, or CI job identity came from a trusted external authority.

Those stronger trust bindings belong to a later trusted CI/reference-authority layer.

## Important residual limits

- Freshness/TTL is not inferred; `freshness` remains `unknown`.
- Comparison covers saved findings and declared capability inventory, not a universal event
  canonicalization engine.
- A missing or digest-mismatched `report.json` fails closed.
- Optional inventory absence is represented explicitly rather than reconstructed.
- Offline comparison is only as trustworthy as the provenance and protection of the artifacts supplied
  to it.
