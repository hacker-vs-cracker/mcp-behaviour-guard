# R7 Tri-State Side-Effect Claims Design

Date: 2026-09-17  
Branch: `fix/evidence-integrity-v0.4.3`  
Baseline before this design: `021b09406e41622f5f3399200dc491133cd5027a`

## 1. Problem

`ToolContract` currently defines these fields as lists with an empty-list default:

- `allowed_network_destinations`
- `allowed_filesystem_writes`
- `allowed_process_commands`

The engine currently checks those fields by truthiness. As a result, `[]` is treated as if no side-effect claim exists. That is the wrong contract semantics for R7.

The corrected semantics are:

- omitted or `null` = no claim is being made for that effect family;
- `[]` = deny all observed effects of that family;
- a non-empty list = allow only matching observed effects.

The current contract generator also emits `[]` for all three fields even though discovery cannot know the approved side-effect policy. Under the corrected semantics that would accidentally create deny-all policy claims. Generated drafts therefore need to emit an explicit no-claim state instead.

## 2. Goals

1. Make “no claim”, “deny all”, and “allowlist” three distinct contract states.
2. Make required observer coverage and violation detection derive from the same internal claim representation.
3. Preserve the existing rule that confirmed observed violations outrank observation uncertainty.
4. Preserve R4: if a potentially mutating invocation has a declared effect claim and required observation is unavailable, the invocation must not happen.
5. Keep generated contracts conservative: discovery must not invent approved or forbidden side-effect policy.
6. Make migration explicit for existing `[]` values rather than silently reinterpreting them.
7. Keep the correction bounded to v0.4.3.

## 3. Non-goals

This correction will not implement:

- R9 observer concurrency redesign;
- R10 hostile native-process sandboxing;
- assurance-pack locking;
- fleet/controller architecture;
- MCP SDK migration;
- a new observer backend merely to preserve an old demo baseline;
- broad report/UI redesign.

## 4. Public contract semantics

The three allowlist fields become nullable:

```python
allowed_network_destinations: list[str] | None = None
allowed_filesystem_writes: list[str] | None = None
allowed_process_commands: list[str] | None = None
```

YAML semantics:

| YAML value | Meaning | Requires matching observer coverage? | Violation rule |
|---|---|---:|---|
| field omitted | no claim | no | ignore this effect family unless another claim covers it |
| `null` | no claim | no | same as omitted |
| `[]` | deny all | yes | any observed event of that kind violates the contract |
| non-empty list | allowlist | yes | an observed event violates unless it matches the allowlist |

Omitted and `null` are intentionally semantically equivalent after parsing. Generated drafts should nevertheless write `null` explicitly so a reviewer can see that policy is undecided rather than accidentally assuming deny-all.

## 5. Interaction with existing claims

`forbidden_side_effects` remains an explicit deny-all claim for the listed effect kinds.

`read_only: true` remains an explicit deny-all claim for the existing state-changing kinds:

- `filesystem_write`
- `database_write`
- `process_execution`
- `message_dispatch`

R7 does not expand `read_only` to network activity. Network policy remains explicit through `allowed_network_destinations` or `forbidden_side_effects`.

If more than one mechanism covers the same effect kind, deny-all wins over an allowlist. This preserves the stronger security statement instead of weakening it silently.

Examples:

```yaml
# No network assertion.
allowed_network_destinations: null

# No network is allowed. Network observation is required.
allowed_network_destinations: []

# Only these destinations are allowed. Network observation is required.
allowed_network_destinations:
  - "*.internal.example:443"
```

## 6. Single internal claim model

Add one private engine representation for effective side-effect claims. It should describe, per `SideEffectKind`:

- whether a claim exists;
- whether it is deny-all or allowlist;
- the allowed patterns when applicable;
- the source of the claim where useful for evidence/debugging.

One helper, conceptually `_effect_claims(tool_contract)`, becomes the source of truth.

The following must derive from that same helper:

1. `_required_effect_kinds`
2. `_side_effect_violations`
3. “does this tool have a side-effect claim?” decisions in behaviour checks
4. guarded-invocation observation preflight decisions

There must be no remaining truthiness logic such as:

```python
if tool.allowed_network_destinations:
```

for deciding whether the policy exists. `[]` is a real claim and must not disappear because it is falsey.

## 7. Violation semantics

For an observed event:

- deny-all claim => violation;
- non-empty allowlist => violation when the relevant value does not match;
- no claim => no violation from that allowlist family;
- `forbidden_side_effects` => violation;
- `read_only` => violation for the existing state-changing kinds.

Relevant event fields stay unchanged:

- network: `destination`
- filesystem: `path`
- process: `command`

Confirmed violations remain failures even if another observer is partial or unavailable.

## 8. Observation and R4 interaction

Required observation coverage must be claim-driven.

For a potentially mutating invocation:

1. derive effective claims;
2. derive required effect kinds from those claims;
3. begin/preflight required observers;
4. if required coverage is unavailable, do not invoke;
5. otherwise invoke and collect evidence;
6. assess violations and observation completeness separately.

`--lab-mode` does not bypass missing required observation.

A `read_only` declaration is itself a side-effect claim and must not be treated as “observation not required” merely because the tool is labelled read-only.

The existing temporal-integrity driver path remains outside this R7/R4 migration. Temporal drivers must still be `read_only: true`; their dedicated bounded repeated-call behavior remains unchanged in v0.4.3. The ordinary behaviour check continues to surface observation limits for that tool.

## 9. Contract generator behavior

Discovery cannot determine what destinations, files, or process commands are authorized.

Generated tool drafts therefore must explicitly emit:

```yaml
allowed_network_destinations: null
allowed_filesystem_writes: null
allowed_process_commands: null
```

The generator must not emit `[]` for these fields unless a human or a later explicit policy compiler chooses deny-all.

Generated-draft notes and contract documentation should state:

- `null` = no claim yet; review required;
- `[]` = deny all and requires observer coverage;
- a non-empty list = allowlist and requires observer coverage.

The existing `_drop_none` behavior must not erase these three deliberate `null` values from generated tool policy. Implementation may special-case these policy keys rather than changing unrelated `None` serialization globally.

## 10. Existing contract migration

Every checked-in explicit empty allowlist must be reviewed by intent.

Rules:

- Keep `[]` where the demo genuinely asserts “none allowed” and the required effect kind can be observed.
- Change to `null` where the field was only a placeholder and the demo has no observer capable of proving the claim.
- Do not add a new observer only to preserve the previous CI baseline.

Expected migration considerations:

### HTTP demo

The HTTP lab already has observers for database writes, network requests, and filesystem writes. Explicit empty network/filesystem allowlists may remain `[]` where they intentionally mean deny-all.

Because `[]` becomes an active claim, observation status and generated `*-EFFECTS` findings may legitimately change. The post-fix demo baseline must be characterized once and the semantic CI verifier updated from actual output.

### STDIO demo

The JSONL observer covers filesystem writes and process execution, not network requests. Empty network allowlists that were boilerplate/no-claim must become `null` unless the project adds real network observation in a later phase.

Filesystem/process fields should retain `[]` or a non-empty list only when the demo intentionally makes that claim and the observer can cover it.

### Temporal demo

The side-effect allowlist placeholders should be `null` unless a real observer-backed claim is intended. `read_only: true` remains the separate state-changing side-effect claim, so the existing observation limitation remains visible rather than being hidden.

## 11. Compatibility

This is a deliberate semantics correction.

Backward compatibility behavior:

- contracts that omit the allowlist fields retain the current effective no-claim behavior;
- contracts using `null` explicitly are no-claim;
- contracts using explicit `[]` change from the current buggy no-claim behavior to deny-all;
- non-empty allowlists retain allowlist semantics.

This change must be called out in v0.4.3 release notes and the contract reference.

No automatic migration should silently convert a user-authored `[]` to `null`.

## 12. Evidence and serialization

Parsed omitted and `null` values may normalize to the same internal `None` representation.

Normal evidence may show `null` for no-claim fields when the normalized tool contract is serialized. That is acceptable and clearer than an empty list with ambiguous meaning.

The semantic contract hash should be based on the normalized parsed model, so omitted and explicit `null` produce the same effective policy state.

No raw secret-bearing values are introduced by this change.

## 13. Test strategy

Implementation must follow RED → GREEN.

Required focused tests:

1. omitted field => no claim, no required coverage;
2. explicit `null` => no claim, no required coverage;
3. explicit `[]` => deny-all and required coverage;
4. non-empty allowlist => required coverage and match enforcement;
5. the above for network, filesystem, and process effect families;
6. `forbidden_side_effects` remains deny-all;
7. `read_only` remains a claim for its existing state-changing kinds;
8. deny-all wins if another claim on the same kind is weaker;
9. guarded mutating invocation with explicit `[]` and missing/broken required observer => zero invocation;
10. generated drafts contain explicit `null` policy fields;
11. generated drafts do not silently create deny-all claims;
12. existing checked-in contracts still parse after deliberate migration;
13. no remaining claim-presence decision relies on list truthiness.

Existing R1-R6/R8 and R5 tests remain regression coverage.

## 14. Post-implementation verification

After focused unit tests, Ruff, mypy, and the full unit suite are green:

1. run exactly one local characterization of the affected STDIO, temporal, and HTTP demos;
2. record the new exact semantic finding baselines;
3. update `scripts/verify_demo_report.py` only from those observed results;
4. rerun the verifier/unit tests, not a second local integration pass;
5. commit the R7 correction separately;
6. push the branch;
7. inspect the GitHub Actions run produced by that push.

The previous pre-R7 characterization must not be reused if the corrected semantics change observation status or findings.

## 15. Commit boundaries

Keep the history reviewable:

- existing `aad98db`: R1-R4/R6-R8 correctness checkpoint;
- existing `021b094`: R5 CI hardening checkpoint;
- design-only commit: this specification;
- implementation commit: R7 tri-state correction and deliberate demo/verifier migration.

Do not bump the package version, tag, merge, publish, or create the v0.4.3 release during this correction.

## 16. Acceptance criteria

R7 is complete only when all of the following are true:

- `null`/omitted, `[]`, and non-empty allowlists have distinct tested semantics;
- `[]` requires observer coverage;
- `[]` flags every observed event of that effect family;
- `null`/omitted creates neither required coverage nor allowlist-family violations;
- coverage and violations come from the same effective claim model;
- guarded mutation honors the corrected claims before invocation;
- generated drafts explicitly use `null`, not `[]`, for undecided side-effect policy;
- checked-in contracts are deliberately migrated;
- documentation explains the migration;
- one fresh post-fix demo characterization is encoded in the CI verifier;
- the subsequent GitHub CI run passes.

