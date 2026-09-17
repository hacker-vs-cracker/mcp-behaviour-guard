# R7 Tri-State Side-Effect Claims Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct R7 so omitted/`null`, empty, and non-empty side-effect allowlists have distinct semantics, while preserving the existing mutation-safety boundary and producing a fresh post-fix demo baseline.

**Architecture:** `ToolContract` will represent side-effect allowlists as nullable lists. A single private engine claim model will normalize `read_only`, `forbidden_side_effects`, deny-all empty lists, and non-empty allowlists. Both required observer coverage and violation detection will consume that model. Generated drafts will explicitly emit `null` for undecided side-effect policy.

**Tech Stack:** Python 3.11.14, Pydantic v2, PyYAML, pytest, Ruff, mypy, Docker Compose for the existing HTTP demo.

**Spec:** `docs/superpowers/specs/2026-09-17-r7-tristate-side-effect-claims-design.md`

## Global Constraints

- Do not change package version `0.4.2`.
- Do not tag, merge, publish, release, or touch PyPI.
- Do not implement R9, R10, fleet/controller work, assurance-pack locking, or MCP SDK migration.
- Keep R1-R6/R8 and R5 behavior intact except where the corrected R7 semantics necessarily change demo findings.
- Omitted and explicit `null` mean no claim.
- Explicit `[]` means deny all and requires matching observer coverage.
- A non-empty list is an allowlist and requires matching observer coverage.
- `forbidden_side_effects` remains deny-all.
- `read_only: true` remains a claim that denies filesystem, database, process, and message writes.
- A stronger deny-all claim wins over an allowlist for the same effect kind.
- Generated drafts must show explicit `null` for the three undecided allowlist fields.
- Do not automatically rewrite a user-authored `[]` to `null`.
- Do not add observers solely to preserve the old demo baseline.
- Confirmed observed violations outrank incomplete observation.
- Preserve the R4 mutation gate: tools declared potentially mutating (`read_only: false`) with required effect claims are not invoked when required coverage is incomplete.
- Do not broaden that preflight gate to block ordinary authorization/tenant/policy calls solely because a tool is declared `read_only`; the `read_only` side-effect claim is assessed by the dedicated behaviour check. This avoids turning missing process/message observers into an authorization failure and keeps authorization separate from behaviour assurance.
- Temporal driver execution remains on the existing bounded temporal path; its `read_only` claim is still surfaced by the ordinary behaviour check.

---

## File Map

**Create**
- `tests/test_side_effect_claims.py` — focused tri-state claim and precedence tests.

**Modify**
- `src/mcp_behaviour_guard/models.py` — nullable allowlist fields.
- `src/mcp_behaviour_guard/engine.py` — central effect-claim model, required coverage, violation logic, and claim-presence checks.
- `src/mcp_behaviour_guard/contract_tools.py` — generated draft emits explicit `null`.
- `tests/test_observation_preflight.py` — remove the incorrect “empty means no claim” assertion and retain/extend mutation-preflight coverage.
- `tests/test_contract_tools.py` — generator-null regression coverage.
- `contracts/http-demo.yaml` — retain or change each explicit list by reviewed intent.
- `contracts/stdio-demo.yaml` — replace placeholder network policy with `null` where no network observer exists; keep intentional observer-backed claims.
- `contracts/temporal-demo.yaml` — use `null` for undecided allowlist placeholders; preserve `read_only: true`.
- `docs/contract-reference.md` — document tri-state semantics and v0.4.3 migration note.
- `scripts/verify_demo_report.py` — **not modified until after one fresh post-fix characterization**.
- `tests/test_ci_report_verifier.py` — update only if the characterized baseline requires fixture changes.

**Do not modify**
- `.github/workflows/ci.yml` during the semantic implementation; R5 is already remotely validated.
- `Dockerfile` / `Dockerfile.runner`.
- release/tag/PyPI configuration.

---

### Task 1: Make the contract model tri-state and add the central claim model

**Files:**
- Create: `tests/test_side_effect_claims.py`
- Modify: `src/mcp_behaviour_guard/models.py`
- Modify: `src/mcp_behaviour_guard/engine.py`
- Modify: `tests/test_observation_preflight.py`

**Interfaces:**
- Consumes: `ToolContract`, `SideEffectKind`, `SideEffectEvent`, `matches_any`.
- Produces:
  - `EffectClaim` private immutable record.
  - `_effect_claims(contract: ToolContract) -> dict[SideEffectKind, EffectClaim]`
  - `_required_effect_kinds(contract: ToolContract) -> set[SideEffectKind]`
  - `_side_effect_violations(contract: ToolContract, events: list[SideEffectEvent]) -> list[dict[str, Any]]`
  - `_has_effect_claims(contract: ToolContract) -> bool`

- [ ] **Step 1: Write RED model/claim tests**

Create `tests/test_side_effect_claims.py` with direct tests for all three effect families.

Use a helper:

```python
def _event(kind: SideEffectKind, **details: str) -> SideEffectEvent:
    return SideEffectEvent(observer="test", kind=kind, details=details)
```

Required assertions:

```python
def test_omitted_allowlists_mean_no_claim() -> None:
    tool = ToolContract(permitted_identities=["user"])
    assert tool.allowed_network_destinations is None
    assert tool.allowed_filesystem_writes is None
    assert tool.allowed_process_commands is None
    assert _required_effect_kinds(tool) == set()


def test_explicit_null_allowlists_mean_no_claim() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_network_destinations=None,
        allowed_filesystem_writes=None,
        allowed_process_commands=None,
    )
    assert _required_effect_kinds(tool) == set()


def test_empty_network_allowlist_is_deny_all() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_network_destinations=[],
    )
    event = _event(
        SideEffectKind.NETWORK_REQUEST,
        destination="example.invalid:443",
    )
    assert SideEffectKind.NETWORK_REQUEST in _required_effect_kinds(tool)
    assert _side_effect_violations(tool, [event])


def test_empty_filesystem_allowlist_is_deny_all() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_filesystem_writes=[],
    )
    event = _event(
        SideEffectKind.FILESYSTEM_WRITE,
        path="/tmp/out.txt",
    )
    assert SideEffectKind.FILESYSTEM_WRITE in _required_effect_kinds(tool)
    assert _side_effect_violations(tool, [event])


def test_empty_process_allowlist_is_deny_all() -> None:
    tool = ToolContract(
        permitted_identities=["user"],
        allowed_process_commands=[],
    )
    event = _event(
        SideEffectKind.PROCESS_EXECUTION,
        command="python build.py",
    )
    assert SideEffectKind.PROCESS_EXECUTION in _required_effect_kinds(tool)
    assert _side_effect_violations(tool, [event])
```

Also test:
- non-empty network/filesystem/process lists accept a matching event and reject a non-match;
- `forbidden_side_effects=[NETWORK_REQUEST]` denies even when a non-empty network allowlist would otherwise match;
- `read_only=True` requires filesystem/database/process/message coverage;
- `read_only=True` plus a filesystem allowlist still denies filesystem writes because deny-all wins.

- [ ] **Step 2: Replace the incorrect R7 test**

In `tests/test_observation_preflight.py`, replace:

```python
test_empty_network_allowlist_means_no_network_claim
```

with an assertion that explicit `[]` requires network coverage and flags a network event.

Keep the existing explicit `forbidden_side_effects=[network_request]` test because it checks a separate deny mechanism.

- [ ] **Step 3: Run focused tests and verify RED for semantics**

Run:

```bash
.venv/bin/python -m pytest \
  tests/test_side_effect_claims.py \
  tests/test_observation_preflight.py \
  -q --tb=short
```

Expected: failures showing current list defaults are `[]`, explicit empty lists do not create required coverage, and empty-list events are not violations.

Do not accept import/fixture/syntax errors as RED evidence.

- [ ] **Step 4: Make `ToolContract` nullable**

Change exactly these fields in `src/mcp_behaviour_guard/models.py`:

```python
allowed_network_destinations: list[str] | None = None
allowed_filesystem_writes: list[str] | None = None
allowed_process_commands: list[str] | None = None
```

Do not change `forbidden_side_effects`.

- [ ] **Step 5: Add the private normalized claim record**

Near the engine helper functions, add:

```python
@dataclass(frozen=True)
class EffectClaim:
    mode: Literal["deny_all", "allowlist"]
    patterns: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
```

Add `dataclass` and `Literal` imports.

Implement `_effect_claims()` so:
- `read_only` installs deny-all for filesystem/database/process/message;
- each `forbidden_side_effects` value installs deny-all;
- an allowlist field of `None` adds nothing;
- an allowlist field of `[]` installs deny-all;
- a non-empty list installs allowlist only when no deny-all already exists;
- deny-all always wins.

Use one mapping:

```python
_ALLOWLIST_CLAIMS = {
    SideEffectKind.NETWORK_REQUEST: (
        "allowed_network_destinations",
        "destination",
    ),
    SideEffectKind.FILESYSTEM_WRITE: (
        "allowed_filesystem_writes",
        "path",
    ),
    SideEffectKind.PROCESS_EXECUTION: (
        "allowed_process_commands",
        "command",
    ),
}
```

- [ ] **Step 6: Derive coverage and violations from the normalized claims**

Implement:

```python
def _required_effect_kinds(contract: ToolContract) -> set[SideEffectKind]:
    return set(_effect_claims(contract))


def _has_effect_claims(contract: ToolContract) -> bool:
    return bool(_effect_claims(contract))
```

Rewrite `_side_effect_violations()` to consult `_effect_claims()` exactly once.

Preserve the existing human-readable reasons where possible:
- explicit `forbidden_side_effects` → `"side-effect kind is explicitly forbidden"`;
- `read_only` state change → `"read-only tool caused a state-changing side effect"`;
- network mismatch → `"network destination is not allowlisted"`;
- filesystem mismatch → `"filesystem path is not allowlisted"`;
- process mismatch → `"process command is not allowlisted"`.

For an explicit empty allowlist, use the same “not allowlisted” reason for that family; no special new public reason is needed.

- [ ] **Step 7: Remove claim-presence truthiness from behaviour checks**

In `_check_tool_side_effects()`:
- replace the no-observer `read_only or forbidden or allowed_*` expression with `_has_effect_claims(tool)`;
- when observers exist, skip tools with no effective claims before beginning observers;
- keep required kinds from `_required_effect_kinds(tool)`;
- do not use nullable list truthiness to decide whether a claim exists.

In `_invoke_with_mutation_observation()`:
- preserve the existing early `read_only` authorization-path separation;
- for `read_only: false`, explicit `[]` must now create `required_kinds`, so missing/broken required coverage prevents invocation;
- `None`/omitted with no other effect claim remains `NOT_REQUIRED`.

- [ ] **Step 8: Run focused claim/preflight tests GREEN**

Run:

```bash
.venv/bin/python -m pytest \
  tests/test_side_effect_claims.py \
  tests/test_engine_rules.py \
  tests/test_observation_preflight.py \
  -q --tb=short
```

Expected: PASS.

- [ ] **Step 9: Verify no claim-presence truthiness remains**

Run:

```bash
grep -nE \
  'if .*allowed_(network_destinations|filesystem_writes|process_commands)|or tool\.allowed_(network_destinations|filesystem_writes|process_commands)' \
  src/mcp_behaviour_guard/engine.py
```

Expected: no output.

---

### Task 2: Make generated drafts explicit no-claim contracts

**Files:**
- Modify: `src/mcp_behaviour_guard/contract_tools.py`
- Modify: `tests/test_contract_tools.py`

**Interfaces:**
- Consumes: `generate_contract_draft()`, `write_yaml()`.
- Produces generated tool mappings that explicitly contain the three policy keys with `None`.

- [ ] **Step 1: Add a RED generator test**

Extend `tests/test_contract_tools.py` with an async test that monkeypatches `McpClient.list_tools()` to return one discovered tool, calls `generate_contract_draft()`, and asserts:

```python
tool = payload["tools"]["lookup"]
assert "allowed_network_destinations" in tool
assert tool["allowed_network_destinations"] is None
assert "allowed_filesystem_writes" in tool
assert tool["allowed_filesystem_writes"] is None
assert "allowed_process_commands" in tool
assert tool["allowed_process_commands"] is None
```

Write the payload with `write_yaml()`, load the YAML, and assert those keys remain present with YAML `null`.

- [ ] **Step 2: Run the generator test RED**

Run:

```bash
.venv/bin/python -m pytest \
  tests/test_contract_tools.py \
  -q --tb=short
```

Expected: FAIL because the current generator emits empty lists and/or `_drop_none()` removes `None`.

- [ ] **Step 3: Change generated side-effect policy to explicit `None`**

In `generate_contract_draft()` emit:

```python
"allowed_network_destinations": None,
"allowed_filesystem_writes": None,
"allowed_process_commands": None,
```

Preserve explicit `null` for these three keys when normalizing the generated payload.

Do not globally preserve every `None`; keep `_drop_none()` behavior for unrelated optional fields.

A bounded implementation is to make `_drop_none()` preserve a constant set:

```python
_EXPLICIT_NULL_POLICY_KEYS = {
    "allowed_network_destinations",
    "allowed_filesystem_writes",
    "allowed_process_commands",
}
```

and retain `None` only when the current key is in that set.

- [ ] **Step 4: Run generator tests GREEN**

Run:

```bash
.venv/bin/python -m pytest \
  tests/test_contract_tools.py \
  -q --tb=short
```

Expected: PASS.

---

### Task 3: Deliberately migrate the checked-in demos and document the semantics

**Files:**
- Modify: `contracts/http-demo.yaml`
- Modify: `contracts/stdio-demo.yaml`
- Modify: `contracts/temporal-demo.yaml`
- Modify: `docs/contract-reference.md`

**Interfaces:**
- Consumes: tri-state parsing from Task 1.
- Produces explicit reviewed intent for every checked-in demo policy.

- [ ] **Step 1: Migrate HTTP demo by observer-backed intent**

Keep explicit `[]` only where the HTTP lab genuinely says “none allowed” and an observer exists for that family.

Do not add process/message observers.

For fields that were only boilerplate and have no corresponding observer-backed policy claim, use `null`.

The HTTP observer set remains:
- database write via server audit;
- network request via telemetry;
- filesystem write via watcher.

- [ ] **Step 2: Migrate STDIO demo**

The existing JSONL observer covers filesystem/process effects.

Set placeholder network allowlists to:

```yaml
allowed_network_destinations: null
```

unless a specific STDIO tool is intentionally asserting a network deny policy backed by an actual network observer.

Keep filesystem/process `[]` or non-empty values only where the contract intentionally asserts those observer-backed boundaries.

- [ ] **Step 3: Migrate temporal demo**

Keep:

```yaml
read_only: true
```

Change undecided side-effect allowlist placeholders to:

```yaml
allowed_network_destinations: null
allowed_filesystem_writes: null
allowed_process_commands: null
```

Do not add new observers.

- [ ] **Step 4: Document tri-state behavior**

Under `docs/contract-reference.md` → `tools`, document exactly:

```text
For allowed_network_destinations, allowed_filesystem_writes, and
allowed_process_commands:

- omitted or null: no policy claim for that effect family;
- []: deny all effects of that family and require observer coverage;
- non-empty list: allow only matching effects and require observer coverage.
```

Add a short migration note:

```text
v0.4.3 corrects empty-list semantics. Contracts that previously used []
as a placeholder should use null instead. User-authored [] values are not
automatically migrated because [] now means an intentional deny-all claim.
```

- [ ] **Step 5: Validate all checked-in contracts parse**

Run:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
from mcp_behaviour_guard.config import load_contract

for path in sorted(Path("contracts").glob("*.yaml")):
    load_contract(path)
    print(f"CONTRACT_OK={path}")
PY
```

Expected: all three demo contracts print `CONTRACT_OK`.

---

### Task 4: Run static/focused/full verification before characterization

**Files:**
- No new production files.

**Interfaces:**
- Consumes all Tasks 1-3.
- Produces a verified working tree ready for the single post-fix characterization.

- [ ] **Step 1: Format and lint only changed Python files**

Run:

```bash
.venv/bin/ruff format \
  src/mcp_behaviour_guard/models.py \
  src/mcp_behaviour_guard/engine.py \
  src/mcp_behaviour_guard/contract_tools.py \
  tests/test_side_effect_claims.py \
  tests/test_observation_preflight.py \
  tests/test_contract_tools.py

.venv/bin/ruff check \
  src/mcp_behaviour_guard/models.py \
  src/mcp_behaviour_guard/engine.py \
  src/mcp_behaviour_guard/contract_tools.py \
  tests/test_side_effect_claims.py \
  tests/test_observation_preflight.py \
  tests/test_contract_tools.py

git diff --check
```

Expected: all PASS.

- [ ] **Step 2: Run mypy using the same CI target**

Run:

```bash
.venv/bin/mypy src/mcp_behaviour_guard
```

Expected: PASS.

- [ ] **Step 3: Run focused R7 and R5 verifier tests**

Run:

```bash
.venv/bin/python -m pytest \
  tests/test_side_effect_claims.py \
  tests/test_engine_rules.py \
  tests/test_observation_preflight.py \
  tests/test_contract_tools.py \
  tests/test_ci_report_verifier.py \
  tests/test_ci_workflow_hardening.py \
  -q --tb=short
```

Expected: PASS.

- [ ] **Step 4: Run the full unit suite once**

Run:

```bash
.venv/bin/python -m pytest -q --tb=short
```

Expected: PASS.

Do not repeat the full suite again before characterization unless source changes.

---

### Task 5: Characterize the corrected demos exactly once

**Files:**
- Do not edit `scripts/verify_demo_report.py` yet.

**Interfaces:**
- Consumes the uncommitted, fully unit-verified R7 implementation.
- Produces the exact new STDIO/temporal/HTTP findings needed for the final verifier migration.

- [ ] **Step 1: Run one isolated STDIO characterization**

Use a temporary output directory and database, with the same demo token as CI.

- [ ] **Step 2: Run one isolated temporal characterization**

Use a separate temporary output directory/database.

- [ ] **Step 3: Run the HTTP lab once**

Run `docker compose up --build -d --wait`, execute the HTTP demo into a temporary output/database, and always run `docker compose down -v`.

- [ ] **Step 4: Print exact semantic baselines**

For each report print:
- schema version;
- assessment;
- total finding count;
- status counts;
- severity counts;
- all non-pass finding IDs with status, severity, observation and category;
- temporal first-drift call.

Also verify each run directory contains:
- `report.json`
- `index.html`
- `junit.xml`
- `results.sarif`

- [ ] **Step 5: Stop at the characterization checkpoint**

Do not edit the CI verifier and do not commit production changes yet.

Present the exact characterization output for review.

The next implementation step is intentionally generated from this observed output rather than guessed in advance. It will:
1. update `scripts/verify_demo_report.py` to the observed post-R7 baseline;
2. update `tests/test_ci_report_verifier.py` only if required;
3. rerun verifier-focused tests plus affected unit tests;
4. create the single R7 implementation commit;
5. push;
6. inspect the resulting GitHub Actions run.

This checkpoint prevents a changed demo result from being automatically blessed as expected behavior.

---

## Self-Review

### Spec coverage

- Tri-state public model: Tasks 1 and 2.
- One internal claim model: Task 1.
- Required coverage and violations from same source: Task 1.
- Empty list deny-all: Task 1.
- Omitted/null no-claim: Task 1.
- Read-only and forbidden precedence: Task 1.
- R4 mutation gate: Task 1.
- Generator explicit null: Task 2.
- Demo migration: Task 3.
- Documentation/migration warning: Task 3.
- Static, type, focused and full verification: Task 4.
- One fresh post-fix characterization: Task 5.
- Verifier is not updated from guessed results: Task 5.
- No release/version/PyPI work: Global Constraints.

### Corner-case decisions locked by this plan

1. `[]` is never inferred from truthiness; it is an active deny-all policy.
2. `None` is never passed to `matches_any`; only normalized allowlist claims carry patterns.
3. `forbidden_side_effects` and `read_only` override weaker allowlists.
4. Read-only behavior is still independently assessed, but R4 does not broaden into blocking all authorization calls for read-only tools merely because process/message observers are absent.
5. Generated drafts do not silently make deny-all claims.
6. No observer is added just to keep historical CI output unchanged.
7. The old R5 semantic baseline is not reused after R7 if findings change.
8. A fresh characterization is reviewed before the CI verifier is changed.

### Placeholder scan

No `TBD`, `TODO`, `FIXME`, or unspecified implementation placeholders are present. The only intentionally deferred values are the post-R7 demo findings, which must be measured rather than guessed; the plan explicitly stops before accepting them.

