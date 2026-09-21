# R10-A Restricted STDIO Launch Policy

Status: R10-A1 implemented / GREEN; pre-commit validated
Base: `0d3b88505c62a87487cead91fc5e1b3bc5bfabc8`

## Purpose

R10-A reduces the ambient authority inherited by an MCP server that Guard launches
through STDIO.

This phase is intentionally called **restricted launch**, not **sandboxing**.
It hardens how the target process is selected and started, but it does not claim
OS-level containment.

R9 ownership/correlation remains evidence attribution. R10-A is a separate target
execution-boundary control.

## Current boundary being addressed

At the R10-A base:

- STDIO launch starts from `dict(os.environ)` and then overlays
  `server.environment`, `identity.environment`, and Guard identity variables.
  A target therefore receives unrelated parent-process environment values unless
  the operating environment removes them first.
- `validate_target()` compares `server.command` against
  `safety.allowed_stdio_commands` by basename. Basename equality is not executable
  identity.
- A configured STDIO `cwd` is checked for existence only. There is no approved-root
  containment check and no canonical/symlink escape check.
- `--lab-mode` controls whether declared state-changing tests may run. It is not an
  execution-isolation control.
- `Dockerfile.runner` drops the Guard CLI to UID 10001, but it does not isolate a
  target launched by Guard from the runner's filesystem/network/process namespace.

## Trust model

Trusted for R10-A:

- the Guard operator;
- the reviewed contract;
- explicitly supplied `server.environment` and `identity.environment` values;
- explicitly configured restricted-launch executable paths, cwd roots and inherited
  environment names.

Potentially hostile:

- the MCP target implementation;
- tool output and notifications;
- target-created child processes;
- target-controlled filesystem content, including symlinks, under locations it can
  modify.

R10-A assumes the Guard host itself and the Python process running Guard have not
already been compromised.

## Contract shape

Restricted launch is attached to `ServerSpec`, not `SafetySpec`, because every
existing `McpClient` construction path already receives `ServerSpec`.

Proposed additive contract-v1 shape:

```yaml
server:
  transport: stdio
  command: python
  cwd: /reviewed/workspace
  stdio_launch:
    mode: restricted
    allowed_executables:
      - /absolute/path/to/python
    allowed_cwd_roots:
      - /reviewed
    inherit_environment:
      - PATH
```

Conceptual model:

```python
class StdioLaunchSpec(ContractModel):
    mode: Literal["legacy", "restricted"] = "legacy"
    allowed_executables: list[Path] = []
    allowed_cwd_roots: list[Path] = []
    inherit_environment: list[str] = []
```

`ServerSpec.stdio_launch` defaults to legacy behavior. Contract version remains 1.

The existing `safety.allowed_stdio_commands` field remains the legacy-mode launch
allowlist in R10-A. It is not silently redefined to mean canonical executable paths.

## Restricted-mode guarantees

### Executable identity

Restricted mode must:

1. resolve the configured command to the executable that would actually be launched;
2. canonicalize the resolved executable path;
3. compare it against canonical **absolute** `allowed_executables` entries;
4. reject basename-only restricted allowlist entries;
5. reject a different executable that happens to share an allowed basename;
6. select the absolute launch path once (direct absolute command or one PATH
   lookup), compare its canonical target against the canonical approved executable,
   and pass that same selected absolute path to the MCP SDK without a second PATH
   lookup. This preserves launcher semantics such as Python virtual environments.

This is executable selection, not descendant-process containment. A permitted target
can still spawn another process unless a later containment backend prevents it.

### Working directory

Restricted mode requires an explicit `server.cwd` and at least one
`allowed_cwd_roots` entry.

Both the cwd and approved roots are resolved canonically. The cwd must be equal to
or contained by an approved root after symlink resolution. A lexical path inside a
root that resolves outside it must be rejected.

This does not make the rest of the filesystem inaccessible to the target. That is
R10-B containment work.

### Environment

Restricted mode starts from an empty inherited-parent environment.

It may then add, in order:

1. parent environment variables whose **names** are explicitly listed in
   `inherit_environment`;
2. explicit `server.environment`;
3. explicit `identity.environment`;
4. Guard's `MCP_GUARD_IDENTITY`, and when present `MCP_GUARD_TENANT` and
   `MCP_GUARD_ROLE`.

Unlisted parent values such as unrelated credentials must not be inherited.

Explicit contract/identity environment values are trusted operator configuration and
are therefore not filtered by `inherit_environment`.

No implicit `HOME`, `PATH`, proxy, cloud-credential or shell variable is promised.
If a target needs one, the contract must explicitly inherit or supply it.

### Lab mode independence

`--lab-mode` must neither enable nor bypass restricted-launch checks. It remains only
a permission gate for declared state-changing/replay tests.

## Legacy compatibility

With `stdio_launch.mode: legacy` (including when `stdio_launch` is omitted):

- existing STDIO contracts continue to use the current
  `safety.allowed_stdio_commands` semantics;
- current environment inheritance remains unchanged;
- current cwd behavior remains unchanged.

R10-A must not silently tighten existing contracts.

## Fail-closed requirements

Restricted mode must reject launch before target execution when:

- an approved executable entry is not absolute;
- the configured command cannot be resolved;
- the resolved executable is not exactly approved;
- `server.cwd` is absent;
- no cwd root is configured;
- the canonical cwd is outside every approved root;
- a symlink causes the canonical cwd to escape its approved root.

Error output must not disclose secret environment values.

## Explicit non-goals for R10-A1

R10-A1 does **not** provide or claim:

- filesystem sandboxing;
- network namespaces/firewall enforcement;
- seccomp, AppArmor, SELinux or macOS sandbox profiles;
- PID/user namespace containment;
- cgroup/resource limits;
- prevention of descendant process execution;
- authenticated target binaries or package signatures;
- protection from a compromised Guard host;
- HTTP redirect confinement;
- fleet/controller/SIEM/IAM/orchestration capabilities.

HTTP redirect/destination confinement is R10-A2.

Optional OS/container containment is R10-B and must be evaluated separately after
R10-A1 is complete.

## R10-A1 acceptance criteria

The RED/GREEN contract must demonstrate all of the following:

| Area | Required behavior |
| --- | --- |
| Contract | additive contract-v1 `server.stdio_launch`; legacy is default |
| Legacy | existing basename allowlist behavior remains valid |
| Executable | basename-only restricted allowlist is rejected |
| Executable | same-basename different executable is rejected |
| Executable | approved basename command resolves once to its approved canonical path |
| CWD | restricted launch requires explicit cwd and approved roots |
| CWD | direct outside-root cwd is rejected |
| CWD | symlink escape is rejected |
| Environment | unrelated parent secret is absent |
| Environment | explicitly inherited parent variable is present |
| Environment | explicit server/identity variables remain present |
| Environment | Guard identity/tenant/role variables remain present |
| Lab mode | lab mode cannot bypass executable/cwd restrictions |

## Expected implementation boundary after RED

R10-A1 should remain small. Expected production touch points are:

- `src/mcp_behaviour_guard/models.py`
- `src/mcp_behaviour_guard/config.py`
- `src/mcp_behaviour_guard/client.py`
- contract reference/changelog
- focused tests

A small shared resolution helper may be introduced only if needed to ensure
`validate_target()` and `McpClient` use the same canonical executable decision.

Do not change reporting schemas, R9 observer/correlation behavior, contract version,
package version, PyPI/release configuration, or the HTTP transport in R10-A1.

## R10-A0 hardening clarifications

The following clarifications are authoritative for R10-A1 and narrow ambiguous edges
in the initial design without expanding into R10-B containment:

- `server.stdio_launch` is valid only for `transport: stdio`.
- Restricted-only settings must not be silently accepted with `mode: legacy`.
- Restricted executable approval is independent of the legacy
  `safety.allowed_stdio_commands` basename list.
- Approved cwd roots must be absolute. Restricted `server.cwd` must resolve to an
  existing directory contained by an approved canonical root.
- Restricted policy is enforced again at the actual `McpClient` launch boundary;
  `validate_target()` is preflight, not the security boundary.
- Restricted-mode Guard identity variables are authoritative: Guard writes
  `MCP_GUARD_IDENTITY`, `MCP_GUARD_TENANT`, and `MCP_GUARD_ROLE` last, so inherited
  or explicit target environment entries cannot spoof them.
- Canonical executable-path approval does not authenticate file contents and does
  not prevent the approved executable from later spawning descendants. Those are
  outside R10-A1.

Additional R10-A1 acceptance checks:

| Area | Required behavior |
| --- | --- |
| Transport | `stdio_launch` is rejected for non-STDIO targets |
| Mode | restricted-only settings are rejected when mode is legacy |
| Executable | restricted approval works independently of legacy basename approval |
| Launch boundary | direct `McpClient` launch enforces restricted policy without preflight |
| CWD | approved roots are absolute and cwd resolves to a directory |
| Environment | Guard identity/tenant/role variables are authoritative |

## R10-A1 pre-GREEN compatibility clarifications

These constraints close serialization and path-identity gaps without expanding
R10-A1 into OS-level containment:

- When `server.stdio_launch` is omitted, legacy serialized contract/server output
  must not gain a synthetic default launch-policy object. Existing contract hashes
  and generated draft shape should not change merely because R10-A1 exists.
- Restricted `server.cwd` must itself be absolute. Canonical containment is still
  checked after resolving it.
- `allowed_executables` entries must be absolute and already canonical; a symlink
  or other path that resolves to a different path is not an executable identity.
  The configured command may be a basename or symlink, but its resolved target
  must equal one of those canonical approved executable paths.
- `allowed_cwd_roots` entries must likewise be absolute and already canonical so
  a mutable root symlink cannot redefine the approved boundary later.

These checks still do not authenticate executable file contents or prevent a
permitted executable from spawning descendants.

R10-A1 also does not provide race-free executable identity. Guard validates the
canonical target at the actual launch boundary and then passes the already-selected
absolute launcher path to the MCP SDK. A path or symlink changed in the interval
between validation and OS process creation is a residual TOCTOU risk. Eliminating
that portably requires a stronger execution/containment backend and is outside
R10-A1.
