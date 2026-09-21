# R10-A2 HTTP Destination and Redirect Confinement

Status: R10-A2 implemented / GREEN locally; integration pending PR CI

Base: `670a2ba6e246e0814d23ba5662d3af8447a348c9`

## Purpose

R10-A2 constrains the URL destinations used by a `streamable-http` MCP client.

The current legacy HTTP path validates the configured initial hostname before execution but the
runtime client follows redirects. That means preflight hostname validation alone is not a
complete runtime destination boundary.

R10-A2 is intentionally URL/destination policy hardening. It is **not** network sandboxing.

## Existing legacy behavior

When no R10-A2 policy is configured:

- `validate_target()` checks the configured HTTP hostname against the existing
  `safety.target_allowlist` plus `server.allowed_hosts`;
- `McpClient` keeps the existing `follow_redirects=True` behavior;
- HTTPX keeps its existing environment behavior;
- existing contract serialization remains unchanged.

R10-A2 must not silently strengthen or alter omitted-policy legacy contracts.

## Proposed additive contract shape

```yaml
server:
  name: reviewed-http-server
  transport: streamable-http
  url: https://mcp.example.test/mcp
  http_destination:
    allowed_origins:
      - https://mcp.example.test
    allow_redirects: false
```

Proposed model:

```text
HttpDestinationSpec
  allowed_origins: list[str]
  allow_redirects: bool = false

ServerSpec.http_destination:
  HttpDestinationSpec | None
```

Presence of `http_destination` enables restricted HTTP destination policy. Omission preserves
legacy behavior.

Contract version remains `1`.

## Restricted origin identity

An approved origin is the tuple:

```text
scheme + normalized hostname + effective port
```

Rules:

1. only `http` and `https` origins are accepted;
2. an approved origin must contain a hostname;
3. URL userinfo is rejected;
4. an approved origin is origin-only, with no non-root path, query, or fragment;
5. hostname comparison is case-insensitive;
6. a DNS trailing dot is normalized away;
7. IPv4 and IPv6 literals are normalized to canonical textual address form;
8. default ports normalize to `80` for HTTP and `443` for HTTPS;
9. an explicit non-default port remains part of destination identity;
10. the configured `server.url` may contain its MCP path/query, but its origin must be approved.

This is stronger than hostname-only comparison because scheme and effective port are part of the
approved destination identity.

## Redirect policy

`allow_redirects: false` is the restricted default.

When false:

- HTTP redirects are not followed automatically.

When true:

- redirects may be followed;
- **every actual request**, including every redirect hop, must pass the same approved-origin
  check before the request is sent;
- a relative redirect that stays on an approved origin is allowed;
- a redirect to a different scheme, host, or port is denied unless that resulting origin was
  explicitly listed in `allowed_origins`.

Listing multiple origins therefore explicitly authorizes requests to each listed origin. Operators
must account for the identity headers that are used with the MCP connection when approving
cross-origin redirect destinations.

## Actual runtime enforcement boundary

Preflight validation is useful but insufficient.

The runtime `McpClient` HTTP path must enforce destination policy at the request boundary so a
caller cannot bypass R10-A2 simply by skipping `validate_target()`.

No request to a disallowed redirect destination may be sent first and rejected afterward.

## Ambient proxy behavior

Restricted HTTP destination mode must not inherit ambient HTTPX proxy configuration from the Guard
process. The restricted client therefore uses `trust_env=False`.

This removes ambient proxy routing from the restricted-mode guarantee. Legacy omitted-policy HTTP
behavior remains unchanged.

R10-A2 does not add a generic explicit proxy configuration feature.

## Interaction with legacy host allowlists

Restricted `server.http_destination.allowed_origins` is the authoritative R10-A2 destination
policy.

The legacy hostname controls:

```text
server.allowed_hosts
safety.target_allowlist
```

remain authoritative only for the legacy omitted-policy path.

Restricted mode must not require a second unrelated approval from those legacy hostname lists.

## Failure semantics

A malformed restricted destination policy, an unapproved initial origin, or an attempted request
to an unapproved redirect origin fails closed before the disallowed request is sent.

The error must identify the policy failure without exposing identity headers or other credentials.

## Trust assumptions

Trusted:

- Guard operator;
- reviewed contract;
- reviewed destination policy;
- Guard process and HTTP client implementation.

Potentially hostile/untrusted:

- MCP server responses;
- redirect responses and `Location` values;
- remote content.

## Explicit non-goals and residual limits

R10-A2 does **not** claim:

- IP-level egress filtering;
- DNS pinning;
- DNS-rebinding prevention;
- protection from a compromised resolver;
- protection from a compromised allowed endpoint;
- TLS certificate pinning;
- generic SSRF prevention for arbitrary non-MCP code;
- firewall/network-namespace containment;
- proxy support beyond disabling ambient proxy inheritance in restricted mode;
- R10-B filesystem/process/container containment.

Hostname approval remains URL identity, not proof that the hostname resolves to a permanently
trusted IP address.

Those distinctions must remain explicit in user-facing documentation.

## RED acceptance matrix

Permanent tests should cover at least:

1. additive contract-v1 policy;
2. omitted-policy serialization compatibility;
3. rejection of HTTP destination policy on STDIO;
4. required non-empty restricted origin list;
5. HTTP/HTTPS-only approved origins;
6. origin-only allowlist entries;
7. userinfo rejection;
8. configured initial URL must be approved;
9. hostname case/default-port normalization;
10. non-default port remains identity;
11. scheme change remains identity;
12. restricted mode independent of legacy hostname allowlists;
13. redirects disabled by default;
14. restricted mode uses `trust_env=False`;
15. every runtime request is checked at the actual client boundary;
16. same-origin relative redirect request is accepted;
17. unapproved cross-origin redirect request is rejected before send;
18. explicitly approved second origin may be used when redirects are enabled;
19. legacy client behavior remains unchanged when policy is omitted.

## GREEN exit gate

R10-A2 is GREEN only when:

- focused R10-A2 tests pass;
- affected existing HTTP/client tests pass;
- Ruff format/lint pass;
- CI-equivalent mypy passes;
- full non-integration pytest passes once after the final code change;
- relevant integration demo(s) pass;
- legacy serialization/runtime behavior remains unchanged when policy is omitted;
- no R10-B, assurance-pack, controller, MCP migration, version bump, release, or PyPI work is
  mixed into the source change.
