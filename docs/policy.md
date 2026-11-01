# Policy contract

blackice separates a policy decision from the mechanism that enforces it. Parsing a file, passing a unit test, or converting another format does not establish a working network boundary.

This document describes `blackice.policy/v0` and the experimental `blackice.sandbox-subset/v1` importer. The CLI validates native policy files and uses them for managed commands on supported backends. The importer is a library API; it is not yet wired into a CLI import command or a native launch path.

## Native policy format

```json
{
  "version": "blackice.policy/v0",
  "network": {
    "mode": "allowlist",
    "allow": ["api.example.com", "*.packages.example"],
    "ports": [80, 443],
    "subnets": {
      "allow": ["10.20.0.0/16"],
      "deny": ["10.20.10.0/24"]
    }
  }
}
```

The sample uses documentation names and addresses. Unknown fields, duplicate JSON fields, unknown modes and unsupported versions are errors. The native CLI reads at most 1 MiB. `network.ports` defaults to `[80,443]`; an explicit list must contain at least one port between 1 and 65535. Every connection must pass `checkPort` as well as its destination checks, including subnet allows and temporary grants. A successful port check alone grants no destination access.

| Mode | Destination behavior |
| --- | --- |
| `deny-all` | Deny destinations. A backend claiming a complete deny must also cover DNS, inherited connections and indirect network paths within its declared scope. |
| `allowlist` | Permit matching names or explicitly allowed address ranges, subject to denied ranges and the local address ceiling. |
| `allow-all` | Permit names and public address literals, still subject to denied ranges and the local/private-address ceiling. This is not unrestricted access to the host network. |

Exact names match only themselves. A leading `*.` matches descendants at any depth, but not the apex: `*.example.com` matches `a.example.com` and `a.b.example.com`, not `example.com`. Names are lowercased and one trailing dot is removed.

For a name-based connection, the connector must validate the name, resolve it through the declared DNS path, check the actual dial address, and connect to that same checked address. A later second lookup can invalidate the check. A caller must not use `checkResolved` by itself as authorization: it assumes the name was already admitted.

Denied address ranges take precedence. An explicit allowed range can authorize local/private addresses; otherwise the native evaluator rejects its listed loopback, private, link-local and other special address ranges. This is a local policy restriction, not a universal classification of every non-public network environment.

An allowed subnet is an independent permission. A proxy that rejects an unlisted hostname before considering an applicable subnet does not implement that independent-permission contract. Integration must define resolution, literal-address handling and DNS access consistently.

## Vercel Sandbox subset

The importer consumes the JSON value of `networkPolicy`, not a complete SDK create request or an API response. Its input shape is pinned to the [Sandbox type definition at commit 8c996641](https://github.com/vercel/sandbox/blob/8c996641a6ceac3a186ee45d9af0e1c8fcfd4d31/packages/vercel-sandbox/src/network-policy.ts). This is a source reference, not a vendored runtime dependency.

That pinned source format has no destination-port field. Subset v1 rejects supplied `ports` fields, including an empty list, as unknown rather than dropping them or treating them as native `network.ports`. The generated 80/443 ceiling is an explicit local restriction requiring acknowledgement; it is not a mapping from upstream input.

| Input | Subset v1 behavior |
| --- | --- |
| `"deny-all"` | Convert to native deny mode. Native and DNS qualification are still required. |
| `{}`, empty allows, or denied ranges without any allow | Convert to deny mode; absence of an allow never becomes allow-all. |
| `{"allow":["api.example.com","*.example.org"]}` | Convert supported hostname patterns. |
| `{"allow":{"api.example.com":[]}}` | Convert a domain map only when every rule array is empty. |
| `subnets.allow` / `subnets.deny` | Accept canonical IPv4 CIDRs, with zero host bits. |
| `"allow-all"`, catch-all `*`, middle wildcards such as `www.*.com`, partial/multiple wildcards | Reject as outside this subset. |
| Nonempty request-rule arrays | Reject the entire import, including `match`, `transform`, `forwardURL`, `response`, or an empty rule object. |
| IPv6 CIDRs, URLs, ports in names, IPs in domain lists, non-ASCII hostnames | Reject. They are not silently converted or omitted. |
| Numeric hostnames such as `2130706433`, `127.1` and `0x7f000001` | Reject; a resolver may interpret them as IP addresses. |

Input is bounded to 64 KiB, eight nested containers and 256 total domain/subnet entries before deduplication. Hostnames use ASCII hostname labels. CIDR prefixes accept canonical decimal digits only. The output sorts and deduplicates entries. Duplicate JSON keys remain errors.

Diagnostics use fixed paths and messages rather than echoing rejected input, which may contain a credential-bearing transform. A successful conversion carries the original input's SHA-256 and a versioned importer profile. Its native policy identifier hashes the generated native JSON; these are different identifiers.

## Conversion and activation are separate

```zig
var imported = try sandbox_import.convert(allocator, source_json, &diagnostic);
defer imported.deinit();

// A review artifact; do not treat this as an activated or qualified policy.
const candidate = imported.candidateJson();
_ = candidate;

// All flags default false. The caller supplies verified backend support,
// not flags supplied by the workload or copied from policy JSON.
const native = try imported.policyForBackend(qualified_capabilities, &diagnostic);
_ = native;
```

The returned JSON and policy pointer borrow the `Import` lifetime. Keep it alive while evaluating the policy. The core policy owns its parsed input, and the importer retains the canonical generated JSON for review/export.

Every candidate requires `native_scope` and `dns_policy`. Domain permissions also require `bound_tls_domains`; address rules require `ipv4_cidrs`. Any granted access requires `destination_ports` and `local_ceiling_acknowledged`. The latter explicitly acknowledges blackice's additional local address restrictions and destination-port ceiling of 80/443. Every candidate writes `ports: [80,443]` explicitly rather than inheriting a core default; this restriction is local, not part of the upstream input. A missing requirement returns `MissingCapability` before a policy pointer is returned. Passing this gate does not arm a backend: the launch transaction must still acknowledge attachment before executing workload code.

These flags are integration requirements, not an implemented capability detector. The current tests use synthetic flags to exercise both refusal and success paths. No native backend is marked qualified by this module.

## Protocol differences that block a parity claim

Vercel's [firewall documentation](https://vercel.com/docs/sandbox/concepts/firewall#http-and-https) matches domain rules against the TLS hostname. Plain HTTP cannot be allowed by a domain rule; it needs an allowed IP range. The blackice v0 proxy applies hostname rules to plain HTTP as well as CONNECT requests. That native behavior differs from Sandbox semantics.

For example, with only `api.example.com` allowed and no allowed subnet, the native proxy can admit `http://api.example.com`; Sandbox's domain rule does not permit that plaintext connection. A backend using that behavior must leave `bound_tls_domains` false, so `policyForBackend()` refuses a candidate containing domain permissions. A documentation warning or acknowledgement of the local address ceiling does not satisfy this gate. An adapter needs a qualified protocol-specific path before it can activate such imports.

Admitting a CONNECT authority alone also does not establish the negotiated TLS name. Domain and subnet permissions have different DNS effects, and subnet allows are independent of domain allows. The importing backend must qualify those semantics or refuse activation.

blackice additionally binds a declared name to a checked dial address. An allowed name alone must not authorize an arbitrary attacker-selected IP. Neither a client-supplied name nor SNI authenticates the server or prevents application data from reaching an allowed destination. The local address ceiling must remain explicit; import is not a silent relaxation or a claim of complete Vercel equivalence.

## Run the checks

From the repository root, with Zig 0.17.0:

```sh
zig build test
zig build
zig-out/bin/blackice policy check examples/agent.json
zig test src/core/sandbox_import.zig
```

Both `zig build test` and the standalone importer test command run 69 acceptance/rejection vectors plus capability, ownership, resource-limit and allocation-failure tests. These are deterministic software tests, not traffic evidence. They must not be entered as a passing native checkpoint in `evidence/`.

The root test module imports `sandbox_import.zig`, and the package manifest includes `tests/` so the vectors remain available in a packaged checkout. This test integration does not activate imported policies. Native support must be qualified separately on each OS.
