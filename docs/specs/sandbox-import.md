---
id: sandbox-import
title: Sandbox policy importer
owner: codex
stage: v0
paths: src/core/sandbox_import.zig, tests/vectors/
cases: P0-03
depends: policy
---

# Sandbox policy importer

## What and why

[Vercel Sandbox](https://vercel.com/docs/sandbox/concepts/firewall) already has a network policy format that
people who run agents in the cloud know. The importer reads a Sandbox `networkPolicy` and turns it into a
blackice policy, so the same intent can be applied to a task on a laptop. It accepts only the parts of that
format blackice has tested, and refuses everything else with a clear error. A policy that cannot be imported
exactly is never imported approximately, because an approximation could allow something the author did not.

## Requirements

| ID | Requirement | Checks |
|---|---|---|
| sandbox-import.R1 | When the input is `"deny-all"`, or a policy with no allowed domains and no allowed subnets (including `{}`, `{"allow": {}}`, `{"subnets": {}}` and a policy with only `subnets.deny`), the importer shall produce a `deny-all` blackice policy. | P0-03 |
| sandbox-import.R2 | When the input is `"allow-all"`, the importer shall refuse it (`UnsupportedMode`); this version never produces an `allow-all` blackice policy. | P0-03 |
| sandbox-import.R3 | When the input lists allowed domains, either as an array or as an object whose rule lists are all empty, the importer shall produce an `allowlist` policy with the same names, keeping an exact name exact and a leading `*.` as a wildcard for names below it. | P0-03 |
| sandbox-import.R4 | When the input has IPv4 ranges in `subnets.allow` or `subnets.deny`, the importer shall copy them to the blackice policy unchanged. If it has an IPv6 range, the importer shall refuse the policy; this version does not import them. | P0-03 |
| sandbox-import.R5 | If a domain rule carries a `transform`, `forwardURL` or `match`, the importer shall refuse the whole policy and name the domain and the field. | P0-03 |
| sandbox-import.R6 | If a domain pattern uses a wildcard anywhere except a leading `*.`, or is the catch-all `*`, the importer shall refuse the policy and name the pattern. | P0-03 |
| sandbox-import.R7 | If the input has any field the importer does not know, the importer shall refuse the policy instead of ignoring the field. | P0-03 |
| sandbox-import.R8 | The importer shall carry a version. When a scope starts from an imported policy, its first receipt shall name the importer version and the digest of the input file. | P0-09 |
| sandbox-import.R10 | blackice shall not run a scope from an imported policy unless it has declared, from its own tested backend support and never from the workload or a command-line flag, that it handles what the policy needs: TLS name binding for domain rules, DNS behaviour, IPv4 ranges, and the extra refusal of local addresses. Each of these starts as unsupported. | P0-03 |
| sandbox-import.R9 | For each case in the test vectors, the importer shall produce exactly the expected blackice policy or the expected refusal, and the policy evaluator shall give the expected verdict for each destination listed in that case. | P0-03 |

## Design

The importer is a translator with a short list of things it understands. It runs before a scope starts, as
part of loading a policy. Anything it does not understand is an error, never a silent default. The shared test
vectors are the definition of the supported subset: if a case is not in the vectors, it is not supported.

The importer translates the access part of a Sandbox policy (which destinations may be reached). It does not
translate the request-handling part (credential injection, forwarding to another proxy, request matchers).
Local rules that do not exist in Sandbox, such as who may grant more access, stay in blackice's own
configuration and are not read from the imported file.

**Technical.**

- Input: a JSON file holding a `networkPolicy` value: the string `"deny-all"` (`"allow-all"` is refused, R2),
  or an object with `allow` (an array of domain patterns, or an object mapping each pattern to a rule list) and
  `subnets` (`allow` and `deny` CIDR lists). The exact accepted wrapper is fixed by the test vectors.
- Output: a `blackice.policy/v0` policy (see [policy](policy.md)) as a candidate to review. Profile
  `blackice.sandbox-subset/v1`, written against one pinned commit of the Sandbox source. Using the candidate
  for a scope goes through a capability gate (R10); the capabilities default to unsupported.
- Bounds: input at most 64 KiB, 256 entries, nesting depth 8. Error messages are fixed strings and never echo
  the input, which may hold credentials.
- Code: `src/core/sandbox_import.zig`; vectors in `tests/vectors/`, each with an input, the expected output
  or refusal, and destination checks.
- Known differences to settle with vectors before any claim of equivalence:
  - Sandbox matches domains on the TLS server name. blackice's proxy matches the host name in the CONNECT or
    HTTP request. Both are claims made by the client.
  - Sandbox does not filter plain HTTP by domain: it must be allowed by address range. blackice's proxy
    decides plain HTTP by host name. An imported policy may therefore allow plain HTTP to a domain where
    Sandbox would not.
  - Sandbox allows wildcards in any label (`www.*.com`) and a catch-all `*`. blackice v0 supports only a
    leading `*.`; the others are refused (R6).
  - With only `subnets.allow`, Sandbox leaves DNS unrestricted. blackice resolves only allowed names.
  - blackice refuses private and local addresses for an allowed name unless an allowed subnet covers them.
    Sandbox's behaviour for that case is not documented.
  - Sandbox policies can change while a sandbox runs. The importer reads one policy at scope start.
- Limits: no handling rules, no Postgres-specific handling, no round trip back to Sandbox format, and no claim
  that a policy behaves the same in Sandbox and in blackice.

## Tasks

| Task | Owner | State | Blocked by |
|---|---|---|---|
| Write the test vectors for the supported subset and the refusals | codex | done | |
| Importer in src/core/sandbox_import.zig against the vectors | codex | done | |
| Decide each known difference above in a vector, or refuse the input | codex | done | |
| Hook the importer into policy loading (`blackice run`, `blackice policy check`) | lead | todo | |
| Set the backend capabilities from tested support, per platform | lead | todo | waits for: the platform backends |

## Evidence

| Covers | Kind | Link | Note |
|---|---|---|---|
| sandbox-import.R1, sandbox-import.R2, sandbox-import.R3, sandbox-import.R4, sandbox-import.R5, sandbox-import.R6, sandbox-import.R7, sandbox-import.R9, sandbox-import.R10 | test | `zig test src/core/sandbox_import.zig`, 63 vectors in tests/vectors/sandbox-import-v1.json plus the capability gate, input bounds and allocation-failure tests | 12/12 passed at fe37bb3 (PR #5), Zig 0.17.0, Linux x86_64. Conversion only: no comparison with Sandbox itself and no enforcement |

## Terms

policy, allowlist, subnet, CIDR, SNI, CONNECT proxy, DNS, credentials brokering, test vectors, policy digest
