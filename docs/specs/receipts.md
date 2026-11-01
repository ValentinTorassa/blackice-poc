---
id: receipts
title: Receipts
owner: lead
stage: v0
paths: src/core/receipt.zig
cases: P0-02, P0-03, P0-09
depends: policy
---

# Receipts

## What and why

A receipt is one line of JSON that blackice writes every time it allows or refuses a connection, and when a
scope starts or ends. It says which scope, which policy, where the decision was enforced, what was decided and
why. Receipts are how a person, a script or an agent such as fx can see what blackice did, without trusting
anyone's description of it. They record facts about connections, never their contents, so reading or sharing
them does not leak what a program sent.

## Requirements

| ID | Requirement | Checks |
|---|---|---|
| receipts.R1 | blackice shall write each receipt as one JSON object on its own line, appended to the scope's `receipts.jsonl`, and never rewrite an earlier line. | P0-09 |
| receipts.R2 | Every receipt shall carry `ts` (UTC, RFC 3339 with milliseconds), `scope`, `policy` (the policy identifier), `gen` (the policy generation), `point` and `event`. Fields that do not apply shall be omitted, never written as null. | P0-09 |
| receipts.R3 | When the proxy, the kernel rules or the relay allows or refuses a connection, blackice shall write exactly one receipt for that decision, with `verdict`, `reason`, the policy `rule` when one decided, and the destination it saw (`host`, `ip`, `port`). | P0-02, P0-03 |
| receipts.R4 | Every receipt shall name its enforcement point as one of `proxy`, `kernel`, `relay`, `control` or `app_filter` (the macOS Network Extension, for app scopes). | P0-02 |
| receipts.R5 | blackice shall have a single writer per scope, the `blackice` process; backends shall pass their events to it, so lines never interleave. | P0-09 |
| receipts.R6 | If a receipt cannot be written, blackice shall leave the verdict unchanged, count the failure, and report the count in the scope's `scope_end` receipt. | P0-09 |
| receipts.R7 | Receipts shall hold metadata only: no request or response bodies, no TLS content, no headers or credentials, no URL paths or query strings, no environment variables and no full command arguments. | P0-09 |
| receipts.R8 | blackice shall keep reason codes stable; renaming or removing one is a recorded contract change. | P0-09 |
| receipts.R9 | A decision receipt shall always be written: blackice shall replace control and invisible characters in each field and cut a field that is too long, ending it in `...`, instead of dropping the line. | P0-02 |

## Design

Every enforcement point reports to the same log, owned by the `blackice` process that runs the scope. A
decision is made first and recorded second: a slow or failing write never delays or changes a decision, it only
increments a counter that shows up at the end of the scope. The log is plain JSON Lines, so `tail -f`, `grep`
and `jq` are enough to read it.

**Technical.**

- Location: `<state directory>/receipts.jsonl` (see [scope-core](scope-core.md)).
- Example:

  ```json
  {"ts":"2026-10-30T04:12:33.123Z","scope":"s-1a2b3c4d","policy":"cae35a3beb20","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"no_matching_rule","host":"attacker.test","port":443}
  ```

- Fields: `ts`, `scope`, `policy`, `gen`, `point`, `event`, and when they apply `verdict` (`allow` or
  `deny`), `reason`, `rule`, `host`, `ip`, `port`, `detail`.
- `event`: `connect`, `http`, `scope_start`, `backend_armed`, `backend_cleanup` (Linux), `scope_end`, `grant`,
  `revoke`, `control` (a control request refused before its operation is known), `relay_call`, `kernel_drop`,
  `warning`. On macOS, `kernel_drop` comes from the kernel log, which records refusals of Apple-signed binaries and not of ad-hoc-signed ones
  ([macos-task-scope](macos-task-scope.md) R12); on Linux every refusal by the cgroup programs is reported, or
  counted as lost, whatever the binary. Refusals by the Linux seccomp filter (such as a raw socket for `ping`) have
  no receipt.
- `reason`: a policy reason code (see [policy](policy.md)) or a short error name for `warning` events.
- `policy`: the first 12 hex digits of the SHA-256 of the policy file. `gen` is the policy generation: 1 for the
  policy the scope started with. v0 has no live policy reload, so it stays 1; grants have their own receipts
  ([grant](grant.md)).
- Writer: `receipt.Log` serialises each line into a fixed 4 KiB buffer and appends it under a lock. Control
  characters, zero-width and bidirectional marks become `?`, and each field is cut at a character boundary to a
  fixed size, ending in `...`, so a decision line always fits (R9). Lines that still cannot be written are
  counted and reported as `dropped` in `scope_end`. The first version dropped a line that did not fit, which
  would have let a workload hide its own refusals behind long names.
- File: `receipts.jsonl` is created exclusively with mode 0600, in a scope directory with mode 0700.
- Linux kernel drops reach the log through the `blackice` process, never by a second writer
  ([linux-task-scope](linux-task-scope.md)).
- Limits:
  - Receipts are not tamper-proof against the user's other processes outside the scope. The scoped command
    itself is meant not to write them: on macOS a sandbox rule denies writes under the state root, renames of
    its parents and hard links to its files (probed on the Mac: direct write, parent rename and hard link
    refused); on Linux the state directory is a read-only
    mount (not yet run with the installed helper).
  - v0 has no per-line sequence number, so a gap inside the file is visible only through `dropped`.
  - No size or time limit on the file yet.
  - A receipt explains a decision; it does not say whether traffic sent to an allowed destination was
    harmful.

## Tasks

| Task | Owner | State | Blocked by |
|---|---|---|---|
| Receipt line format and single writer | lead | done | |
| Count failed writes | lead | done | |
| Report the failed-write count in `scope_end` (`dropped`) | lead | done | |
| Proxy decisions write receipts | network | done | |
| Relay calls and grants write receipts | network | doing | |
| Clean and cut long fields instead of dropping the line | lead | done | |
| Linux kernel refusals (ring buffer) passed to the `blackice` process as receipts | codex-linux | done | |
| After a helper kill, the receipts say `command_not_started` and `scope_end` 127 for a command that had been running; report a helper failure during the run as such (P0-06 finding P6-4) | lead | todo | |
| Kernel receipts carry the kernel's refusal time in `detail`: `ts` is when the line was written, so refusals made while `blackice run` was stopped carry the resume time (P0-06) | codex-linux | todo | |

## Evidence

| Covers | Kind | Link | Note |
|---|---|---|---|
| receipts.R2, receipts.R4 | entry | [P0-02 Linux](../../evidence/P0-02-real-deny-linux.md) | Debian 13, kernel 6.12.113, x86_64, launcher 020f389, helper 7c3bcff (`515ebfac…`), Zig 0.17.0, one run. Every refusal has a `kernel_drop` receipt with point `kernel` and reason `loopback_proxy_only` |
| receipts.R2, receipts.R4 | entry | [P0-02 macOS](../../evidence/P0-02-real-deny-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #11. Receipts from three points (`control`, `kernel`, `proxy`), each with `ts`, `scope`, `policy`, `gen`, `point` and `event`. macOS logs refusals only for Apple-signed programs; here python3 and curl |
| receipts.R1, receipts.R2, receipts.R4 | entry | [P0-04 macOS](../../evidence/P0-04-owner-grant-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #10. Eight lines in one file, flat fields, points `control`, `kernel` and `proxy` |
| receipts.R1, receipts.R2 | test | `zig build test`, src/core/receipt.zig: "receipt lines are JSON with nulls omitted" | One line per receipt, escaping, nulls omitted. 21/21 passed at 99e2f4e (PR #1), Zig 0.17.0, Linux x86_64 |
| receipts.R2 | test | `zig build test`, src/core/receipt.zig: "formatTimestamp" | Timestamp format. Same run |
| receipts.R9 | test | `zig build test`, src/core/receipt.zig: "long and malformed fields cannot drop a receipt", "clean" | Same run |

## Terms

receipt, scope, policy, policy digest, policy generation, reason code, enforcement point, JSON Lines, CONNECT proxy
proxy, relay, NFLOG, grant
