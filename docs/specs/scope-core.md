---
id: scope-core
title: Task scope core
owner: lead
stage: v0
paths: src/main.zig, src/core/scope.zig, src/core/backend.zig
cases: P0-01, P0-02, P0-09, P0-10
depends: policy, receipts, proxy
---

# Task scope core

## What and why

`blackice run` puts one command, and every process it starts, inside a task scope. It reads the policy
first, starts the scope's proxy, and only then hands the command to the operating system's confinement for
this platform. The command never runs for a moment without that confinement: if this platform has no working
confinement yet, blackice refuses to run it and says so. When the command ends, the scope ends with it and
blackice exits with the command's own status, so it can sit in front of any command in a script.

## Requirements

| ID | Requirement | Checks |
|---|---|---|
| scope-core.R1 | When `blackice run --policy FILE -- CMD...` is invoked, blackice shall load and check the policy before it creates the scope; if the policy is refused, it shall exit non-zero without starting CMD. | P0-01 |
| scope-core.R2 | blackice shall start CMD only after the platform backend has confined it, so that a connection CMD attempts at its very first instruction is already subject to the scope. | P0-01 |
| scope-core.R3 | If this platform has no enforcing backend, blackice shall refuse to run CMD, print the reason, write a `warning` receipt with reason `backend_unavailable`, and exit non-zero. It shall never run a command unconfined. | P0-10 |
| scope-core.R4 | When a scope is created, blackice shall give it a new identifier (`s-` followed by 8 hex digits) and a state directory holding the exact policy bytes and the scope's `receipts.jsonl`. | P0-09 |
| scope-core.R5 | blackice shall confine CMD and every process it starts so that they can open network connections only to the loopback ports of the scope's own proxy and, when present, its relay. | P0-02 |
| scope-core.R6 | When CMD starts, blackice shall set `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, in upper and lower case, to the scope's proxy address, and set `NO_PROXY` and `no_proxy` to loopback only. | P0-03 |
| scope-core.R7 | When the scope starts and ends, blackice shall write a `scope_start` and a `scope_end` receipt; `scope_end` carries CMD's exit status and the number of receipts that could not be written. | P0-09 |
| scope-core.R8 | When CMD ends, blackice shall stop the scope's control socket, relay and proxy, write `scope_end` as the scope's last receipt, and exit with CMD's exit code, or 128 plus the signal number if CMD was killed by a signal. It shall exit 125 when it cannot set up the scope and 127 when CMD cannot be started. | P0-01 |
| scope-core.R9 | When `--name N` is given, blackice shall record N in the `scope_start` receipt as a label only; a name never selects or widens a policy. | P0-09 |
| scope-core.R10 | blackice shall make the scope's state directory read-only, or hidden, for the command and every process it starts, and shall load the policy into memory once, never re-reading it from that directory. | P0-04 |
| scope-core.R11 | When CMD starts, blackice shall give it a clean environment: only a short pass list (`PATH`, `HOME`, `TERM`, the locale and XDG base-directory variables, `AI_AGENT`), the names given with `--env NAME`, `BLACKICE_SCOPE` and the proxy variables. Nothing else from the caller's environment shall pass. | P0-07 |
| scope-core.R12 | blackice shall keep these unchanged inside the scope: its own executable as resolved, the path used to reach it (`argv[0]` or the `PATH` entry, only when it resolves to the same file), the policy file, and each `--protect PATH` (at most 8). For each given path, it shall protect the resolved file and every symlink component on the way as the entry the kernel sees: writes, and renames or removals of their parent directories, shall be refused. If the platform backend cannot do this, `blackice run` shall refuse to start. | P0-01 |
| scope-core.R13 | When `--policy-sha256 HEX` is given, blackice shall refuse to start unless the policy file's SHA-256 is HEX. | P0-01 |

## Design

`blackice run` is one process that owns the whole scope: it reads the policy, creates the scope directory,
opens the receipt log, starts the proxy (and the relay when asked), and asks the platform backend to launch the
command already confined. Everything that decides or records stays outside the command. The backend's only
job is to make sure the command and its children cannot reach the network except through the scope's own
loopback ports; names and addresses are then decided by the proxy.

**Technical.**

- CLI: `blackice run --policy FILE [--name N] -- CMD...`. Today the binary implements `version` and
  `policy check FILE`; `run` is being built.
- Scope identifier: `s-` + 8 random hex digits (`src/core/scope.zig`).
- State directory: `$XDG_STATE_HOME/blackice/scopes/<id>/` when `XDG_STATE_HOME` is an absolute path,
  otherwise `~/.local/state/blackice/scopes/<id>/`. It holds `policy.json` (the exact bytes the scope started
  with) and `receipts.jsonl`.
- Backend contract (`src/core/backend.zig`): the core passes a `LaunchSpec` with the scope id, argv, the
  environment (already carrying the proxy variables), `allowed_loopback_ports`, the state directory
  (`state_dir`, which the backend makes read-only or hidden inside the scope) and the receipt log. The backend
  must confine the command before it runs and returns its exit (`exited`, `signal` or `other`).
  `BackendUnavailable` means the command was not run. Changing this contract is a recorded change between
  owners.
- Backends: macOS uses a Seatbelt profile through `sandbox-exec` ([macos-task-scope](macos-task-scope.md));
  Linux uses a root-owned cgroup with eBPF socket programs and a small helper ([linux-task-scope](linux-task-scope.md)).
  Until that backend is merged, `run` on Linux refuses; with it, `run` refuses a helper older than the protocol it
  expects (`linux_helper_upgrade_required`).
- Lifecycle in v0: requested, checked, confined, running, ended. Not in v0: policy updates other than grants,
  a degraded state with recovery, draining, and nested scopes.
- Limits:
  - Clients that ignore the proxy variables cannot connect at all: they fail closed, they are not let
    through.
  - Work handed to a service outside the scope (a container daemon, launchd, `systemd-run --user`) runs
    outside the scope. Each platform spec lists what it blocks and what it does not.
  - The state directory is in the user's home and only the blackice process writes it; inside the scope it is
    read-only or hidden. Other processes of the same user outside every scope can still change it, so
    receipts are a record for diagnosis, not tamper-proof evidence.
  - What happens to processes still running after CMD exits is not defined yet (see Tasks).
  - Path protection follows the symlinks in the path given, not symlinks inside a link's target.

## Tasks

| Task | Owner | State | Blocked by |
|---|---|---|---|
| Scope identifier and state directory | lead | done | |
| Backend contract between the core and the platform backends | lead | done | |
| Linux placeholder that refuses to run and writes a `backend_unavailable` receipt | lead | done | |
| `blackice run`: arguments, policy load, scope creation, launch, exit status (PR #7) | lead | done | |
| Write the policy bytes into the state directory | lead | done | |
| State directory read-only inside the scope on macOS, parents protected against rename | lead | done | |
| State directory read-only or hidden inside the scope on Linux (PR #6) | codex-linux | done | |
| Proxy variables and the clean environment | lead | done | |
| `scope_start` and `scope_end` receipts, with the failed-write count | lead | done | |
| Decide and document what happens to processes left running after CMD exits | lead | todo | |
| Protected paths (`protected_paths` in the launch contract, `--protect`, symlink components) and `--policy-sha256`; macOS honors them (PR #7, b958046) | lead | done | |
| Linux backend honors protected paths (`protects_paths = true`), helper protocol v2 (PR #6; reviewed and pinned) | codex-linux | done | |
| Create each scope's state directory exclusively (0700), with a new id on a clash | lead | done | |
| `run` handles INT, TERM and HUP: cancel through the backend, wait for its cleanup, write `scope_end` as cancelled. Today SIGTERM and Ctrl-C leave no `scope_end` (P0-06 finding P6-2) | lead | todo | |
| A helper or launch failure exits 125 (cannot set up the scope), not 127 (P0-06 finding P6-3) | lead | todo | |
| Linux enforcing backend behind the same contract (PR #6, not merged; `run` refuses on Linux until it lands) | codex-linux | done | |

## Evidence

| Covers | Kind | Link | Note |
|---|---|---|---|
| scope-core.R1, scope-core.R2, scope-core.R13 | entry | [P0-01 Linux](../../evidence/P0-01-policy-before-exec-linux.md) | Debian 13, kernel 6.12.113, x86_64, launcher 020f389, helper 7c3bcff (`515ebfac…`), Zig 0.17.0, one run. An invalid policy and a hash mismatch each exited 125 with no scope directory, no receipts and no command marker; the valid command saw its policy before doing work |
| scope-core.R5 | entry | [P0-02 Linux](../../evidence/P0-02-real-deny-linux.md) | Debian 13, kernel 6.12.113, x86_64, launcher 020f389, helper 7c3bcff (`515ebfac…`), Zig 0.17.0, one run. Direct TCP and UDP over IPv4 and IPv6 refused, also from a double-forked descendant |
| scope-core.R4, scope-core.R6, scope-core.R10, scope-core.R11, scope-core.R12 | entry | [P0-03 Linux](../../evidence/P0-03-explicit-allow-linux.md) | Same launcher and helper, one run. Scope directory 700 and receipts 600; `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` set; appending to its own or another scope's receipts failed (`Read-only file system`); a synthetic secret from the caller's environment was absent; writing or renaming blackice, the policy and a `--protect` file failed, and all three were unchanged |
| scope-core.R10, scope-core.R12 | test | `zig build test` on an earlier build of PR #6, src/linux/protection_test.zig: "protected files, symlink entries and state ancestors resist mutation while neighbors remain writable", "pre-existing hard links and intermediate symlinks refuse protection before exec", "an existing alternate mount view refuses protection before exec", "stdio cannot retain protected inodes, state files or directory access through the old mount" | Linux side of protected paths and the state directory: writes, renames, hard links, other mount views and stdio refused in rootless fixtures, from a directory under `/tmp`. No installed helper and no sudo, so the privileged path is not exercised. 106/106 passed in my copy, Zig 0.17.0, Debian 13 x86_64 |
| scope-core.R11, scope-core.R12 | entry | [P0-07 macOS, scripted model](../../evidence/P0-07-fx-hook-scripted-macos.md) | macOS 27.0.1 arm64, SIP on, blackice claude/run 58e73cc, fx v0.0.16 with the hook patch at 08e34f3, scripted model, PR #11. `FAKE_SECRET` from fx's environment was absent in the scope and `AI_AGENT` passed; writes to blackice, the policy, fx and a `--protect`ed profile file, and renames of `bin/` and the policy, were all refused, with hashes unchanged |
| scope-core.R1, scope-core.R2, scope-core.R13 | entry | [P0-01 macOS](../../evidence/P0-01-policy-before-exec-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #11. A policy with the allow entry `*`, and a `--policy-sha256` that did not match, each stopped blackice before the command: exit 125, no scope, no marker file. The command's first network call was refused |
| scope-core.R5 | entry | [P0-02 macOS](../../evidence/P0-02-real-deny-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #11. Direct TCP and UDP, IPv4 and IPv6, from python3 and curl refused by the kernel; the same scope reached example.com through its proxy |
| scope-core.R4, scope-core.R6, scope-core.R7 | entry | [P0-03 macOS](../../evidence/P0-03-explicit-allow-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #10. Each scope got its own id and directory, curl used the proxy variables, and every receipt file starts with `scope_start` and ends with `scope_end` (status and `dropped`) |
| scope-core.R4 | test | `zig build test`, src/core/scope.zig: "newId", "create" | Identifier format, and a new owner-only directory per scope. 21/21 passed at 99e2f4e (PR #1), Zig 0.17.0, Linux x86_64 |
| scope-core.R5, scope-core.R10, scope-core.R11 | probe | Reported by the lead: `blackice run` (PR #7, 61ffe84) on macOS 27.0.1 (26A434), arm64, SIP on, ReleaseSafe | Through the proxy: example.com and registry.npmjs.org 200 with `allowed_by_rule` receipts; github.com 403 with `no_matching_rule`. With `--noproxy`, a name and 1.1.1.1 were refused by the sandbox. A caller variable off the pass list did not reach CMD. Writing the scope's receipts from inside: Operation not permitted, also after renaming a parent of the state root (that rename worked on the build before 61ffe84). No evidence entry yet |

## Terms

task scope, scope, policy, receipt, backend, state directory, loopback, proxy variables, Seatbelt,
sandbox-exec, cgroup v2, nftables, exit status
