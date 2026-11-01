---
id: macos-task-scope
title: macOS task scope (experimental)
owner: lead
stage: v0
paths: src/macos/seatbelt.zig, src/core/backend.zig
cases: P0-01, P0-02, P0-08, P0-10
depends: policy, proxy, receipts
---

# macOS task scope (experimental)

## What and why

On macOS, `blackice run` starts the command inside the operating system's built-in sandbox. The sandbox lets the
command, and everything it starts, connect to exactly two places: blackice's own proxy and relay on this
machine. Every other connection fails inside the kernel, whether the program asks for a name, an IP address or
another local port. The proxy then decides which names are allowed, using the policy. This mode is
experimental: it uses a deprecated Apple tool, it covers commands that blackice starts, and it is not the app
control that a signed Network Extension will provide later (see [app-scopes](app-scopes.md)).

## Requirements

| ID | Requirement | Checks |
|---|---|---|
| macos-task-scope.R1 | When `blackice run` starts a command on macOS, blackice shall apply the scope's sandbox profile before the command's first instruction, so the command never runs unconfined. | P0-01 |
| macos-task-scope.R2 | While a command runs in a macOS task scope, the kernel shall let it and every process it starts open outbound connections only to the scope's proxy and relay ports on loopback. Connections to any other address, including raw IP addresses and other loopback ports, shall fail. | P0-02 |
| macos-task-scope.R3 | While a command runs in a macOS task scope, a name lookup from inside the scope shall fail unless it is made by the proxy on the command's behalf. | P0-02 |
| macos-task-scope.R4 | When a process in the scope starts a child, including a child that outlives its parent and is adopted by launchd, the child shall keep the same restrictions. | P0-01, P0-02 |
| macos-task-scope.R5 | If the sandbox cannot be applied (sandbox-exec is missing, the profile is rejected, or the spawn fails), blackice shall not run the command, shall exit non-zero, and shall write a receipt with the reason. | P0-01 |
| macos-task-scope.R6 | blackice shall refuse attempts from inside the scope to have launchd, LaunchServices (`open`) or Apple Events (`osascript`) start a process outside the sandbox. | P0-02 |
| macos-task-scope.R7 | When blackice starts a command on macOS, the command shall not inherit any network socket from blackice. | P0-02 |
| macos-task-scope.R8 | blackice shall label this backend as experimental wherever it reports the backend: CLI help, the scope start receipt and the docs. | P0-10 |
| macos-task-scope.R9 | When the same policy and the same test destinations run in a macOS and a Linux task scope, blackice shall reach the same verdict for each destination. The receipts may differ only in the enforcement point. | P0-08 |
| macos-task-scope.R10 | A process inside a macOS task scope shall not be able to write the blackice state directory: receipts, the policy copy or the control socket. | P0-04 |
| macos-task-scope.R11 | A process inside a macOS task scope shall not be able to bind a socket or accept a connection on any address, loopback included: task scopes are clients only. | P0-02 |
| macos-task-scope.R12 | When the sandbox refuses something a process in the scope tried, and macOS logs that refusal, blackice shall write a `kernel_drop` receipt with a reason (`loopback_proxy_only`, `clients_only`, `protected_path`, `launch_outside_scope`, `clipboard_outside_scope`, or `seatbelt_refused` with the raw line when it cannot be parsed). If receipts are folded, lost or cannot be read, it shall say so in a `warning` receipt (`kernel_receipts_folded`, `kernel_receipts_lost`, `kernel_receipts_off`). | P0-02 |
| macos-task-scope.R13 | A process inside a macOS task scope shall not be able to read or write the pasteboard (the clipboard and its Handoff client); a logged refusal gets a `kernel_drop` receipt with reason `clipboard_outside_scope`. | - |

## Design

blackice writes a short sandbox profile for each scope and starts the command through Apple's `sandbox-exec`
tool. The profile refuses all outbound network use and then allows the scope's two loopback ports. Because the
rule lives in the kernel and is inherited by every child, the command cannot step around it by ignoring proxy
settings: a program that does not use the proxy simply gets no network. The sandbox cannot name remote hosts
or addresses, only "any host" or "localhost", so every decision about names happens in the proxy.

**Technical.**

- Profile (`src/macos/seatbelt.zig`), for proxy port 18780 and relay port 18781:

  ```scheme
  (version 1)
  (allow default)
  (deny network-outbound)
  (allow network-outbound (remote ip "localhost:18780"))
  (allow network-outbound (remote ip "localhost:18781"))
  ```

  Then, always: `(deny network-bind)`, `(deny network-inbound)` (R11),
  `(deny file-write* (subpath (param "STATE_ROOT")))` (R10), `(deny job-creation)`, `(deny lsopen)` and
  `(deny appleevent-send)` (R6). `STATE_ROOT` is the real path of the blackice state root, passed with
  `sandbox-exec -D STATE_ROOT=<path>`.
- Why no loopback listeners: Seatbelt cannot limit a listener to loopback. An allow for `local ip
  "localhost:*"` also admitted `0.0.0.0` and connections from the local network, so the profile refuses every
  bind, as the Linux backend does.
- Launch: `/usr/bin/sandbox-exec -p <profile> <command...>` with the environment the core prepared
  (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and lowercase forms point at the proxy). The backend contract is
  `src/core/backend.zig` (`LaunchSpec`, `launch`).
- `(deny network-outbound)` also covers Unix-socket connections. That blocks the system DNS resolver socket
  (mDNSResponder) and is expected to keep the scope away from blackice's own control socket (see
  [grant](grant.md)); the second point still needs its own test.
- `(allow default)` means files, processes and other IPC are not restricted, except the state directory. This
  is a network boundary only.
- `sandbox-exec` is deprecated by Apple but still ships and still applies profiles. This backend stays
  experimental for that reason and because it covers only commands blackice starts.
- Limits until tested:
  - Mach and XPC services: a process can still ask a system service to connect on its behalf. Such
    connections run outside the scope.
  - Processes started through `open` or `osascript`: the deny rules are in the profile, but their tests open
    windows and have not run yet.
  - No command inside a scope can run a local server, even on loopback.
  - Name lookups through other system services (for example Directory Services) are untested.
  - The proxy port: what happens if the proxy restarts or another local process takes its port, and how one
    scope's proxy is kept from serving another, belong to [proxy](proxy.md) and are untested.
  - Inherited sockets (R7) are untested.
  - In the recorded build (58e73cc) the pasteboard is shared: a command in a scope read a value copied outside
    it, and a value it wrote was read outside (`pbcopy`/`pbpaste`, synthetic values, the lead's probes). The write
    side matters more: a scoped command could leave a crafted command line on the clipboard for the owner to paste
    into a terminal outside any scope. Refused since claude/run e6dcd3f (R13); as with every rule here, a refused
    program that is not Apple-signed gets no receipt.
  - Reading another process's environment from a scope was refused the two ways tried: `/bin/ps` (setuid)
    does not start inside a scope, and `sysctl` `KERN_PROCARGS2` returns the arguments without the
    environment, inside a scope and outside alike (lead's probe). Other paths, such as a debugger attach,
    are untested.
  - Sandbox refusals reach the receipts by reading the kernel log (`log stream`, filtered to the scope's tag).
    Other processes of the same user can tag their own profiles, so receipts can be added to but not removed;
    bursts lose lines in the kernel log (239 of 300 in a tight loop), and repeats of one refusal are folded
    and counted.
  - macOS logs a sandbox refusal when the refused process is an Apple-signed binary (`curl`, `nc`,
    `python3`, `git`, ...), and not when it is ad-hoc signed (blackice itself, a program built locally).
    Binaries signed with a third-party Developer ID were not tested. Refusals that are not logged are still
    enforced, but leave no log line, so no `kernel_drop` receipt, and the end-of-scope check cannot detect the
    gap. Found when blackice's own connect to the control socket in P0-04 left no receipt while the same
    connect from `python3` did; a locally built C probe behaved like blackice. `(with report)` and
    `(debug deny)` do not change it.
  - The state root's parent directories are also denied rename, hard links to files in the state root are refused,
    and the root is checked by its real path. An earlier build let a command rename a parent and then write
    its own receipts.

## Tasks

| Task | Owner | State | Blocked by |
|---|---|---|---|
| Profile generator and launch through sandbox-exec | lead | done | |
| Wire `blackice run` on macOS: scope, proxy, receipts, launch (PR #7) | lead | done | |
| Receipts for refusals made by the sandbox, read from the kernel log (818a3ae, ca62d58) | lead | done | |
| Protect the state root's parent directories against rename | lead | done | |
| Cross-build for aarch64-macos | lead | done | |
| End-to-end run on the Mac with SIP on, with receipts, an off-host receiver that sees nothing, and an evidence entry | lead | todo | |
| Test hardening against launchd job creation (no window opens) | lead | done | |
| State-directory write deny and bind/inbound deny in the profile | lead | done | |
| Test hardening against `open` and `osascript` | lead | blocked | Valen's OK: these tests open windows, so not while recording |
| Test inherited sockets, proxy restart and port takeover | lead | todo | |
| Test name lookups through other system services, with fresh random names | lead | todo | |
| docs/macos.md | lead | todo | |
| Receipt reason `protected_path` for a refused hard link to a protected file (Seatbelt logs it as `forbidden-link-priv`), cffa0cd | lead | done | |
| Deny the pasteboard's service lookup in task scopes, with a receipt (security Low on PR #7): ae59ed5, e6dcd3f | lead | done | |
| Label the backend experimental in `blackice run --help`, the scope line and the `scope_start` receipt (R8): at 58b9491 they say `macos-seatbelt` only | lead | todo | |

## Evidence

| Covers | Kind | Link | Note |
|---|---|---|---|
| macos-task-scope.R13 | probe | Reported by the lead: claude/run e6dcd3f release (aarch64-macos `f3c8aead…`), macOS 27.0.1, SIP on, scope s-97b9df22, synthetic values | `pbpaste` and `pbcopy` inside a scope exited 1, the owner's pasteboard was unchanged, each refusal left a `clipboard_outside_scope` receipt; git, python3, swift and fx still ran. No evidence entry |
| macos-task-scope.R3, macos-task-scope.R12 | entry | [P0-07 macOS, scripted model](../../evidence/P0-07-fx-hook-scripted-macos.md) | macOS 27.0.1 arm64, SIP on, blackice claude/run 58e73cc, fx v0.0.16 with the hook patch at 08e34f3, scripted model, PR #11. `curl --noproxy '*' https://example.com` could not resolve the name: Seatbelt refused the resolver socket (`/private/var/run/mDNSResponder`) with a `kernel_drop`; writes and renames of protected files left `protected_path` receipts |
| macos-task-scope.R1, macos-task-scope.R12 | entry | [P0-01 macOS](../../evidence/P0-01-policy-before-exec-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #11. curl's first and only network call was refused at once (exit 7), with `backend_armed` before the `kernel_drop`; a grandchild started a second later was refused the same way; a child that outlived the command was refused too (exit 7), with no receipt because receipts stop at the scope's end. That the orphan was adopted by launchd is not shown, so R4 stays open |
| macos-task-scope.R2, macos-task-scope.R3, macos-task-scope.R11, macos-task-scope.R12 | entry | [P0-02 macOS](../../evidence/P0-02-real-deny-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #11. A scoped python3 got `Operation not permitted` for TCP and UDP over IPv4 and IPv6; curl direct was refused (exit 7); `getaddrinfo` failed (resolver socket refused); `bind` + `listen` on 127.0.0.1 refused (`clients_only`); `launchctl submit` refused (`launch_outside_scope`) and the job never ran. A receiver on another machine logged controls before and after and nothing from any scope; the IPv6 path was Tailscale. `open`, Apple Events (the rest of R6) and R7 are not tested |
| macos-task-scope.R2, macos-task-scope.R6, macos-task-scope.R10, macos-task-scope.R11 | test | `zig build test`, src/macos/seatbelt.zig: "profile" | 21/21 passed at 99e2f4e (PR #1), Zig 0.17.0, Linux x86_64. Checks the profile text only, not enforcement |
| macos-task-scope.R6, macos-task-scope.R10, macos-task-scope.R11 | probe | Reported by the lead: the exact profile on macOS 27.0.1, SIP on | Binds and listeners refused (8 address variants), writes under `STATE_ROOT` refused, launchd job creation refused; `git`, `swift` and fx still ran. `open` and `osascript` not exercised. No evidence entry yet |
| macos-task-scope.R2 | probe | Sandbox probe on macOS 27.0.1 (26A434), Apple M4, SIP on, without blackice code | With only localhost allowed, a connection to a raw IP failed at once; with one loopback port allowed, another loopback port was blocked; a stand-in proxy on the allowed port received `CONNECT example.com:443` |
| macos-task-scope.R3 | probe | Same probe | With all outbound network denied, `curl https://example.com` failed with "Could not resolve host" |
| macos-task-scope.R4 | probe | Same probe | A background child, orphaned and adopted by launchd (parent PID 1), was still blocked |
| macos-task-scope.R2 | probe | fx 0.0.16 inside the same kind of profile, scripted local model, stand-in proxy, SIP on | fx reached its model only on the allowed port; a direct `curl` from a tool could not resolve the host; through the stand-in proxy the request arrived as `CONNECT example.com:443` |
| macos-task-scope.R1, macos-task-scope.R2, macos-task-scope.R10 | probe | Reported by the lead: `blackice run` (PR #7, 61ffe84) on macOS 27.0.1 (26A434), arm64, SIP on, ReleaseSafe | `curl --noproxy '*'` to a name failed (exit 6) and to 1.1.1.1 failed (exit 7); 169.254.169.254 through the proxy got `local_or_private_address`; writing the receipts from inside was refused, and so were a parent rename and a hard link to the home directory, /private/tmp or an ancestor (security re-check of 7e26dfd: no open findings). No evidence entry yet |

## Terms

task scope, Seatbelt, sandbox-exec, SIP, policy, CONNECT proxy, relay, receipt, DNS, Network Extension, app scope
