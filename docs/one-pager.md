# blackice in one page

## What it is

blackice gives each app and each task on a machine its own network permissions, decided by a policy file. It
runs natively on macOS and Linux, headless, with no per-connection prompts, no account and no telemetry.

Today it works for tasks. You put it in front of a command: `blackice run --policy policy.json -- <command>`.
The command and every process it starts can then reach only the destinations the policy allows. The limit is
in place before the command runs, nothing inside can widen it, and every decision leaves a receipt. For apps,
the macOS app filter is built and waits for Developer ID signing, and the Linux app filter is in review.
blackice is at v0 and not production-ready.

## Design

- **Policy**: a small JSON file. Deny everything, allow everything public, or allow a list of names, networks
  and ports (80 and 443 by default). Any mistake in the file stops the run instead of being guessed at.
- **Scope**: the box the policy applies to. The operating system confines the command before its first
  instruction: a Seatbelt sandbox profile on macOS (experimental, because Apple has deprecated `sandbox-exec`),
  a root-owned cgroup with eBPF socket programs on Linux. Inside, the only reachable addresses are blackice's
  own proxy and relay on loopback.
- **Proxy**: checks each requested name against the policy, resolves it itself, and connects only to addresses
  that pass. A program that ignores the proxy has no network at all.
- **Receipts**: one JSON line per decision, with the scope, policy, enforcement point (proxy, kernel, relay,
  control), verdict and reason. Metadata only, no contents.
- **Grants**: the owner can add one host to a running scope for a limited time, from outside. The same command
  from inside the scope fails.
- **fx**: a small patch to fx's `PreToolUse` hook runs every command fx launches in its own scope. All of fx
  can also run in one scope, reaching its model through a relay that holds the key outside.

## What the checkpoints show

The runs were on macOS 27.0.1 on Apple silicon with SIP on, and on Debian 13 (kernel 6.12.113) on x86_64. Each
entry is one run, made by the people building blackice on their own machines; none is an independent test.

| Checkpoint | What it shows | Evidence |
|---|---|---|
| P0-01 Policy before execution | A command cannot connect before its scope is armed, even at its first instruction. | [macOS](../evidence/P0-01-policy-before-exec-macos.md), [Linux](../evidence/P0-01-policy-before-exec-linux.md) |
| P0-02 Real deny | The OS refuses direct TCP and UDP over IPv4 and IPv6, and a receiver on another machine sees nothing. macOS also refuses name lookups, listening and launchd jobs; on Linux, a descendant that double-forked was refused too. | [macOS](../evidence/P0-02-real-deny-macos.md), [Linux](../evidence/P0-02-real-deny-linux.md) |
| P0-03 Small explicit allow | Allowed names work through the proxy; other names are refused. | [macOS](../evidence/P0-03-explicit-allow-macos.md), [Linux](../evidence/P0-03-explicit-allow-linux.md) |
| P0-04 Authorized change | The owner widens a scope from outside; the same request from inside fails. | [macOS](../evidence/P0-04-owner-grant-macos.md), [Linux](../evidence/P0-04-owner-grant-linux.md) |
| P0-05 Bounded grant | The extra access ends at its expiry. | [macOS](../evidence/P0-05-grant-expiry-macos.md), [Linux](../evidence/P0-05-grant-expiry-linux.md) |
| P0-06 Faults and recovery | On Linux, with the proxy stopped, the launcher or the helper killed, a full disk, or a grant expiring during a stop, no scoped connection left the host. After a helper kill, a surviving process could reach a local program on the dead proxy's port, and recovery and the receipts did not always hold: four findings, written down as failures. An extra, not part of v0's list. | [Linux, with findings](../evidence/P0-06-faults-linux.md) |
| P0-07 fx | Every shell command fx 0.0.16 runs gets its own scope and receipts. The full run used a scripted test model; a run with a real model shows its one shell command in its own scope. | [macOS, scripted](../evidence/P0-07-fx-hook-scripted-macos.md), [macOS, real model](../evidence/P0-07-fx-real-model-macos.md) |
| P0-08 Second platform | P0-01 to P0-05 pass on both macOS and Linux, each enforced by the platform's own mechanism. fx (P0-07) was not run on Linux. | [macOS and Linux](../evidence/P0-08-second-platform.md) |
| P0-09 Forwardable proof | Evidence entries, a short recording and this page. | pending: no recording yet |
| P0-10 Release gap | The table below. | this page |

P0-06 (faults and recovery) is not part of the v0 checkpoints.

## What is not done yet

The first usable release needs all four cells. "Built" means the code compiles and its tests pass, not that it
was shown working.

| | Tasks | Apps |
|---|---|---|
| **macOS** | Shown on one Mac in the entries above. Not shown yet: launches through `open` or Apple Events refused, fx with a real model through the relay. | Built, unsigned, in #8: a Network Extension filter. It has never been activated. Needs an Apple Developer ID, a signed Network Extension, tests on a live system, and receipts written through blackice. |
| **Linux** | Shown on one Debian 13 machine in the entries above. A small helper is set up by a script run with sudo, again after each reboot (cgroups do not persist). The first two real runs on 30 Oct failed closed before the command ran, and were fixed. Not shown yet: aarch64, fx, other distributions. On Ubuntu 24.04 and later, where `kernel.apparmor_restrict_unprivileged_userns=1` is the default, scopes are expected to fail closed. | In review, not cleared: a first build and the fixes from its security review. Kernel tests in a virtual machine and a security clearance come before any install. |

Windows comes after macOS and Linux. Nothing is built for it.

Also not in v0: limits for a whole machine and nested scopes, protocols other than HTTP and HTTPS through the
proxy, observe mode, and recovery after faults.

## Limits

- Network only. Files, processes and credentials need their own controls. In the recorded macOS build (58e73cc),
  a command in a scope could read and write the clipboard; main refuses that since 727a5db.
- On Linux, ping, SCTP and raw sockets are refused when they are created, so they leave no receipt.
- On Linux, if the helper is killed while a scope runs, processes that detached from the command keep running
  with access only to the dead proxy's local port, which another local program can later listen on; removing
  them needs root, and the receipts wrongly say the command did not start.
- blackice does not detect prompt injection. It blocks connections the policy does not allow; what is sent to an
  allowed destination is up to that destination.
- With the fx hook, fx itself runs outside the scopes. Its file tools are kept inside the workspace, so install
  blackice and fx outside it (root-owned is best). What fx reads goes to the model provider.
- Any process of the same user that runs outside every scope counts as the owner.
- When a grant ends, the proxy cuts its connections within 200 ms (11 ms measured on macOS), but data that
  already reached the program stays readable.
- Work handed to a service outside the scope (launchd, `open`, `systemd-run --user`, Docker) is refused only
  where a test shows it.
- An allowed name on a shared CDN can reach other sites on that CDN through domain fronting inside TLS: the
  proxy checks the TLS server name, not the encrypted request.
- On macOS, a refusal leaves a receipt only when the refused program is signed by Apple, such as `curl` or
  `python3`. A program you built yourself is still blocked, without a receipt. Programs signed with a Developer
  ID were not tested.
- Receipts are a local record for diagnosis. Other programs of the same user, and administrators, can change
  them. The scoped command itself is designed not to write them: on macOS that held in probes, without an
  evidence entry yet; on Linux it is not tested yet.

## Build

Zig 0.17, standard library only. One binary, plus a small Linux helper with four file capabilities (`CAP_BPF`,
`CAP_NET_ADMIN`, `CAP_CHOWN`, `CAP_DAC_OVERRIDE`) that sets up each scope. Apache-2.0. Design and requirements:
[`docs/specs/`](specs/README.md).
