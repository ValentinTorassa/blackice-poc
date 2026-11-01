# P0-08: the task-scope checks on the second platform (P0-01 to P0-05, macOS and Linux)

**Claim.** Checkpoints P0-01 to P0-05 each have a passing run on macOS and a passing run on Linux, and the two
runs of each checkpoint make the same claim, enforced by each platform's own mechanism. fx (P0-07) has a run on
macOS only. This covers checkpoint P0-08 (second platform) for P0-01 to P0-05.

**Scope.** This entry adds no run. It compares the ten entries listed below, as they are on main. Its scope is
P0-01 to P0-05 by decision of the project lead on 30 Oct 2026. P0-06 (faults and recovery) is not part of the v0
checkpoints. P0-07 is named under Limits.

**Platform.**
- macOS 27.0.1 (26A434), arm64 (Apple silicon MacBook Air), System Integrity Protection enabled.
- Debian GNU/Linux 13 (trixie), kernel `6.12.113+deb13-amd64`, x86_64.

**Build.**
- macOS: `claude/run` at 58e73cc for P0-01 to P0-04 and at 58b9491 for P0-05, Zig 0.17.0, ReleaseSafe. Those
  commits can be fetched with `git fetch origin pull/7/head` (see [README](README.md), "Older builds").
- Linux: the same launcher for all five, `020f389` (`blackice-x86_64-linux`, sha256
  `b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762`), with the helper built from `7c3bcff`
  (sha256 `515ebfacc545e1a2ca4f66190630aae2f8ff09b68f2575a2bcf11ea7698aadbd`), Zig 0.17.0.

Each entry names its own build in full.

**Policy.** Each entry names its policy file and hash:

| Checkpoint | macOS | Linux |
|---|---|---|
| P0-01, P0-02 | `agent.json` (`b28c9f29…2760`), which allows `example.com` and `registry.npmjs.org` | `deny.json` (`0190ed20…7438`), `deny-all` |
| P0-03, P0-04, P0-05 | `policy.json` (`b0aa1758…76ff2`), which allows only `example.com` | `agent.json` (`b28c9f29…2760`) |

**Run.** The commands are in each entry. They differ by platform:
- macOS P0-01 and P0-02 used `scripts/evidence/p0-01-02-macos.sh`; P0-03 to P0-05 were run by hand, with the
  commands written in each entry.
- Linux P0-01 and P0-02 used the frozen launcher and harness from `020f389`; P0-03 to P0-05 used
  `scripts/e2e/linux-run.sh`, `linux-grant.sh` and `grant-expiry.sh`, as on main.

**Result.**

| Checkpoint | Same claim on both | macOS: where it is enforced | Linux: where it is enforced | Shown on one platform only |
|---|---|---|---|---|
| P0-01 Policy before execution | A policy that does not load, or does not match its pinned hash, starts nothing. | blackice before launch; Seatbelt from the first instruction | the launcher before it creates a scope | macOS: the first network call and a grandchild that outlives the command are refused. Linux: the command saw its policy copy and its first receipt before doing any work. |
| P0-02 Real deny | Direct TCP and UDP over IPv4 and IPv6 are refused, and a receiver on another machine got nothing from inside the scope, while the same sender reached it from outside. | Seatbelt, in the kernel | cgroup BPF `connect` and `sendmsg` hooks, in the kernel | macOS: name lookups, listening and launchd jobs are refused. Linux: a descendant that double-forked is refused, and each refusal has a kernel receipt. |
| P0-03 Small explicit allow | An allowed name works through the scope's proxy, github.com is refused, and each decision leaves a receipt. | the proxy | the proxy; the same destinations reached directly are refused by the kernel | macOS: plain HTTP as well as HTTPS. Linux: two allowed names, and the cloud metadata address refused. |
| P0-04 Authorized change | A command inside the scope cannot grant itself more access. The owner's grant from outside lets exactly one more name through, with an end time. The control socket is gone once the scope ends. | the Seatbelt profile keeps the control socket out of reach; the proxy applies the grant | the scope cannot reach the control socket; the proxy applies the grant | Linux: the owner's `revoke` takes the grant back at once. |
| P0-05 Bounded grant | At the grant's end the proxy resets the connection opened under it, and a new connection to the same name is refused again. | the proxy | the proxy | |

**Receipts.** In the compared entries:

- P0-01: [macOS](P0-01-policy-before-exec-macos.md), [Linux](P0-01-policy-before-exec-linux.md)
- P0-02: [macOS](P0-02-real-deny-macos.md), [Linux](P0-02-real-deny-linux.md)
- P0-03: [macOS](P0-03-explicit-allow-macos.md), [Linux](P0-03-explicit-allow-linux.md)
- P0-04: [macOS](P0-04-owner-grant-macos.md), [Linux](P0-04-owner-grant-linux.md)
- P0-05: [macOS](P0-05-grant-expiry-macos.md), [Linux](P0-05-grant-expiry-linux.md)

**Recording.** None.

**Limits.**
- **fx on Linux was not run.** P0-07 has a macOS entry only. The fx track was parked on 30 Oct 2026, when the
  project's priority moved to app scopes, so no Linux fx run was made. Dual-platform completion is claimed here
  for P0-01 to P0-05 only.
- The two runs of each checkpoint used different scripts and different policy files (the tables above). That
  changes the test details, not the claim.
- One machine per platform: Apple silicon only on macOS, x86_64 only on Linux, one Debian 13 kernel. Not run:
  Intel Macs, aarch64 Linux, other distributions. On Ubuntu 24.04 and later, where
  `kernel.apparmor_restrict_unprivileged_userns=1` is the default, Linux scopes are expected to fail closed.
- Each entry is one run, made by the people building blackice on their own machines; none is an independent
  test. Each entry's own limits apply.
- App scopes are not covered by any P0 checkpoint.

**Date.** 2026-10-30. The compared runs are dated in their entries (06:39 to 07:23 UTC on macOS, 13:27 to 13:31
UTC on Linux).
