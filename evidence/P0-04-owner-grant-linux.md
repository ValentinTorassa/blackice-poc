# P0-04: the owner grants from outside; the scope cannot grant itself (Linux: Debian 13, kernel 6.12)

**Claim.** On the Linux host below, a command inside a task scope cannot widen its own policy: its
`blackice grant` cannot reach the scope's control socket. The owner's `blackice grant` from outside the scope
lets exactly one more name through the proxy, with an end time. The owner's `blackice revoke` takes it back
at once. The control socket is gone once the scope ends. Checkpoint P0-04.

**Platform.** Debian GNU/Linux 13 (trixie), Linux 6.12.113+deb13-amd64, x86_64.
- Unified cgroup v2 and Landlock ABI 6.
- AppArmor is enabled, but this kernel has no unprivileged user-namespace restriction:
  `kernel.apparmor_restrict_unprivileged_userns` does not exist, and `kernel.unprivileged_userns_clone` is 1.

**Build.** The same launcher, helper and scripts as the P0-03 Linux entry.
- Launcher: `020f389`, `zig build release` with Zig 0.17.0. Binary `blackice-x86_64-linux`, sha256
  `b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762`.
- Helper: built from `7c3bcff`, sha256 `515ebfacc545e1a2ca4f66190630aae2f8ff09b68f2575a2bcf11ea7698aadbd`,
  installed by the owner.
- Scripts: `scripts/e2e/` as on main, byte-identical to `7cc5697`.

Both hashes were checked before the run.

**Policy.** `agent.json`, sha256 `b28c9f29dbeafbf9ae0fa9163a3affaefbc997aaedc19c23b3d20bf1dc662760` (policy
id `b28c9f29dbea`): allow list with `example.com` and `registry.npmjs.org`, the same file as P0-03. github.com
is not on it.

**Run.**

```sh
BLACKICE=/path/to/blackice-x86_64-linux bash scripts/e2e/linux-grant.sh
```

One scope runs the bash script `INNER` from `scripts/e2e/linux-grant.sh`. It reads its standard input, a FIFO
the script holds, to wait for each of the owner's steps, so the order is fixed:
1. check github.com;
2. try `blackice grant` from inside;
3. wait for the owner's grant, then check github.com and www.github.com;
4. wait for the owner's revoke, then check github.com.

The owner's commands run outside the scope, as the same user:

```sh
blackice grant s-e643c173 github.com --for 2m
blackice revoke s-e643c173 github.com
blackice grant s-e643c173 github.com --for 1m    # after the scope ended
```

**Result.** 17 checks passed, 0 failed. Enforcement point: the scope's proxy, which reads the grant table that
only the control socket changes.

Inside the scope, verbatim (`CONNECT code/HTTP code`):

```
inside: github.com before the grant -> 403/000
blackice: cannot reach the control socket of scope s-e643c173 (Unexpected). Commands inside a scope cannot reach it; from outside, check that the scope is still running.
inside: self-grant exit 1
inside: waiting for the owner grant
inside: github.com after the owner grant -> 200/200
inside: www.github.com (not granted) -> 403/000
inside: waiting for the owner revoke
inside: github.com after the revoke -> 403/000
blackice: scope s-e643c173 ended with status 0; 10 receipts
```

Outside, verbatim:

```
outside: blackice grant s-e643c173 github.com --for 2m
granted github.com to scope s-e643c173 until 2026-10-30T13:33:37.939Z
outside: blackice revoke s-e643c173 github.com
revoked github.com in scope s-e643c173
outside: blackice grant s-e643c173 github.com --for 1m   (after the scope ended)
blackice: cannot reach the control socket of scope s-e643c173 (FileNotFound). Commands inside a scope cannot reach it; from outside, check that the scope is still running.
```

**Receipts.** Verbatim. The first scope is the script's `/bin/true` probe:

```
{"ts":"2026-10-30T13:31:37.622Z","scope":"s-ae99d180","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command true; proxy port 55931; 2 protected files"}
{"ts":"2026-10-30T13:31:37.666Z","scope":"s-ae99d180","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:37.667Z","scope":"s-ae99d180","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:37.667Z","scope":"s-ae99d180","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:37.680Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command bash; proxy port 53803; 2 protected files"}
{"ts":"2026-10-30T13:31:37.683Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:37.689Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"no_matching_rule","host":"github.com","port":443}
{"ts":"2026-10-30T13:31:37.939Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"control","event":"grant","verdict":"allow","reason":"owner_grant","rule":"github.com","host":"github.com","detail":"pid=722697 for 120s until 2026-10-30T13:33:37.939Z"}
{"ts":"2026-10-30T13:31:37.991Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"allow","reason":"granted","rule":"grant:github.com","host":"github.com","ip":"4.228.31.150","port":443,"detail":"sni_match grant_until=2026-10-30T13:33:37.939Z"}
{"ts":"2026-10-30T13:31:38.382Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"no_matching_rule","host":"www.github.com","port":443}
{"ts":"2026-10-30T13:31:38.448Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"control","event":"revoke","verdict":"allow","reason":"owner_revoke","rule":"github.com","host":"github.com","detail":"pid=722713 removed"}
{"ts":"2026-10-30T13:31:38.455Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"no_matching_rule","host":"github.com","port":443}
{"ts":"2026-10-30T13:31:38.456Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:38.456Z","scope":"s-e643c173","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

There is exactly one `grant` receipt, and it is the owner's (`owner_grant`, from pid 722697 outside the
scope).

**Recording.** None for this run.

**Limits.**
- **Who the owner is.** In v0, any process of the same user outside every scope counts as the owner. The
  grant and the revoke came from such processes (pids 722697 and 722713). There is no separate owner
  credential.
- **How the self-grant fails.** The run shows the refusal by its error and its effects: no grant receipt, and
  github.com still refused. It does not show the mechanism. On Linux the scope's seccomp filter refuses
  Unix-domain sockets with EPERM; the helper's unit test checks that. That refusal writes no receipt.
- **Expiry.** A grant's expiry and the closing of live connections are P0-05, not shown here. The revoke came
  before the 2-minute grant ended.
- **The host.** This entry covers only this host. On Ubuntu 24.04 and later, where
  `kernel.apparmor_restrict_unprivileged_userns=1` is the default, a scope is expected to fail closed before
  the command starts (not tested on Ubuntu).
- **The run.** One run, by the people building blackice, on the owner's machine. Not a recording.

**Date.** 2026-10-30, 13:31 UTC.
