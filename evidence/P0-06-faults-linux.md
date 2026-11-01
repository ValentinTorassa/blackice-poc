# P0-06: faults and recovery for task scopes (Linux: Debian 13, kernel 6.12), with four findings

**Claim.** On the Linux host below, and in a disposable virtual machine with the same kernel and the same helper
binary, this run stopped, killed or starved the parts of a task scope one at a time and recorded what each fault
did. No scoped connection left the host in any case. After a helper kill (F3b, VM), a surviving process reached a
local program that took the dead proxy's port (P6-1): a refused destination reached on the same machine, which
would have let the traffic out if that program had been a relay. Recovery and the receipts did not always hold
either. Those cases are written down as failures: four findings, P6-1 to P6-4.
Checkpoint P0-06. **This is a run, not a pass.** P0-06 is not in v0's acceptance list; it is recorded as an extra.

**Platform.**
- Host: Debian GNU/Linux 13.7 (trixie), Linux 6.12.113+deb13-amd64, x86_64, unified cgroup v2, Landlock ABI 6.
- Virtual machine (labeled **VM** below): a disposable Debian 13.7 guest, Linux 6.12.113+deb13-amd64, BTF sha256
  `5727b13fd2212290ae031719c9367251c0c8eda0a3f48181af71452ccf5f8943`. Root inside the VM only. Torn down afterwards
  with `scripts/linux-teardown.sh` (exit 0).

**Build.**
- Launcher: a `git archive` of main `5f84f67`, `zig build release` with Zig 0.17.0. `blackice-x86_64-linux`
  sha256 `b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762`, the same on the host and in the VM.
- Helper: `/usr/local/libexec/blackice-linux-helper` sha256
  `515ebfacc545e1a2ca4f66190630aae2f8ff09b68f2575a2bcf11ea7698aadbd`, `cap_chown,cap_dac_override,cap_net_admin,cap_bpf=ep`,
  root:valen 0750, as installed on the host before this run; checked before the first fault and after the last.
  The VM built the same bytes from the same archive and installed them with main's `scripts/linux-setup.sh`, so the
  VM results cover the host's helper byte for byte. The helper's source has not changed since `7c3bcff`.

**Policy.** `agent.json`, sha256 `b28c9f29dbeafbf9ae0fa9163a3affaefbc997aaedc19c23b3d20bf1dc662760` (policy id
`b28c9f29dbea`), the same file as P0-03 to P0-05: `example.com` and `registry.npmjs.org`.

**Run.** A driver script, run as the user, started each scope with
`blackice run --policy agent.json -- bash -c '…'` in a fresh 0700 state directory, applied the fault from outside,
and recorded before and after: processes in `/blackice/` cgroups (from `/proc/<pid>/cgroup`), processes carrying a
marker word, blackice listeners, and `/sys/fs/cgroup/cgroup.stat`. Nothing on the host ran as root.
`/sys/fs/cgroup/blackice` is 0700 root, so the user cannot list it: the evidence that a scope's cgroup is gone is
the helper's `backend_cleanup` / `cgroup_empty_and_removed` receipt, which the helper writes only after its
rmdir succeeded. An empty leftover cgroup directory cannot be seen without root.

Direct connections from inside a scope went to a LAN address where nothing listened (`TARGET_V4:47121`). A control
from outside every scope, before and after each fault, got ECONNREFUSED from that machine, so the path off the host
worked; every scoped attempt got EPERM at `connect()`, before any packet was sent. **There was no receiver log**:
the P0-02 receiver was unreachable that afternoon. That is weaker than P0-02's evidence, and it is the method here.

**Result.**

| Fault | What happened | Verdict |
| --- | --- | --- |
| F1. `blackice run` (and so its proxy) stopped with SIGSTOP for 20 s during a rate-limited download, with direct connections every 2 s | 12 of 12 direct attempts got EPERM, 10 of them while stopped. 12 `kernel_drop` receipts, no loss warning. The 10 refused while stopped carry the CONT time (17:24:00.856Z): a receipt's `ts` is when it was written. The download stalled and resumed until curl's own 45 s limit. `scope_end` status 0, cgroup removed | Held |
| F2. `blackice run` killed with SIGKILL during the download, with a `setsid` descendant started first | The download broke. The helper was gone within 5 s. No process was left in a `/blackice/` cgroup or with the marker, and `nr_descendants` returned to its value before the scope. No `scope_end` and no cgroup receipt: the process that writes them was killed | Held; cleanup inferred, not receipted |
| F2. The same with SIGTERM | The same, and `blackice run` died of the signal. No `scope_end` | **P6-2** |
| F2. The same with Ctrl-C in a terminal | The same; no `scope_end`. The helper printed `scope_cleanup: ReceiptPipeClosed`: it could not report its cleanup, while the checks above show the cleanup happened | **P6-2** |
| F3a. Helper setup fails (run inside `unshare --user --map-current-user`) | The command did not run. Receipts: `linux_launch_refused` / `InvalidState`, `command_not_started` / `SpawnFailed`, `scope_end` 127. Exit **127**, which reads as "command not found" | Fails closed; **P6-3** |
| F3b (**VM**). The helper killed with SIGKILL 5 s into a scope | The command's first process died (its parent-death signal). `blackice run` exited 127, and its receipts say `command_not_started` for a command that had run for 5 s. The `setsid` descendant survived in its scope cgroup, with only the dead proxy's port (`127.0.0.1:60313`) allowed | **P6-1, P6-3, P6-4** |
| F3b (**VM**). The dead port | A listener outside any scope, as the same user, bound `127.0.0.1:60313` 0.07 s after `blackice run` exited. It received both of the survivor's requests (`CONNECT example.com:443`, at 17:30:19 and 17:30:34). A second scope got another port (51065), and the survivor could not reach it (refused at once) | **P6-1** |
| F3b (**VM**). Cleanup | Killing the survivor left its child (`sleep 300`, re-parented to init) in the cgroup, so `rmdir` failed with EBUSY. Only killing the pid listed in the cgroup's `cgroup.procs`, as root, let `rmdir` succeed | **P6-1** |
| F4a. The state directory cannot be created (0500 parent) | Exit 125, "cannot create the scope directory: AccessDenied"; the command did not run | Held |
| F4b (**VM**). A 256 KiB tmpfs filled to 8 KiB free during a scope of 600 direct attempts | All 600 got EPERM. 44 `kernel_drop` lines were written and `scope_end` reports `dropped: 556`: 44 + 556 = 600. `scope_end` was written after the filler file was removed; cgroup removed | Held; the gap is counted |
| F5. A grant ends while `blackice run` is stopped (grant 30 s, STOP at +20 s, CONT at +45 s) | `grant_expired` / `connection_reset` in the same millisecond as the CONT (17:22:38.510Z). The next request got 403 (`no_matching_rule`). The last 100 bytes of the stream, sent by the server at about +20.0 to +20.4 s while the grant was valid, were in the proxy's buffer during the STOP and reached curl after the CONT. `scope_end` 0 | Held |
| F6. Start again after F2's SIGKILL | A new scope worked (200, normal receipts, `scope_end`). A grant to F2's dead scope failed: "cannot reach the control socket … (ConnectionRefused)". Each killed scope leaves a stale `control.sock` file | Held |
| The workload kills itself (`kill -KILL $$`) | Exit 137, `scope_end` 137, cgroup removed | Held |

After the last fault the host was clean: no process in a `/blackice/` cgroup, no marker process, no blackice
listener, `cgroup.stat` equal to the baseline, the state directories removed, and the helper's hash and
capabilities unchanged. That check cannot see an empty leftover cgroup directory (root only).

**Findings.**
- **P6-1 (low).** If the helper is killed while a scope runs, processes that detached from the command keep
  running, confined to the dead proxy's local port. Another local program can later listen on that port and
  receive their connections, as F3b showed. Removing them needs root, through the cgroup's `cgroup.procs`; killing
  by name or marker misses re-parented children. Fix (helper): an orphan sweep for the user's scopes when the helper
  starts, and the same sweep as a user command.
- **P6-2 (low).** SIGTERM and Ctrl-C on `blackice run` leave no `scope_end`, and Ctrl-C is the usual way to stop a
  run. Fix: `run` handles INT, TERM and HUP, cancels through the helper, waits for its cleanup report, and writes
  `scope_end` as cancelled.
- **P6-3 (low).** A helper or launch failure exits 127 (`SpawnFailed`), which reads as "command not found"; setup
  failures are documented as 125.
- **P6-4 (medium, receipts).** After a helper kill, the receipts say `command_not_started` / `SpawnFailed` and
  `scope_end` 127 for a command that had been running for 5 s, while a descendant was still running. The receipts
  are wrong in that case.

**Receipts.** Complete logs, with private addresses replaced, in
[`data/linux-p0-06-20261030T1717Z/`](data/linux-p0-06-20261030T1717Z/README.md). The F3b receipts, verbatim:

```
{"ts":"2026-10-30T17:29:59.901Z","scope":"s-54ebb173","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command bash; proxy port 60313; 2 protected files"}
{"ts":"2026-10-30T17:29:59.924Z","scope":"s-54ebb173","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T17:30:04.968Z","scope":"s-54ebb173","policy":"b28c9f29dbea","gen":1,"point":"control","event":"warning","verdict":"deny","reason":"linux_launch_refused","detail":"HelperFailed"}
{"ts":"2026-10-30T17:30:04.968Z","scope":"s-54ebb173","policy":"b28c9f29dbea","gen":1,"point":"control","event":"warning","reason":"command_not_started","detail":"SpawnFailed"}
{"ts":"2026-10-30T17:30:04.968Z","scope":"s-54ebb173","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":127,"detail":"command_not_started","dropped":0}
```

The survivor's own log (`vm-f3b-survivor.log`) shows it started at 17:29:59.929 in `0::/blackice/s-54ebb173` with
`HTTPS_PROXY=http://127.0.0.1:60313`, five seconds before these receipts say the command did not start.

The F4b scope end, verbatim:

```
{"ts":"2026-10-30T17:32:16.456Z","scope":"s-e286ed1c","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":556}
```

**Recording.** None for this run.

**Limits.**
- **No receiver log.** The off-host evidence is ECONNREFUSED for the controls and EPERM for the scoped attempts,
  not a receiver that saw nothing.
- **F2's descendant.** The run checked for leftovers after the kill and found none. It did not record the
  descendant while it ran, before the kill.
- **F2's cleanup** is inferred from three checks (no process in a `/blackice/` cgroup, the helper gone,
  `nr_descendants` back to its baseline). There is no receipt on that path, and an empty leftover cgroup directory
  cannot be seen without root.
- **F1's timing.** The direct attempts ran alongside the download, so most fell inside the STOP.
- **F5.** The first attempt was a harness error: the stream's files were under `/tmp`, which is private inside a
  scope, so the stream ended before the STOP and the fault was not exercised. It was re-run once (f5b), with the
  working directory as the stream's location, as `scripts/e2e/grant-expiry.sh` does. Both are in the data.
- **Not run:** a missing helper (it would mean removing the installed one), a reboot or an out-of-memory kill during
  a scope, the relay, fx, macOS and the app filters.
- **Two machines, one each.** The host faults ran on this host; F3b and F4b ran in the VM only. Ubuntu 24.04 and
  later are expected to fail closed before the command starts (not tested).
- **The run.** One run of each fault, by the people building blackice, on the owner's machine and a VM. Not a
  recording, and not an independent test.

**Date.** 2026-10-30, 17:17 to 17:33 UTC.
